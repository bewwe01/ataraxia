//! Milestone 4.5, Profile (ADR-0020): name, status and picture, sent end-to-end encrypted to
//! contacts; who sees the picture; nicknames and pictures only the user sees.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use base64::Engine as _;
use common::*;
use veil_client::ClientError;
use veil_client::service::{ContactView, PictureVisibility};
use veil_core::content::{Body, Profile};
use zeroize::Zeroizing;

const JPEG: &[u8] = &[
    0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0, 1, 1, 0, 0, 1,
];
const PICTURE_MARK: &[u8] = b"profile-picture-at-rest-probe";

fn picture(mark: &[u8]) -> String {
    let mut b = JPEG.to_vec();
    b.extend_from_slice(mark);
    base64::engine::general_purpose::STANDARD.encode(b)
}

async fn view(c: &veil_client::service::Client, id: i64) -> ContactView {
    c.contacts()
        .await
        .unwrap()
        .into_iter()
        .find(|x| x.id == id)
        .unwrap()
}

/// Waits until `f` holds for the contact's view.
async fn until(c: &veil_client::service::Client, id: i64, f: impl Fn(&ContactView) -> bool) -> ContactView {
    eventually(|| async {
        let v = view(c, id).await;
        f(&v).then_some(v)
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn profiles_reach_contacts_as_the_user_chose() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    let (a, b) = (&alice.client, &bob.client);
    // Bob only knows Alice by a made-up name until her profile comes.
    assert!(b_alice.name.starts_with("Contact "));

    // Name and status arrive; the picture does not (it is shown to nobody until chosen).
    a.set_profile("Alice A".into(), "On holiday 🌴".into())
        .await
        .unwrap();
    a.set_my_picture(Some(picture(PICTURE_MARK))).await.unwrap();
    let v = until(b, b_alice.id, |v| v.name == "Alice A").await;
    assert_eq!(v.status.as_deref(), Some("On holiday 🌴"));
    assert!(v.picture.is_none() && !v.nickname);
    let me = a.profile().await.unwrap();
    assert_eq!(
        (me.name.as_str(), me.visibility),
        ("Alice A", PictureVisibility::Nobody)
    );
    assert!(me.picture.is_some());

    // Verified contacts only: Bob gets it once Alice verifies him.
    a.set_picture_visibility(PictureVisibility::Verified)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(view(b, b_alice.id).await.picture.is_none(), "not verified yet");
    a.set_verified(a_bob.id, true).await.unwrap();
    until(b, b_alice.id, |v| v.picture.is_some()).await;
    let url = b.picture(Some(b_alice.id)).await.unwrap().unwrap();
    assert!(url.starts_with("data:image/jpeg;base64,"));

    // Hidden from Bob alone: it is taken back; shown again: it returns.
    a.set_picture_hidden(a_bob.id, true).await.unwrap();
    until(b, b_alice.id, |v| v.picture.is_none()).await;
    assert!(b.picture(Some(b_alice.id)).await.unwrap().is_none());
    a.set_picture_hidden(a_bob.id, false).await.unwrap();
    until(b, b_alice.id, |v| v.picture.is_some()).await;
    a.set_picture_visibility(PictureVisibility::Nobody).await.unwrap();
    until(b, b_alice.id, |v| v.picture.is_none()).await;

    // A nickname wins over their name, and the profile still says what they call themselves.
    b.set_nickname(b_alice.id, Some("Mum".into())).await.unwrap();
    a.set_profile("Alice B".into(), String::new()).await.unwrap();
    let v = until(b, b_alice.id, |v| v.their_name.as_deref() == Some("Alice B")).await;
    assert!(v.name == "Mum" && v.nickname && v.status.is_none());
    b.set_nickname(b_alice.id, None).await.unwrap();
    assert_eq!(view(b, b_alice.id).await.name, "Alice B");

    // A picture only Bob sees replaces hers on his side, and is never sent.
    let png = base64::engine::general_purpose::STANDARD.encode(b"\x89PNG\r\n\x1a\nlocal");
    b.set_contact_picture(b_alice.id, Some(png)).await.unwrap();
    assert!(
        b.picture(Some(b_alice.id))
            .await
            .unwrap()
            .unwrap()
            .starts_with("data:image/png;")
    );
    assert!(view(b, b_alice.id).await.picture.unwrap().starts_with('l'));
    b.set_contact_picture(b_alice.id, None).await.unwrap();
    assert!(view(b, b_alice.id).await.picture.is_none());

    // Refused: not an image, too big, unknown contacts, an empty nickname.
    let svg = base64::engine::general_purpose::STANDARD.encode(b"<svg onload=alert(1)>");
    assert_eq!(
        a.set_my_picture(Some(svg)).await.unwrap_err(),
        ClientError::BadInput
    );
    let mut big = JPEG.to_vec();
    big.resize(veil_core::content::MAX_PICTURE_LEN + 1, 0);
    let big = base64::engine::general_purpose::STANDARD.encode(big);
    assert_eq!(
        a.set_my_picture(Some(big)).await.unwrap_err(),
        ClientError::TooLarge
    );
    assert_eq!(
        a.set_picture_hidden(9999, true).await.unwrap_err(),
        ClientError::UnknownContact
    );
    assert_eq!(
        b.set_nickname(b_alice.id, Some("  ".into())).await.unwrap_err(),
        ClientError::BadInput
    );

    // Encrypted at rest on both sides.
    a.set_picture_visibility(PictureVisibility::All).await.unwrap();
    until(b, b_alice.id, |v| v.picture.is_some()).await;
    for u in [&alice, &bob] {
        u.client.lock().await.unwrap();
        assert!(
            !tree_contains(u.dir(), PICTURE_MARK),
            "profile picture found in the clear"
        );
        u.client
            .unlock(Zeroizing::new("correct horse battery".into()))
            .await
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_contact_cannot_take_another_contacts_name() {
    let r = relay().await;
    let (alice, bob, mallory) = (
        user(&r, "Alice").await,
        user(&r, "Bob").await,
        user(&r, "Mallory").await,
    );
    let (a_bob, _) = pair(&alice.client, &bob.client).await;
    let (a_mal, m_alice) = pair(&alice.client, &mallory.client).await;
    assert_eq!(a_bob.name, "Bob");

    // Mallory renames herself "bob": Alice keeps calling her Mallory, and says so.
    mallory
        .client
        .set_profile(" bob ".into(), String::new())
        .await
        .unwrap();
    let v = until(&alice.client, a_mal.id, |v| v.their_name.is_some()).await;
    assert_eq!(
        (v.name.as_str(), v.their_name.as_deref()),
        ("Mallory", Some("bob"))
    );

    // An older profile (a replay, or one overtaken in transit) changes nothing.
    mallory
        .client
        .raw_send(
            m_alice.id,
            vec![9; 16],
            Body::Profile(Profile {
                rev: 1,
                name: "Old".into(),
                status: "old".into(),
                picture: None,
            }),
        )
        .await
        .unwrap();
    mallory.client.send(m_alice.id, "after".into()).await.unwrap();
    arrives(&alice.client, a_mal.id, "after").await;
    let v = view(&alice.client, a_mal.id).await;
    assert_eq!(v.their_name.as_deref(), Some("bob"));
    assert!(v.status.is_none());
}
