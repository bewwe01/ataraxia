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
use veil_client::service::{Client, ContactView, PictureVisibility};
use veil_core::content::{Body, Profile};
use zeroize::Zeroizing;

const PICTURE_MARK: &[u8] = b"profile-picture-at-rest-probe";

/// The start of a `w` × `h` JPEG (SOI, APP0, start of frame), then `mark`.
fn jpeg(w: u16, h: u16, mark: &[u8]) -> Vec<u8> {
    let mut b = vec![
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x04, 0, 0, 0xFF, 0xC0, 0x00, 0x11, 8,
    ];
    b.extend_from_slice(&h.to_be_bytes());
    b.extend_from_slice(&w.to_be_bytes());
    b.extend_from_slice(&[3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]);
    b.extend_from_slice(mark);
    b
}

fn b64(bytes: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(bytes))
}

fn picture(mark: &[u8]) -> Zeroizing<String> {
    b64(&jpeg(512, 512, mark))
}

fn profile(rev: u64, name: &str, picture: Option<Vec<u8>>) -> Body {
    Body::Profile(Profile {
        rev,
        name: name.into(),
        status: String::new(),
        picture,
        pad: Vec::new(),
    })
}

async fn view(c: &Client, id: i64) -> ContactView {
    c.contacts()
        .await
        .unwrap()
        .into_iter()
        .find(|x| x.id == id)
        .unwrap()
}

/// Waits until `f` holds for the contact's view.
async fn until(c: &Client, id: i64, f: impl Fn(&ContactView) -> bool) -> ContactView {
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
    b.set_contact_picture(b_alice.id, Some(picture(b"local")))
        .await
        .unwrap();
    assert!(
        b.picture(Some(b_alice.id))
            .await
            .unwrap()
            .unwrap()
            .starts_with("data:image/jpeg;")
    );
    assert!(view(b, b_alice.id).await.local_picture);
    b.set_contact_picture(b_alice.id, None).await.unwrap();
    let v = view(b, b_alice.id).await;
    assert!(v.picture.is_none() && !v.local_picture);

    // Refused: not a JPEG (an SVG, a PNG), one that declares a huge size (review PR-1), too
    // many bytes, unknown contacts, an empty nickname.
    for bad in [
        b"<svg onload=alert(1)>".to_vec(),
        b"\x89PNG\r\n\x1a\n....".to_vec(),
        jpeg(60000, 60000, b""),
    ] {
        assert_eq!(
            a.set_my_picture(Some(b64(&bad))).await.unwrap_err(),
            ClientError::BadInput
        );
    }
    let mut big = jpeg(10, 10, b"");
    big.resize(veil_core::content::MAX_PICTURE_LEN + 1, 0);
    assert_eq!(
        a.set_my_picture(Some(b64(&big))).await.unwrap_err(),
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
    let a = &alice.client;
    assert_eq!(a_bob.name, "Bob");

    // Mallory renames herself "bob": Alice keeps calling her Mallory, and says so.
    mallory
        .client
        .set_profile(" bob ".into(), String::new())
        .await
        .unwrap();
    let v = until(a, a_mal.id, |v| v.their_name.is_some()).await;
    assert_eq!(
        (v.name.as_str(), v.their_name.as_deref()),
        ("Mallory", Some("bob"))
    );

    // A picture that declares 60000 × 60000 pixels is dropped on arrival (review PR-1).
    let huge = profile(u64::MAX - 1, "bob", Some(jpeg(60000, 60000, b"bomb")));
    mallory
        .client
        .raw_send(m_alice.id, vec![8; 16], huge)
        .await
        .unwrap();
    mallory.client.send(m_alice.id, "bomb sent".into()).await.unwrap();
    arrives(a, a_mal.id, "bomb sent").await;
    assert!(view(a, a_mal.id).await.picture.is_none());

    // An older profile (a replay, or one overtaken in transit) changes nothing.
    let old = Body::Profile(Profile {
        rev: 1,
        name: "Old".into(),
        status: "old".into(),
        picture: None,
        pad: Vec::new(),
    });
    mallory
        .client
        .raw_send(m_alice.id, vec![9; 16], old)
        .await
        .unwrap();
    mallory.client.send(m_alice.id, "after".into()).await.unwrap();
    arrives(a, a_mal.id, "after").await;
    let v = view(a, a_mal.id).await;
    assert_eq!(v.their_name.as_deref(), Some("bob"));
    assert!(v.status.is_none());
}

/// Look-alike letters do not get a contact another contact's name, and a name that changes is
/// written into the chat (review PR-6).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lookalike_names_are_refused_and_renames_are_shown() {
    let r = relay().await;
    let (alice, bob, mallory) = (
        user(&r, "Alice").await,
        user(&r, "Bob").await,
        user(&r, "Mallory").await,
    );
    let (a_bob, _) = pair(&alice.client, &bob.client).await;
    let (a_mal, _) = pair(&alice.client, &mallory.client).await;
    let (ali, bo, mal) = (&alice.client, &bob.client, &mallory.client);
    // Bob's own name counts as taken even under a nickname.
    bo.set_profile("Bob".into(), String::new()).await.unwrap();
    until(ali, a_bob.id, |v| v.status.is_none() && v.name == "Bob").await;
    ali.set_nickname(a_bob.id, Some("Bobby".into())).await.unwrap();
    for fake in ["Вob", "Ｂob", "B0b", "Böb", "bob"] {
        mal.set_profile(fake.into(), String::new()).await.unwrap();
        let v = until(ali, a_mal.id, |v| v.their_name.as_deref() == Some(fake)).await;
        assert_eq!(v.name, "Mallory", "{fake} was adopted");
    }
    // A real rename is shown, and written into the chat.
    mal.set_profile("Mal".into(), String::new()).await.unwrap();
    until(ali, a_mal.id, |v| v.name == "Mal").await;
    let lines: Vec<String> = ali
        .messages(a_mal.id)
        .await
        .unwrap()
        .into_iter()
        .filter(|x| x.kind == "renamed")
        .map(|x| x.text)
        .collect();
    assert_eq!(lines, ["Mallory\nMal"]);
    // "Use their name" refuses a name another contact has, and keeps the nickname (PR-15).
    ali.set_nickname(a_mal.id, Some("M".into())).await.unwrap();
    mal.set_profile("Bobby".into(), String::new()).await.unwrap();
    until(ali, a_mal.id, |v| v.their_name.as_deref() == Some("Bobby")).await;
    assert_eq!(
        ali.set_nickname(a_mal.id, None).await.unwrap_err(),
        ClientError::NameTaken
    );
    let v = view(ali, a_mal.id).await;
    assert!(v.nickname && v.name == "M");
}

/// The picture never reaches a contact with an unresolved key-change warning, nor one the user
/// hid it from, even after accepting their new key (reviews PR-2, PR-8, PR-11).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_changes_keep_the_users_choices() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (a_bob, _) = pair(&alice.client, &bob.client).await;
    let a = &alice.client;
    a.set_my_picture(Some(picture(b"kc"))).await.unwrap();
    a.set_picture_visibility(PictureVisibility::All).await.unwrap();
    a.set_picture_hidden(a_bob.id, true).await.unwrap();
    a.set_nickname(a_bob.id, Some("Bobby".into())).await.unwrap();
    a.set_contact_picture(a_bob.id, Some(picture(b"mine")))
        .await
        .unwrap();

    // Bob reinstalled: a new key under the same name. Nothing goes to the new key while the
    // warning stands, not even the name.
    let bob2 = user(&r, "Bob").await;
    let (a_bob2, b2_alice) = pair(a, &bob2.client).await;
    assert!(a_bob2.key_warning);
    a.set_picture_hidden(a_bob2.id, false).await.unwrap(); // a sync round for them
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let v = view(&bob2.client, b2_alice.id).await;
    assert!(v.picture.is_none() && v.name.starts_with("Contact "));

    // "It's them": the choices about Bob carry over, so he still does not get the picture.
    a.accept_key_change(a_bob2.id, a_bob.id).await.unwrap();
    let v = view(a, a_bob2.id).await;
    assert!(v.picture_hidden && v.nickname && v.name == "Bobby" && v.local_picture);
    a.set_profile("Alice A".into(), String::new()).await.unwrap();
    let v = until(&bob2.client, b2_alice.id, |v| v.name == "Alice A").await;
    assert!(
        v.picture.is_none(),
        "picture reached a contact it was hidden from"
    );

    // A warning dismissed (kept apart, not merged): from then on they are a contact like any
    // other, and get the picture as the setting says.
    let bob3 = user(&r, "Bob").await;
    let (a_bob3, b3_alice) = pair(a, &bob3.client).await;
    assert!(a_bob3.key_warning);
    a.dismiss_key_warning(a_bob3.id).await.unwrap();
    a.set_picture_hidden(a_bob3.id, false).await.unwrap();
    until(&bob3.client, b3_alice.id, |v| v.picture.is_some()).await;
}

/// A picture taken back while a contact is blocked, or whose taking back was given up on,
/// still leaves their screen (reviews PR-3, PR-4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_picture_taken_back_always_leaves() {
    let r = relay().await;
    let hop = Proxy::to(&r.addr).await;
    let alice = user_at(&r, &hop.addr, "Alice", None).await;
    let bob = user(&r, "Bob").await;
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    let (a, b) = (&alice.client, &bob.client);
    a.set_my_picture(Some(picture(b"tb"))).await.unwrap();
    a.set_picture_visibility(PictureVisibility::All).await.unwrap();
    until(b, b_alice.id, |v| v.picture.is_some()).await;

    // A new picture queued while offline; Bob blocked; taken back; unblocked: it leaves, and
    // the queued one never arrives.
    hop.cut();
    online(a, false).await;
    a.set_my_picture(Some(picture(b"tb2"))).await.unwrap();
    a.set_blocked(a_bob.id, true).await.unwrap();
    a.set_picture_visibility(PictureVisibility::Nobody).await.unwrap();
    hop.restore();
    online(a, true).await;
    a.set_blocked(a_bob.id, false).await.unwrap();
    until(b, b_alice.id, |v| v.picture.is_none()).await;

    // Taken back while offline, and that update given up on: the next round sends it again.
    a.set_picture_visibility(PictureVisibility::All).await.unwrap();
    until(b, b_alice.id, |v| v.picture.is_some()).await;
    hop.cut();
    online(a, false).await;
    a.set_picture_visibility(PictureVisibility::Nobody).await.unwrap();
    assert_eq!(a.give_up_profiles(a_bob.id).await.unwrap(), 1);
    hop.restore();
    online(a, true).await;
    a.set_picture_hidden(a_bob.id, false).await.unwrap(); // a sync round for Bob
    until(b, b_alice.id, |v| v.picture.is_none()).await;
}

/// An animated GIF works as a picture; its metadata never leaves the device (ADR-0020).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn animated_gifs_arrive_without_their_metadata() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (_, b_alice) = pair(&alice.client, &bob.client).await;
    let (a, b) = (&alice.client, &bob.client);
    let frame = [0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 2, 0x44, 0x01, 0];
    let mut gif = b"GIF89a\x02\x00\x02\x00\x80\x00\x00\xFF\xFF\xFF\x00\x00\x00".to_vec();
    gif.extend_from_slice(b"\x21\xFF\x0BNETSCAPE2.0\x03\x01\x00\x00\x00");
    let clean_len = gif.len() + 2 * (8 + frame.len()) + 1;
    gif.extend_from_slice(b"\x21\xFE\x12gif-metadata-probe\x00");
    for _ in 0..2 {
        gif.extend_from_slice(&[0x21, 0xF9, 4, 4, 10, 0, 0, 0]);
        gif.extend_from_slice(&frame);
    }
    gif.push(0x3B);

    a.set_my_picture(Some(b64(&gif))).await.unwrap();
    a.set_picture_visibility(PictureVisibility::All).await.unwrap();
    until(b, b_alice.id, |v| v.picture.is_some()).await;
    let url = b.picture(Some(b_alice.id)).await.unwrap().unwrap();
    let got = base64::engine::general_purpose::STANDARD
        .decode(url.strip_prefix("data:image/gif;base64,").unwrap())
        .unwrap();
    assert_eq!(got.len(), clean_len);
    assert!(got.starts_with(b"GIF89a") && !got.windows(18).any(|w| w == b"gif-metadata-probe"));
    // A local GIF for a contact works the same way.
    b.set_contact_picture(b_alice.id, Some(b64(&gif))).await.unwrap();
    assert!(
        b.picture(Some(b_alice.id))
            .await
            .unwrap()
            .unwrap()
            .starts_with("data:image/gif;")
    );
}
