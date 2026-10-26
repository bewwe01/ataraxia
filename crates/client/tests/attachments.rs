//! Milestone 3 end to end through the real relay: photos, files and voice notes are encrypted,
//! uploaded in chunks, sent, downloaded, checked and decrypted; uploads resume after the
//! connection drops; deleting and disappearing remove the file.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

mod common;

use std::time::Duration;

use common::*;
use rand::TryRngCore as _;
use veil_client::ClientError;
use veil_client::service::{AUTO_DOWNLOAD_PER_DAY, AttachmentInput, Client, MAX_FILE, MessageView};
use veil_core::attachment;
use veil_core::content::{Attachment, Body};
use zeroize::Zeroizing;

fn input(kind: &str, mime: &str, name: Option<&str>, data: Vec<u8>) -> AttachmentInput {
    AttachmentInput {
        kind: kind.into(),
        mime: mime.into(),
        name: name.map(Into::into),
        data: Zeroizing::new(data),
        thumbnail: None,
        duration_ms: None,
        waveform: None,
    }
}

/// Bytes that do not compress or repeat, so chunk mix-ups would show.
fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| u8::try_from((i.wrapping_mul(31) ^ (i >> 7)) & 0xFF).unwrap() ^ seed)
        .collect()
}

async fn ready(c: &Client, contact: i64, pick: impl Fn(&MessageView) -> bool) -> MessageView {
    within(Duration::from_secs(30), || async {
        c.messages(contact)
            .await
            .unwrap()
            .into_iter()
            .find(|m| pick(m) && m.attachment.as_ref().is_some_and(|a| a.state == "ready"))
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn files_photos_and_voice_notes_round_trip() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;

    // A file of several chunks (64 KiB each) with an odd size.
    let file = pattern(300_001, 7);
    let sent = alice
        .client
        .send_attachment(
            a_bob.id,
            input("file", "application/pdf", Some("../report.pdf"), file.clone()),
        )
        .await
        .unwrap();
    let att = sent.attachment.as_ref().unwrap();
    assert_eq!(
        (att.kind.as_str(), att.state.as_str(), att.name.as_deref()),
        ("file", "uploading", Some("report.pdf"))
    );
    assert_eq!(sent.status, "sending");
    let got = ready(&bob.client, b_alice.id, |m| m.kind == "attachment").await;
    let a = got.attachment.as_ref().unwrap();
    assert_eq!(
        (a.mime.as_str(), a.size, a.name.as_deref()),
        ("application/pdf", 300_001, Some("report.pdf"))
    );
    let (mime, name, data) = bob.client.attachment_data(got.id).await.unwrap();
    assert_eq!(
        (mime.as_str(), name.as_deref()),
        ("application/pdf", Some("report.pdf"))
    );
    assert_eq!(*data, file);
    // The sender keeps the file too, and the message is sent.
    within(Duration::from_secs(10), || async {
        let m = alice
            .client
            .messages(a_bob.id)
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.id == sent.id)?;
        (m.status == "sent" && m.attachment.as_ref()?.state == "sent").then_some(())
    })
    .await;
    assert_eq!(*alice.client.attachment_data(sent.id).await.unwrap().2, file);

    // A photo with its preview, and a voice note with duration and waveform.
    let mut photo = input("image", "image/webp", None, pattern(5_000, 3));
    photo.thumbnail = Some(vec![0xFF, 0xD8, 1, 2, 3]);
    bob.client.send_attachment(b_alice.id, photo).await.unwrap();
    let mut voice = input("voice", "audio/webm", None, pattern(20_000, 9));
    voice.duration_ms = Some(4_200);
    voice.waveform = Some(vec![10, 200, 30]);
    bob.client.send_attachment(b_alice.id, voice).await.unwrap();
    let pic = ready(&alice.client, a_bob.id, |m| {
        m.attachment.as_ref().is_some_and(|a| a.kind == "image")
    })
    .await;
    assert_eq!(pic.attachment.unwrap().thumbnail, Some(vec![0xFF, 0xD8, 1, 2, 3]));
    let v = ready(&alice.client, a_bob.id, |m| {
        m.attachment.as_ref().is_some_and(|a| a.kind == "voice")
    })
    .await;
    let va = v.attachment.unwrap();
    assert_eq!((va.duration_ms, va.waveform), (Some(4_200), vec![10, 200, 30]));
    // The chat list says what it is, never the bytes.
    let c = alice.client.contacts().await.unwrap();
    assert_eq!(c[0].last_text.as_deref(), Some("🎤 Voice message"));

    // Reactions and replies work on attachments; edits do not.
    alice.client.react(v.id, Some("👍".into())).await.unwrap();
    let reply = alice.client.reply(a_bob.id, "nice".into(), pic.id).await.unwrap();
    assert_eq!(reply.reply.unwrap().text, "📎 Attachment");
    assert_eq!(
        alice.client.edit_message(sent.id, "x".into()).await.unwrap_err(),
        ClientError::BadInput
    );

    // No plaintext at rest, anywhere in either data folder (INV-ATT-4, review M3-5).
    alice.client.lock().await.unwrap();
    bob.client.lock().await.unwrap();
    for d in [alice.dir(), bob.dir()] {
        for canary in [
            &file[100_000..100_064],
            &pattern(5_000, 3)[1_000..1_064],
            &pattern(20_000, 9)[9_000..9_064],
        ] {
            assert!(!tree_contains(d, canary), "file plaintext found at rest");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn limits_and_names() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (a_bob, _) = pair(&alice.client, &bob.client).await;
    let too_big = input(
        "file",
        "application/zip",
        Some("big.zip"),
        vec![0; veil_client::service::MAX_FILE + 1],
    );
    assert_eq!(
        alice.client.send_attachment(a_bob.id, too_big).await.unwrap_err(),
        ClientError::BadInput
    );
    for bad in [
        input("file", "text/html; x=1", Some("a"), vec![1]),
        input("file", "application/pdf", Some(".."), vec![1]),
        input("voice", "audio/webm", None, vec![1]),
        input("file", "application/pdf", Some("a"), vec![]),
    ] {
        assert_eq!(
            alice.client.send_attachment(a_bob.id, bad).await.unwrap_err(),
            ClientError::BadInput
        );
    }
    let mut thumb = input("image", "image/png", None, vec![1, 2, 3]);
    thumb.thumbnail = Some(vec![0; 9 * 1024]);
    assert_eq!(
        alice.client.send_attachment(a_bob.id, thumb).await.unwrap_err(),
        ClientError::BadInput
    );
    // SVG is a file, never an inline image.
    let svg = alice
        .client
        .send_attachment(
            a_bob.id,
            input("image", "image/svg+xml", Some("x.svg"), vec![b'<'; 10]),
        )
        .await
        .unwrap();
    assert_eq!(svg.attachment.unwrap().kind, "file");
}

/// The connection drops in the middle of an upload; it resumes where it stopped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_resumes_after_the_connection_drops() {
    let r = relay().await;
    let hop = Proxy::to(&r.addr).await;
    let alice = user_at(&r, &hop.addr, "Alice", None).await;
    let bob = user(&r, "Bob").await;
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    let file = pattern(2_000_000, 1);
    let sent = alice
        .client
        .send_attachment(
            a_bob.id,
            input("file", "application/octet-stream", Some("big.bin"), file.clone()),
        )
        .await
        .unwrap();
    // Cut as soon as some progress shows.
    within(Duration::from_secs(20), || async {
        let m = alice
            .client
            .messages(a_bob.id)
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.id == sent.id)?;
        (m.attachment?.progress > 0.0).then_some(())
    })
    .await;
    hop.cut();
    online(&alice.client, false).await;
    let stuck = alice
        .client
        .messages(a_bob.id)
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.id == sent.id)
        .unwrap();
    assert_eq!(stuck.attachment.unwrap().state, "uploading");
    hop.restore();
    online(&alice.client, true).await;
    let got = within(Duration::from_mins(1), || async {
        bob.client
            .messages(b_alice.id)
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.attachment.as_ref().is_some_and(|a| a.state == "ready"))
    })
    .await;
    assert_eq!(*bob.client.attachment_data(got.id).await.unwrap().2, file);
}

/// Deleting for everyone removes the file on both sides; so does the disappearing timer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_and_expiry_remove_the_file() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    let sent = alice
        .client
        .send_attachment(
            a_bob.id,
            input("file", "text/plain", Some("note.txt"), b"secret plan".to_vec()),
        )
        .await
        .unwrap();
    let got = ready(&bob.client, b_alice.id, |m| m.kind == "attachment").await;
    // Not yet sent? Wait until it is, then delete for everyone.
    within(Duration::from_secs(10), || async {
        let m = alice
            .client
            .messages(a_bob.id)
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.id == sent.id)?;
        (m.status == "sent").then_some(())
    })
    .await;
    alice.client.delete_for_everyone(sent.id).await.unwrap();
    within(Duration::from_secs(10), || async {
        let m = bob
            .client
            .messages(b_alice.id)
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.id == got.id)?;
        (m.deleted && m.attachment.is_none()).then_some(())
    })
    .await;
    assert!(bob.client.attachment_data(got.id).await.is_err());
    assert!(alice.client.attachment_data(sent.id).await.is_err());

    // Disappearing: gone from both, file included.
    alice.client.set_timer(a_bob.id, 4).await.unwrap();
    eventually(|| async { (bob.client.contacts().await.unwrap()[0].timer_secs == 4).then_some(()) }).await;
    let s2 = alice
        .client
        .send_attachment(
            a_bob.id,
            input(
                "file",
                "text/plain",
                Some("brief.txt"),
                b"burn after reading".to_vec(),
            ),
        )
        .await
        .unwrap();
    let g2 = ready(&bob.client, b_alice.id, |m| {
        m.attachment
            .as_ref()
            .is_some_and(|a| a.name.as_deref() == Some("brief.txt"))
    })
    .await;
    within(Duration::from_secs(15), || async {
        let gone_b = bob.client.attachment_data(g2.id).await.is_err();
        let gone_a = alice.client.attachment_data(s2.id).await.is_err();
        (gone_a && gone_b).then_some(())
    })
    .await;
}

/// Compares large files without printing them on failure.
fn same(a: &[u8], b: &[u8]) -> bool {
    a == b
}

/// An `Attachment` message as a contact could craft it.
fn crafted(
    blob_id: &[u8],
    key: &attachment::AttachmentKey,
    sha: &[u8],
    size: u64,
    padded: u64,
    name: &str,
) -> Body {
    Body::Attachment(Attachment {
        blob_id: blob_id.to_vec(),
        key: key.key_bytes().to_vec(),
        nonce_prefix: key.nonce_prefix().to_vec(),
        ciphertext_sha256: sha.to_vec(),
        size,
        padded_size: padded,
        mime: "application/octet-stream".into(),
        file_name: Some(name.into()),
        thumbnail: None,
        voice_duration_ms: None,
        waveform: None,
        expire_timer_secs: None,
    })
}

fn random_id() -> Vec<u8> {
    random_bytes(16)
}

/// A blob id (32 bytes) the relay does not have.
fn random_blob() -> Vec<u8> {
    random_bytes(32)
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut id = vec![0u8; n];
    rand::rngs::OsRng.unwrap_err().try_fill_bytes(&mut id).unwrap();
    id
}

async fn named(c: &Client, contact: i64, name: &str) -> Option<MessageView> {
    c.messages(contact)
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.attachment.as_ref().and_then(|a| a.name.as_deref()) == Some(name))
}

async fn state_of(c: &Client, contact: i64, name: &str) -> Option<String> {
    Some(named(c, contact, name).await?.attachment?.state)
}

/// A hostile contact cannot get a wrong file shown: forged hashes, sizes that do not fit the
/// blob, and repeated ids all end without a file (review M3-5).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crafted_attachments_never_show_a_wrong_file() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let file = pattern(100_000, 5);
    let (key, enc) = attachment::encrypt(&mut rng, &file).unwrap();
    let first_blob = bob.client.raw_upload(enc.ciphertext.clone()).await.unwrap();
    let (size, padded, sha) = (enc.size, enc.padded_size, enc.ciphertext_sha256);
    let send = |id: Vec<u8>, body: Body| bob.client.raw_send(b_alice.id, id, body);

    // A forged hash: downloaded, checked, refused.
    let mut bad_sha = sha;
    bad_sha[0] ^= 1;
    send(
        random_id(),
        crafted(&first_blob, &key, &bad_sha, size, padded, "forged-hash"),
    )
    .await
    .unwrap();
    // Sizes that do not fit each other: dropped on arrival.
    send(
        random_id(),
        crafted(&first_blob, &key, &sha, size, padded + 1, "bad-padding"),
    )
    .await
    .unwrap();
    // A size that needs more chunks than the first_blob has: refused at the first chunk.
    let big = 3 * 1024 * 1024;
    let big_padded = attachment::padded_size(big).unwrap();
    send(
        random_id(),
        crafted(&first_blob, &key, &sha, big, big_padded, "wrong-count"),
    )
    .await
    .unwrap();
    // Larger than this version takes: never downloaded.
    let huge = u64::try_from(MAX_FILE).unwrap() + 1;
    let huge_padded = attachment::padded_size(huge).unwrap();
    send(
        random_id(),
        crafted(&first_blob, &key, &sha, huge, huge_padded, "too-large"),
    )
    .await
    .unwrap();
    // The genuine one, then its id again with another file.
    let id = random_id();
    send(
        id.clone(),
        crafted(&first_blob, &key, &sha, size, padded, "genuine"),
    )
    .await
    .unwrap();
    let (key2, enc2) = attachment::encrypt(&mut rng, &pattern(100_000, 6)).unwrap();
    let second_blob = bob.client.raw_upload(enc2.ciphertext).await.unwrap();
    send(
        id,
        crafted(
            &second_blob,
            &key2,
            &enc2.ciphertext_sha256,
            enc2.size,
            enc2.padded_size,
            "repeat",
        ),
    )
    .await
    .unwrap();

    let ok = within(Duration::from_secs(20), || async {
        named(&alice.client, a_bob.id, "genuine")
            .await
            .filter(|m| m.attachment.as_ref().is_some_and(|a| a.state == "ready"))
    })
    .await;
    assert_eq!(*alice.client.attachment_data(ok.id).await.unwrap().2, file);
    for name in ["forged-hash", "wrong-count"] {
        within(Duration::from_secs(20), || async {
            (state_of(&alice.client, a_bob.id, name).await.as_deref() == Some("failed")).then_some(())
        })
        .await;
        let m = named(&alice.client, a_bob.id, name).await.unwrap();
        assert_eq!(
            alice.client.attachment_data(m.id).await.unwrap_err(),
            ClientError::NotReady
        );
    }
    assert_eq!(
        state_of(&alice.client, a_bob.id, "too-large").await.as_deref(),
        Some("too_large")
    );
    assert!(named(&alice.client, a_bob.id, "bad-padding").await.is_none());
    assert!(named(&alice.client, a_bob.id, "repeat").await.is_none());
    let files = alice
        .client
        .messages(a_bob.id)
        .await
        .unwrap()
        .into_iter()
        .filter(|m| m.attachment.is_some())
        .count();
    assert_eq!(files, 4, "one row per id");
}

/// Blobs the relay does not have fail at once and never hold up the user's own uploads
/// (review M3-4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_blobs_do_not_hold_up_uploads() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let (key, enc) = attachment::encrypt(&mut rng, &pattern(70_000, 2)).unwrap();
    for i in 0..5 {
        let body = crafted(
            &random_blob(),
            &key,
            &enc.ciphertext_sha256,
            enc.size,
            enc.padded_size,
            &format!("gone-{i}"),
        );
        bob.client.raw_send(b_alice.id, random_id(), body).await.unwrap();
    }
    within(Duration::from_secs(20), || async {
        (state_of(&alice.client, a_bob.id, "gone-4").await.is_some()).then_some(())
    })
    .await;
    let file = pattern(200_000, 4);
    let sent = alice
        .client
        .send_attachment(
            a_bob.id,
            input("file", "application/octet-stream", Some("mine.bin"), file.clone()),
        )
        .await
        .unwrap();
    within(Duration::from_secs(10), || async {
        let m = alice
            .client
            .messages(a_bob.id)
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.id == sent.id)?;
        (m.status == "sent").then_some(())
    })
    .await;
    let got = ready(&bob.client, b_alice.id, |m| m.kind == "attachment").await;
    assert_eq!(*bob.client.attachment_data(got.id).await.unwrap().2, file);
    for i in 0..5 {
        within(Duration::from_secs(10), || async {
            (state_of(&alice.client, a_bob.id, &format!("gone-{i}"))
                .await
                .as_deref()
                == Some("failed"))
            .then_some(())
        })
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn download_resumes_after_the_connection_drops() {
    let r = relay().await;
    let hop = Proxy::to(&r.addr).await;
    let alice = user(&r, "Alice").await;
    let bob = user_at(&r, &hop.addr, "Bob", None).await;
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    let file = pattern(8_000_000, 8);
    alice
        .client
        .send_attachment(
            a_bob.id,
            input("file", "application/octet-stream", Some("big.bin"), file.clone()),
        )
        .await
        .unwrap();
    // Cut as soon as part of the file is here.
    within(Duration::from_mins(1), || async {
        let a = named(&bob.client, b_alice.id, "big.bin").await?.attachment?;
        (a.progress > 0.0).then_some(())
    })
    .await;
    hop.cut();
    online(&bob.client, false).await;
    let a = named(&bob.client, b_alice.id, "big.bin")
        .await
        .unwrap()
        .attachment
        .unwrap();
    assert_eq!(a.state, "downloading", "cut part-way");
    assert!(a.progress < 1.0);
    hop.restore();
    online(&bob.client, true).await;
    let got = within(Duration::from_mins(2), || async {
        named(&bob.client, b_alice.id, "big.bin")
            .await
            .filter(|m| m.attachment.as_ref().is_some_and(|a| a.state == "ready"))
    })
    .await;
    assert!(same(&bob.client.attachment_data(got.id).await.unwrap().2, &file));
}

/// An upload token that expired while offline: the upload starts again under a fresh key,
/// blob id and token, and arrives (review M3-7).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_upload_token_starts_a_fresh_upload() {
    let r = relay_with(|c| c.quotas.upload_token_ttl_secs = 5).await;
    let hop = Proxy::to(&r.addr).await;
    let alice = user_at(&r, &hop.addr, "Alice", None).await;
    let bob = user(&r, "Bob").await;
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    let file = pattern(1_000_000, 3);
    let sent = alice
        .client
        .send_attachment(
            a_bob.id,
            input("file", "application/octet-stream", Some("late.bin"), file.clone()),
        )
        .await
        .unwrap();
    within(Duration::from_secs(20), || async {
        let m = alice
            .client
            .messages(a_bob.id)
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.id == sent.id)?;
        (m.attachment?.progress > 0.0).then_some(())
    })
    .await;
    hop.cut();
    online(&alice.client, false).await;
    tokio::time::sleep(Duration::from_secs(6)).await;
    hop.restore();
    let got = within(Duration::from_mins(1), || async {
        named(&bob.client, b_alice.id, "late.bin")
            .await
            .filter(|m| m.attachment.as_ref().is_some_and(|a| a.state == "ready"))
    })
    .await;
    assert!(same(&bob.client.attachment_data(got.id).await.unwrap().2, &file));
}

/// Past the daily allowance a contact's files wait for a tap (review M3-12).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_contact_cannot_fill_the_phone() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let (key, enc) = attachment::encrypt(&mut rng, &pattern(10, 1)).unwrap();
    // Claimed sizes only; the blobs do not exist. Four fit the allowance, the fifth does not.
    let each = u64::try_from(AUTO_DOWNLOAD_PER_DAY / 4).unwrap() - 1;
    let padded = attachment::padded_size(each).unwrap();
    for i in 0..5 {
        let body = crafted(
            &random_blob(),
            &key,
            &enc.ciphertext_sha256,
            each,
            padded,
            &format!("big-{i}"),
        );
        bob.client.raw_send(b_alice.id, random_id(), body).await.unwrap();
    }
    within(Duration::from_secs(20), || async {
        (state_of(&alice.client, a_bob.id, "big-4").await.is_some()).then_some(())
    })
    .await;
    assert_eq!(
        state_of(&alice.client, a_bob.id, "big-4").await.as_deref(),
        Some("available")
    );
    for i in 0..4 {
        assert_ne!(
            state_of(&alice.client, a_bob.id, &format!("big-{i}"))
                .await
                .as_deref(),
            Some("available")
        );
    }
    // The user taps to download: it starts (and here fails, as the blob is not there).
    let m = named(&alice.client, a_bob.id, "big-4").await.unwrap();
    alice.client.retry_attachment(m.id).await.unwrap();
    within(Duration::from_secs(20), || async {
        (state_of(&alice.client, a_bob.id, "big-4").await.as_deref() == Some("failed")).then_some(())
    })
    .await;
}
