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
use veil_client::ClientError;
use veil_client::service::{AttachmentInput, Client, MessageView};
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
