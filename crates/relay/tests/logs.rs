//! INV-META-2 / INV-LOG-1: during a full session the relay logs nothing that identifies a
//! client: no IP, no mailbox id, no token, no blob id, no size.
//!
//! Its own test binary so the capture can be the **global** subscriber, exactly as `main.rs`
//! installs it: store calls run on `spawn_blocking` threads, which a thread-local
//! (`set_default`) subscriber would never see (review P3-6).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines
)]

mod common;

use std::sync::{Arc, Mutex};

use common::TestRelay;
use veil_relay::server::Config;
use veil_wire::{ErrorCode, Request, Response};

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_logs_nothing_about_clients() {
    let buf = Buf::default();
    let sink = buf.clone();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || sink.clone())
            .with_ansi(false)
            .finish(),
    )
    .unwrap();
    // Positive control: an event from a blocking thread reaches the capture.
    tokio::task::spawn_blocking(|| tracing::info!("capture-canary-7e11"))
        .await
        .unwrap();

    let cfg = Config {
        turn: Some(veil_relay::turn::TurnConfig {
            secret: zeroize::Zeroizing::new(vec![7; 32]),
            urls: vec!["turn:turn.relay.test:3478".into()],
            ttl_secs: 3600,
            relay_ips: vec![],
        }),
        ..Config::default()
    };
    let relay = TestRelay::start(cfg).await;
    let mut c = relay.client().await;
    let m: [u8; 32] = rand::random();
    let tok: [u8; 32] = rand::random();
    c.new_mailbox(relay.pin, m).await;
    c.add_token(m, tok).await;
    let mut s = relay.client().await;
    s.deposit(m, tok, vec![0x5A; 4096]).await.unwrap();
    let _ = s.deposit(m, [9; 32], vec![0; 1024]).await;
    c.fetch(m, 0).await.unwrap();
    c.call(Request::Ack(veil_wire::Ack {
        mailbox_id: m.to_vec(),
        up_to_seq: 1,
    }))
    .await
    .unwrap();
    // Invites.
    let inv = Request::PutInvite(veil_wire::PutInvite {
        mailbox_id: m.to_vec(),
        invite_id: vec![3; 16],
        sealed: vec![1; veil_wire::SEALED_INVITE_LEN],
        expires_at: now() + 100,
    });
    c.call(inv).await.unwrap();
    s.call(Request::TakeInvite(veil_wire::TakeInvite {
        invite_id: vec![3; 16],
    }))
    .await
    .unwrap();
    // Blobs: token, two chunks, download, a refused download.
    let Response::UploadToken(up) = c
        .call(Request::BlobUploadToken(veil_wire::MailboxRef {
            mailbox_id: m.to_vec(),
        }))
        .await
        .unwrap()
    else {
        panic!()
    };
    let blob: [u8; 32] = rand::random();
    for (i, data) in [vec![0xAB; veil_wire::MAX_BLOB_CHUNK], vec![0xCD; 777]]
        .into_iter()
        .enumerate()
    {
        c.call(Request::BlobPut(veil_wire::BlobPut {
            upload_token: up.upload_token.clone(),
            blob_id: blob.to_vec(),
            chunk_index: u32::try_from(i).unwrap(),
            total_chunks: 2,
            data,
        }))
        .await
        .unwrap();
    }
    s.call(Request::BlobGet(veil_wire::BlobGet {
        blob_id: blob.to_vec(),
        chunk_index: 1,
    }))
    .await
    .unwrap();
    assert_eq!(
        s.call(Request::BlobGet(veil_wire::BlobGet {
            blob_id: vec![0x77; 32],
            chunk_index: 0,
        }))
        .await,
        Err(ErrorCode::NotFound)
    );
    // TURN credentials.
    let Response::Turn(turn) = c
        .call(Request::TurnCredentials(veil_wire::MailboxRef {
            mailbox_id: m.to_vec(),
        }))
        .await
        .unwrap()
    else {
        panic!()
    };
    // Garbage, then delete the mailbox.
    s.send_raw(vec![0xFF; 10]).await;
    let _ = s.recv().await;
    c.call(Request::DeleteMailbox(veil_wire::MailboxRef {
        mailbox_id: m.to_vec(),
    }))
    .await
    .unwrap();
    c.close().await;
    s.close().await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let logs = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("capture-canary-7e11"), "capture is not global");
    // The relay logs nothing at all during a session (P3R2-4): any line, whatever its
    // format (hex, `Debug` arrays, sizes of derived records), is a failure.
    let other: Vec<&str> = logs
        .lines()
        .filter(|l| !l.contains("capture-canary-7e11"))
        .collect();
    assert!(
        other.is_empty(),
        "relay logged during a session:\n{}",
        other.join("\n")
    );
    // Second check, kept for clarity of intent: specific identifiers never appear.
    for (what, needle) in [
        ("client IP", "127.0.0.1".to_owned()),
        ("relay port (connection info)", relay.addr.port().to_string()),
        ("mailbox id (hex)", veil_relay::tls::hex(&m[..6])),
        ("token (hex)", veil_relay::tls::hex(&tok[..6])),
        ("blob id (hex)", veil_relay::tls::hex(&blob[..6])),
        ("upload token (hex)", veil_relay::tls::hex(&up.upload_token[..6])),
        ("TURN username", turn.username.clone()),
        ("TURN credential", turn.credential.clone()),
        ("envelope size", "4096".to_owned()),
        ("chunk size", "777".to_owned()),
        ("invite size", veil_wire::SEALED_INVITE_LEN.to_string()),
    ] {
        assert!(!logs.contains(&needle), "{what} in relay logs:\n{logs}");
    }
}
