//! End to end through the real relay: two clients set up, pair by invite link, exchange text
//! messages, agree on the safety number, lock and unlock. Also checks that message text never
//! reaches the local database file in plaintext (INV-REST-1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::format_collect,
    clippy::too_many_lines
)]

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use veil_client::ClientError;
use veil_client::service::{AppState, Client, SetupInput};
use veil_core::vault::KdfParams;
use veil_relay::server::{Config, Shared};
use veil_relay::store::Store;
use zeroize::Zeroizing;

struct Relay {
    addr: String,
    pin: String,
    _dir: tempfile::TempDir,
    _stop: tokio::sync::oneshot::Sender<()>,
}

async fn relay() -> Relay {
    let dir = tempfile::tempdir().unwrap();
    let pin = veil_relay::tls::generate(&dir.path().join("tls"), vec!["127.0.0.1".into()]).unwrap();
    let (tls, _) =
        veil_relay::tls::load(&dir.path().join("tls/cert.pem"), &dir.path().join("tls/key.pem")).unwrap();
    let cfg = Config::default();
    let store = Store::open(&dir.path().join("relay.redb"), cfg.quotas).unwrap();
    let shared = Shared::new(store, cfg, pin, veil_relay::server::system_clock());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(veil_relay::server::serve(
        listener,
        tls,
        Arc::clone(&shared),
        async {
            let _ = rx.await;
        },
    ));
    let pin = pin.iter().map(|b| format!("{b:02x}")).collect();
    Relay {
        addr,
        pin,
        _dir: dir,
        _stop: tx,
    }
}

fn start(dir: &Path) -> Client {
    Client::start(dir.to_path_buf(), KdfParams::FLOOR, Arc::new(|_, _| {})).unwrap()
}

fn input(r: &Relay, name: &str, pass: &str) -> SetupInput {
    SetupInput {
        relay: r.addr.clone(),
        pin: r.pin.clone(),
        name: name.into(),
        kind: veil_client::unlock::SecretKind::Password,
        passphrase: Zeroizing::new(pass.into()),
    }
}

async fn eventually<T, F: Future<Output = Option<T>>>(mut f: impl FnMut() -> F) -> T {
    for _ in 0..200 {
        if let Some(v) = f().await {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("condition not reached in 10 s");
}

fn file_contains(dir: &Path, needle: &[u8]) -> bool {
    std::fs::read_dir(dir).unwrap().flatten().any(|e| {
        e.path().is_file()
            && std::fs::read(e.path()).is_ok_and(|b| b.windows(needle.len()).any(|w| w == needle))
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_clients_pair_and_talk() {
    let r = relay().await;
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let alice = start(da.path());
    let bob = start(db.path());
    assert_eq!(alice.state().await.unwrap(), AppState::New);

    // A wrong pin is a hard failure, and leaves nothing behind.
    let mut bad = input(&r, "Alice", "correct horse battery");
    bad.pin = "00".repeat(32);
    assert_eq!(alice.setup(bad).await.unwrap_err(), ClientError::PinMismatch);
    assert_eq!(alice.state().await.unwrap(), AppState::New);

    alice
        .setup(input(&r, "Alice", "correct horse battery"))
        .await
        .unwrap();
    bob.setup(input(&r, "Bob", "tr0ub4dor and three")).await.unwrap();
    assert_eq!(
        alice
            .setup(input(&r, "A", "correct horse battery"))
            .await
            .unwrap_err(),
        ClientError::AlreadySetUp
    );

    let inv = alice.create_invite().await.unwrap();
    let b_contact = bob.accept_invite(inv.link.clone()).await.unwrap();
    assert!(!b_contact.verified);
    // Single use.
    assert!(bob.accept_invite(inv.link.clone()).await.is_err());

    let a_contact = eventually(|| async { alice.contacts().await.unwrap().into_iter().next() }).await;
    assert_eq!(a_contact.name, "Bob");
    assert!(!a_contact.verified);

    let sa = alice.safety(a_contact.id).await.unwrap();
    let sb = bob.safety(b_contact.id).await.unwrap();
    assert_eq!(sa.groups, sb.groups);

    let secret = "the eagle lands at midnight";
    let sent = bob.send(b_contact.id, secret.into()).await.unwrap();
    assert!(sent.mine);
    let got = eventually(|| async {
        alice
            .messages(a_contact.id)
            .await
            .unwrap()
            .into_iter()
            .find(|m| !m.mine)
    })
    .await;
    assert_eq!(got.text, secret);
    assert_eq!(alice.contacts().await.unwrap()[0].unread, 1);
    alice.mark_read(a_contact.id).await.unwrap();
    assert_eq!(alice.contacts().await.unwrap()[0].unread, 0);

    alice.send(a_contact.id, "copy that".into()).await.unwrap();
    let back = eventually(|| async {
        bob.messages(b_contact.id)
            .await
            .unwrap()
            .into_iter()
            .find(|m| !m.mine)
    })
    .await;
    assert_eq!(back.text, "copy that");
    let mine = bob
        .messages(b_contact.id)
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.mine)
        .unwrap();
    assert_eq!(mine.status, "sent");

    alice.set_verified(a_contact.id, true).await.unwrap();
    assert!(alice.contacts().await.unwrap()[0].verified);

    // Lock, wrong passphrase, unlock: history survives.
    alice.lock().await.unwrap();
    assert_eq!(alice.state().await.unwrap(), AppState::Locked);
    assert_eq!(
        alice.messages(a_contact.id).await.unwrap_err(),
        ClientError::Locked
    );
    assert_eq!(
        alice
            .unlock(Zeroizing::new("wrong passphrase!!".into()))
            .await
            .unwrap_err(),
        ClientError::WrongPassphrase
    );
    alice
        .unlock(Zeroizing::new("correct horse battery".into()))
        .await
        .unwrap();
    assert_eq!(alice.messages(a_contact.id).await.unwrap().len(), 2);

    // Messages delivered while locked arrive after unlock.
    alice.lock().await.unwrap();
    bob.send(b_contact.id, "while you were away".into())
        .await
        .unwrap();
    alice
        .unlock(Zeroizing::new("correct horse battery".into()))
        .await
        .unwrap();
    eventually(|| async {
        alice
            .messages(a_contact.id)
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.text == "while you were away")
    })
    .await;

    // No plaintext at rest.
    alice.lock().await.unwrap();
    bob.lock().await.unwrap();
    for d in [da.path(), db.path()] {
        for needle in [secret.as_bytes(), b"copy that", b"Alice", b"Bob"] {
            assert!(!file_contains(d, needle), "plaintext found at rest");
        }
    }
}

/// One relay reached at two addresses (as over a tailnet IP and over a public name): an invite
/// naming the other address is accepted, because the pin is what identifies the relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invite_from_another_address_of_the_same_relay() {
    let r = relay().await;
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let alice = start(da.path());
    let bob = start(db.path());
    alice
        .setup(input(&r, "Alice", "correct horse battery"))
        .await
        .unwrap();
    let mut other = input(&r, "Bob", "tr0ub4dor and three");
    other.relay = r.addr.replacen("127.0.0.1", "localhost", 1);
    assert_ne!(other.relay, r.addr);
    bob.setup(other).await.unwrap();

    let inv = alice.create_invite().await.unwrap();
    let b_contact = bob.accept_invite(inv.link.clone()).await.unwrap();
    let a_contact = eventually(|| async { alice.contacts().await.unwrap().into_iter().next() }).await;
    assert_eq!(a_contact.name, "Bob");

    bob.send(b_contact.id, "hi from the other address".into())
        .await
        .unwrap();
    let got = eventually(|| async {
        alice
            .messages(a_contact.id)
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.text == "hi from the other address")
    })
    .await;
    assert!(!got.mine);
}
