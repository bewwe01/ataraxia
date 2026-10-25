//! Regression tests for the final-gate review: auto-lock is not postponed by incoming traffic
//! (P4-2), a lock request pre-empts a stalled relay (P4-1), and setup recovers from an
//! interrupted earlier setup, as does "start over" (P4-3).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::format_collect
)]

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

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

/// A TCP forwarder to `target` that can be switched into a tarpit: it then accepts
/// connections and never answers, like a relay that stalls on purpose.
async fn proxy(target: String, tarpit: Arc<AtomicBool>) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let Ok((mut inbound, _)) = l.accept().await else {
                return;
            };
            let target = target.clone();
            let tarpit = Arc::clone(&tarpit);
            tokio::spawn(async move {
                if tarpit.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_hours(1)).await;
                    drop(inbound);
                    return;
                }
                let Ok(mut out) = tokio::net::TcpStream::connect(target).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut out).await;
            });
        }
    });
    addr
}

fn input(addr: &str, pin: &str, name: &str) -> SetupInput {
    SetupInput {
        relay: addr.into(),
        pin: pin.into(),
        name: name.into(),
        kind: veil_client::unlock::SecretKind::Password,
        passphrase: Zeroizing::new("correct horse battery".into()),
    }
}

async fn wait_state(c: &Client, want: AppState, within: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < within {
        if c.state().await.unwrap() == want {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incoming_traffic_does_not_postpone_auto_lock() {
    let r = relay().await;
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let auto_lock = Duration::from_secs(3);
    let alice =
        Client::start_with_auto_lock(da.path().into(), KdfParams::FLOOR, Arc::new(|_, _| {}), auto_lock)
            .unwrap();
    let bob = Client::start(db.path().into(), KdfParams::FLOOR, Arc::new(|_, _| {})).unwrap();
    alice.setup(input(&r.addr, &r.pin, "Alice")).await.unwrap();
    bob.setup(input(&r.addr, &r.pin, "Bob")).await.unwrap();
    let inv = alice.create_invite().await.unwrap();
    let b_contact = bob.accept_invite(inv.link).await.unwrap();

    // Bob keeps writing and Alice's UI keeps refreshing, as it does on every event. Neither is
    // user activity, so Alice must still lock about `auto_lock` after her last action.
    let start = Instant::now();
    let mut locked_at = None;
    while start.elapsed() < Duration::from_secs(10) {
        let _ = bob.send(b_contact.id, "ping".into()).await;
        let _ = alice.contacts().await;
        let _ = alice.me().await;
        if alice.state().await.unwrap() == AppState::Locked {
            locked_at = Some(start.elapsed());
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let t = locked_at.expect("auto-lock never fired under incoming traffic");
    assert!(t >= Duration::from_secs(2), "locked too early: {t:?}");

    // A touch is user activity and postpones it.
    alice
        .unlock(Zeroizing::new("correct horse battery".into()))
        .await
        .unwrap();
    for _ in 0..8 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        alice.touch().await.unwrap();
    }
    assert_eq!(alice.state().await.unwrap(), AppState::Unlocked);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_preempts_a_stalled_relay() {
    let r = relay().await;
    let tarpit = Arc::new(AtomicBool::new(false));
    let addr = proxy(r.addr.clone(), Arc::clone(&tarpit)).await;
    let d = tempfile::tempdir().unwrap();
    let c = Client::start(d.path().into(), KdfParams::FLOOR, Arc::new(|_, _| {})).unwrap();
    c.setup(input(&addr, &r.pin, "Alice")).await.unwrap();
    c.lock().await.unwrap();

    // The relay now stalls every new connection. Unlock blocks in connect...
    tarpit.store(true, Ordering::SeqCst);
    let c2 = c.clone();
    let unlocking =
        tokio::spawn(async move { c2.unlock(Zeroizing::new("correct horse battery".into())).await });
    tokio::time::sleep(Duration::from_millis(1500)).await;
    // ...and a lock request must not wait for the relay's 15 s timeouts.
    let start = Instant::now();
    tokio::time::timeout(Duration::from_secs(3), c.lock())
        .await
        .expect("lock waited for the relay")
        .unwrap();
    assert!(start.elapsed() < Duration::from_secs(3));
    let _ = unlocking.await.unwrap();
    assert_eq!(c.state().await.unwrap(), AppState::Locked);
}

fn plant_debris(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("device.secret"), [7u8; 32]).unwrap();
    std::fs::write(dir.join("veil.db"), b"not a database from this setup").unwrap();
    std::fs::write(dir.join("vault.hdr.tmp"), b"torn").unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setup_recovers_from_debris_and_reset_starts_over() {
    let r = relay().await;
    let d = tempfile::tempdir().unwrap();
    plant_debris(d.path());
    let c = Client::start(d.path().into(), KdfParams::FLOOR, Arc::new(|_, _| {})).unwrap();
    assert_eq!(c.state().await.unwrap(), AppState::New);
    c.setup(input(&r.addr, &r.pin, "Alice")).await.unwrap();
    assert!(c.create_invite().await.is_ok());

    // Start over: everything goes, and a fresh setup works.
    c.reset().await.unwrap();
    assert_eq!(c.state().await.unwrap(), AppState::New);
    assert!(!d.path().join("veil.db").exists());
    assert!(!d.path().join("vault.hdr").exists());
    c.setup(input(&r.addr, &r.pin, "Alice again")).await.unwrap();
    assert!(wait_state(&c, AppState::Unlocked, Duration::from_secs(1)).await);
    assert_eq!(c.me().await.unwrap().name, "Alice again");
}
