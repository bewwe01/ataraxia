//! PIN or password, failed-attempt delays, the Purge PIN and biometric unlock (ADR-0012).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::format_collect,
    clippy::too_many_lines
)]

use std::path::Path;
use std::sync::Arc;

use veil_client::ClientError;
use veil_client::service::{AppState, Client, SetupInput, UnlockOutcome};
use veil_client::unlock::SecretKind;
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

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.into())
}

async fn setup(r: &Relay, dir: &Path, kind: SecretKind, secret: &str) -> Client {
    let c = Client::start(dir.into(), KdfParams::FLOOR, Arc::new(|_, _| {})).unwrap();
    c.setup(SetupInput {
        relay: r.addr.clone(),
        pin: r.pin.clone(),
        name: "Alice".into(),
        kind,
        passphrase: z(secret),
    })
    .await
    .unwrap();
    c
}

fn files(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|it| {
            it.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pin_rules_and_attempt_delays() {
    let r = relay().await;
    let d = tempfile::tempdir().unwrap();
    let c = Client::start(d.path().into(), KdfParams::FLOOR, Arc::new(|_, _| {})).unwrap();
    let mut input = SetupInput {
        relay: r.addr.clone(),
        pin: r.pin.clone(),
        name: "A".into(),
        kind: SecretKind::Pin,
        passphrase: z("12345"),
    };
    assert_eq!(c.setup(input).await.unwrap_err(), ClientError::BadInput);
    input = SetupInput {
        relay: r.addr.clone(),
        pin: r.pin.clone(),
        name: "A".into(),
        kind: SecretKind::Pin,
        passphrase: z("482913"),
    };
    c.setup(input).await.unwrap();
    c.lock().await.unwrap();
    let info = c.unlock_info().await.unwrap();
    assert_eq!(info.kind, SecretKind::Pin);
    assert!(!info.biometric);

    for _ in 0..6 {
        assert_eq!(
            c.unlock(z("000000")).await.unwrap_err(),
            ClientError::WrongPassphrase
        );
    }
    // Now even the right PIN has to wait.
    assert!(c.unlock_info().await.unwrap().wait_secs > 0);
    assert_eq!(c.unlock(z("482913")).await.unwrap_err(), ClientError::RetryLater);
    assert_eq!(c.state().await.unwrap(), AppState::Locked);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn purge_pin_wipes_everything() {
    let r = relay().await;
    let d = tempfile::tempdir().unwrap();
    let c = setup(&r, d.path(), SecretKind::Pin, "482913").await;
    assert!(!c.security().await.unwrap().purge_set);
    // Wrong current PIN refused; the Purge PIN may not equal the PIN.
    assert_eq!(
        c.set_purge(z("111111"), z("999999")).await.unwrap_err(),
        ClientError::WrongPassphrase
    );
    assert_eq!(
        c.set_purge(z("482913"), z("482913")).await.unwrap_err(),
        ClientError::PurgeSameAsUnlock
    );
    assert_eq!(
        c.set_purge(z("482913"), z("abc")).await.unwrap_err(),
        ClientError::BadInput
    );
    c.set_purge(z("482913"), z("999999")).await.unwrap();
    assert!(c.security().await.unwrap().purge_set);
    c.create_invite().await.unwrap();

    // The real PIN still opens Veil.
    c.lock().await.unwrap();
    assert_eq!(c.unlock(z("482913")).await.unwrap(), UnlockOutcome::Unlocked);
    c.lock().await.unwrap();
    assert!(!files(d.path()).is_empty());

    // The Purge PIN wipes the data directory.
    assert_eq!(c.unlock(z("999999")).await.unwrap(), UnlockOutcome::Purged);
    assert_eq!(files(d.path()), Vec::<String>::new());
    assert_eq!(c.state().await.unwrap(), AppState::New);
    // Afterwards every attempt, even the old PIN, looks like a wrong PIN.
    assert_eq!(
        c.unlock(z("482913")).await.unwrap_err(),
        ClientError::WrongPassphrase
    );
    // And Veil can be set up from scratch.
    let c2 = setup(&r, d.path(), SecretKind::Password, "a brand new start").await;
    assert_eq!(c2.state().await.unwrap(), AppState::Unlocked);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn change_secret_clears_purge_and_switches_kind() {
    let r = relay().await;
    let d = tempfile::tempdir().unwrap();
    let c = setup(&r, d.path(), SecretKind::Password, "correct horse battery").await;
    c.set_purge(z("correct horse battery"), z("a purge passphrase"))
        .await
        .unwrap();
    assert_eq!(
        c.change_secret(z("wrong passphrase!!"), SecretKind::Pin, z("135790"))
            .await
            .unwrap_err(),
        ClientError::WrongPassphrase
    );
    assert_eq!(
        c.change_secret(z("correct horse battery"), SecretKind::Pin, z("12a456"))
            .await
            .unwrap_err(),
        ClientError::BadInput
    );
    c.change_secret(z("correct horse battery"), SecretKind::Pin, z("135790"))
        .await
        .unwrap();
    let sec = c.security().await.unwrap();
    assert_eq!(sec.kind, SecretKind::Pin);
    assert!(!sec.purge_set);

    c.lock().await.unwrap();
    // The old purge passphrase is now just wrong; nothing is wiped.
    assert_eq!(
        c.unlock(z("a purge passphrase")).await.unwrap_err(),
        ClientError::WrongPassphrase
    );
    assert_eq!(
        c.unlock(z("correct horse battery")).await.unwrap_err(),
        ClientError::WrongPassphrase
    );
    assert_eq!(c.unlock(z("135790")).await.unwrap(), UnlockOutcome::Unlocked);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn biometric_unlock_round_trip() {
    let r = relay().await;
    let d = tempfile::tempdir().unwrap();
    let c = setup(&r, d.path(), SecretKind::Pin, "482913").await;
    assert_eq!(
        c.biometric_prepare(z("000000")).await.unwrap_err(),
        ClientError::WrongPassphrase
    );
    // The app shell hands this secret to the platform keystore; here a stand-in "seals" it.
    let secret = c.biometric_prepare(z("482913")).await.unwrap();
    let sealed: Vec<u8> = secret.iter().map(|b| b ^ 0x5a).collect();
    c.biometric_commit(sealed).await.unwrap();
    assert!(c.security().await.unwrap().biometric);

    c.lock().await.unwrap();
    assert!(c.unlock_info().await.unwrap().biometric);
    let blob = c.biometric_sealed().await.unwrap().unwrap();
    let opened: [u8; 32] = blob
        .iter()
        .map(|b| b ^ 0x5a)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    // A wrong secret does not open it.
    assert_eq!(
        c.unlock_biometric(Zeroizing::new([1u8; 32])).await.unwrap_err(),
        ClientError::BiometricUnavailable
    );
    c.unlock_biometric(Zeroizing::new(opened)).await.unwrap();
    assert_eq!(c.state().await.unwrap(), AppState::Unlocked);

    // Changing the PIN keeps biometric unlock working (same vault, same DB key).
    c.change_secret(z("482913"), SecretKind::Pin, z("777333"))
        .await
        .unwrap();
    c.lock().await.unwrap();
    c.unlock_biometric(Zeroizing::new(opened)).await.unwrap();

    // Turning it off removes the files.
    c.biometric_disable().await.unwrap();
    assert!(!c.security().await.unwrap().biometric);
    c.lock().await.unwrap();
    assert!(c.biometric_sealed().await.unwrap().is_none());
    assert_eq!(
        c.unlock_biometric(Zeroizing::new(opened)).await.unwrap_err(),
        ClientError::BiometricUnavailable
    );
}
