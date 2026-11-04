//! Milestone 7, encrypted backup and restore (ADR-0021).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

mod common;

use common::*;
use veil_client::ClientError;
use veil_client::service::{AppState, RestoreInput};
use veil_client::unlock::SecretKind;
use zeroize::Zeroizing;

const MARK: &str = "backup-plaintext-probe-a41c";

fn input(backup: &[u8], code: &str) -> RestoreInput {
    RestoreInput {
        backup: Zeroizing::new(backup.to_vec()),
        code: Zeroizing::new(code.to_owned()),
        kind: SecretKind::Password,
        passphrase: Zeroizing::new("a new phone, a new password".into()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restored_backup_keeps_identity_contacts_and_history() {
    let r = relay().await;
    let (alice, bob, carol) = (
        user(&r, "Alice").await,
        user(&r, "Bob").await,
        user(&r, "Carol").await,
    );
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    let (a, b) = (&alice.client, &bob.client);
    a.send(a_bob.id, format!("before the backup {MARK}"))
        .await
        .unwrap();
    arrives(b, b_alice.id, &format!("before the backup {MARK}")).await;
    b.send(b_alice.id, "hi Alice".into()).await.unwrap();
    arrives(a, a_bob.id, "hi Alice").await;
    // Bob's re-key invite reaches Alice (within a few ticks of pairing).
    within(std::time::Duration::from_secs(30), || async {
        a.has_rekey(a_bob.id).await.unwrap().then_some(())
    })
    .await;
    let safety_before = b.safety(b_alice.id).await.unwrap().groups;

    // Carol is a contact whose re-key invite never arrives (she is gone before it can).
    let (a_carol, _) = pair(a, &carol.client).await;
    carol.client.lock().await.unwrap();

    // The first backup makes the code; later ones reuse it.
    let first = a.create_backup().await.unwrap();
    let code = first.code.clone().unwrap();
    assert_eq!(code.len(), 39, "eight groups of four");
    let file = a.take_backup().await.unwrap();
    assert_eq!(u64::try_from(file.len()).unwrap(), first.bytes);
    assert!(
        !file.windows(MARK.len()).any(|w| w == MARK.as_bytes()),
        "message in the clear in the backup"
    );
    assert!(a.take_backup().await.is_err(), "the file is handed over once");
    assert!(a.create_backup().await.unwrap().code.is_none());
    let _ = a.take_backup().await.unwrap();
    // Showing the code again takes the password.
    assert_eq!(
        a.backup_code(Zeroizing::new("wrong password here".into()))
            .await
            .unwrap_err(),
        ClientError::WrongPassphrase
    );
    assert_eq!(
        a.backup_code(Zeroizing::new("correct horse battery".into()))
            .await
            .unwrap()
            .as_deref(),
        Some(code.as_str())
    );

    // Alice's phone is lost. A fresh install restores the backup.
    drop(alice);
    let dir = tempfile::tempdir().unwrap();
    let alice2 = start(dir.path(), std::sync::Arc::default());
    assert_eq!(alice2.state().await.unwrap(), AppState::New);
    // A wrong code and a damaged file are refused, and leave nothing behind.
    let other = veil_core::backup::BackupCode::generate(&mut rand::rng());
    assert_eq!(
        alice2.restore(input(&file, other.expose())).await.unwrap_err(),
        ClientError::BackupCode
    );
    let mut bad = file.to_vec();
    let mid = bad.len() / 2;
    bad[mid] ^= 1;
    assert_eq!(
        alice2.restore(input(&bad, &code)).await.unwrap_err(),
        ClientError::BackupInvalid
    );
    assert_eq!(
        alice2.restore(input(b"not a backup", &code)).await.unwrap_err(),
        ClientError::BackupInvalid
    );
    assert_eq!(alice2.state().await.unwrap(), AppState::New);
    // The right code (typed in lowercase, with spaces) works.
    let typed = code.to_lowercase().replace('-', " ");
    let view = alice2.restore(input(&file, &typed)).await.unwrap();
    assert_eq!((view.contacts, view.need_invite), (2, 1));

    // Same contacts and history; Carol needs a new invite.
    let contacts = alice2.contacts().await.unwrap();
    let bob_here = contacts.iter().find(|c| c.id == a_bob.id).unwrap();
    assert!(!bob_here.needs_invite);
    assert!(contacts.iter().find(|c| c.id == a_carol.id).unwrap().needs_invite);
    assert!(texts(&alice2, a_bob.id).await.contains(&"hi Alice".to_owned()));

    // Both ways work again; Bob sees the same Alice, same safety number, and a notice.
    alice2.send(a_bob.id, "I'm back".into()).await.unwrap();
    arrives(b, b_alice.id, "I'm back").await;
    assert_eq!(b.safety(b_alice.id).await.unwrap().groups, safety_before);
    assert!(
        !b.contacts()
            .await
            .unwrap()
            .iter()
            .find(|c| c.id == b_alice.id)
            .unwrap()
            .key_warning
    );
    assert!(
        b.messages(b_alice.id)
            .await
            .unwrap()
            .iter()
            .any(|m| m.kind == "restored")
    );
    b.send(b_alice.id, "welcome back".into()).await.unwrap();
    arrives(&alice2, a_bob.id, "welcome back").await;
    // Bob gives the restored Alice a new re-key invite, so a second restore works too.
    within(std::time::Duration::from_secs(30), || async {
        alice2.has_rekey(a_bob.id).await.unwrap().then_some(())
    })
    .await;

    // Nothing of the backup is left in the clear on the new device.
    alice2.lock().await.unwrap();
    assert!(
        !tree_contains(dir.path(), MARK.as_bytes()),
        "plaintext at rest after a restore"
    );
    for f in ["backup.vbak", "restore.db", "backup-export.db"] {
        assert!(!dir.path().join(f).exists(), "{f} left behind");
    }
}
