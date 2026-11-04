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

/// Our invites (each with its own prekeys) in a client's store.
const INVITES: &str = "SELECT count(*) FROM kv WHERE substr(k, 1, 4) = x'696e762f'";

/// A number about one contact.
async fn of(c: &veil_client::service::Client, contact: i64, column: &str) -> i64 {
    c.test_query(&format!("SELECT {column} FROM contacts WHERE id = {contact}"))
        .await
        .unwrap()
}

/// Makes a backup and returns (file, code); the code is marked as seen.
async fn backup(c: &veil_client::service::Client) -> (Zeroizing<Vec<u8>>, String) {
    let view = c.create_backup().await.unwrap();
    let file = c.take_backup().await.unwrap();
    c.backup_code_seen().await.unwrap();
    let code = c
        .backup_code(Zeroizing::new("correct horse battery".into()))
        .await
        .unwrap()
        .unwrap();
    if let Some(shown) = view.code {
        assert_eq!(shown, code);
    }
    (file, code)
}

/// What a backup holds, decrypted as a restore does it: the exported database.
fn open_backup(file: &[u8], code: &str, dir: &std::path::Path) -> veil_client::db::Db {
    let code = veil_core::backup::BackupCode::parse(code).unwrap();
    let mut plain = Vec::new();
    veil_core::backup::open(&code, file, |c| {
        plain.extend_from_slice(c);
        Ok(())
    })
    .unwrap();
    let key: [u8; 32] = plain[..32].try_into().unwrap();
    let path = dir.join("inspect.db");
    std::fs::write(&path, &plain[32..]).unwrap();
    veil_client::db::Db::open(&path, &key).unwrap()
}

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
    // A Purge PIN is set on the old phone (review BK-3).
    a.set_purge(
        Zeroizing::new("correct horse battery".into()),
        Zeroizing::new("a purge password".into()),
    )
    .await
    .unwrap();
    assert!(a.security().await.unwrap().purge_set);

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
    // Until the user says they saw it, every backup shows the code (review BK-7)...
    assert_eq!(
        a.create_backup().await.unwrap().code.as_deref(),
        Some(code.as_str())
    );
    let _ = a.take_backup().await.unwrap();
    a.backup_code_seen().await.unwrap();
    // ...and after, none does.
    assert!(a.create_backup().await.unwrap().code.is_none());
    let _ = a.take_backup().await.unwrap();

    // What the backup holds (review BK-10, INV-BAK-1): no ratchet sessions, prekeys or
    // invites, no envelopes sealed under them, no free pages with deleted rows, and no
    // Purge PIN flag.
    let inspect = tempfile::tempdir().unwrap();
    {
        let db = open_backup(&file, &code, inspect.path());
        let n = |q: &str| -> i64 { db.conn().query_row(q, [], |r| r.get(0)).unwrap() };
        for prefix in veil_core::backup::NOT_BACKED_UP {
            let hex = prefix.iter().fold(String::new(), |mut h, b| {
                use std::fmt::Write as _;
                let _ = write!(h, "{b:02x}");
                h
            });
            assert_eq!(
                n(&format!(
                    "SELECT count(*) FROM kv WHERE substr(k, 1, {}) = x'{hex}'",
                    prefix.len()
                )),
                0,
                "{} in the backup",
                String::from_utf8_lossy(prefix)
            );
        }
        assert!(n("SELECT count(*) FROM kv") > 0, "the identity is in it");
        assert_eq!(n("SELECT count(*) FROM invites"), 0);
        assert_eq!(n("SELECT count(*) FROM messages WHERE envelope IS NOT NULL"), 0);
        assert_eq!(n("SELECT count(*) FROM contacts WHERE intro IS NOT NULL"), 0);
        assert_eq!(n("PRAGMA freelist_count"), 0);
        assert_eq!(
            n("SELECT count(*) FROM settings WHERE k = 'purge_set' AND v = x'01'"),
            0
        );
        assert!(
            texts_in(&db).iter().any(|t| t.contains(MARK)),
            "the history is in it"
        );
    }
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

    // The Purge PIN is not restored, and nothing says it is (review BK-3).
    assert!(!alice2.security().await.unwrap().purge_set);
    // Same contacts and history; Carol needs a new invite.
    let contacts = alice2.contacts().await.unwrap();
    let bob_here = contacts.iter().find(|c| c.id == a_bob.id).unwrap();
    assert!(!bob_here.needs_invite);
    assert!(contacts.iter().find(|c| c.id == a_carol.id).unwrap().needs_invite);
    // Her chat says so (the line's text reaches the UI).
    assert!(
        alice2
            .messages(a_carol.id)
            .await
            .unwrap()
            .iter()
            .any(|m| m.kind == "restored" && m.mine && m.text == "needs-invite")
    );
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
    assert_eq!(of(&alice2, a_bob.id, "rekey_pending_ms").await, 0, "Bob answered");
    // Carol, who has no session with the restored Alice, is not given a re-key invite every
    // tick: the invite count stays put (review BK-2).
    let invites = alice2.test_query(INVITES).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(12)).await;
    assert_eq!(alice2.test_query(INVITES).await.unwrap(), invites);

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

/// The text bodies in a database opened outside the client.
fn texts_in(db: &veil_client::db::Db) -> Vec<String> {
    let mut st = db
        .conn()
        .prepare("SELECT body FROM messages WHERE kind = 'text'")
        .unwrap();
    st.query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// Review BK-1: a known contact cannot fake a restore over the session they have. Neither an
/// introduction without an invite nor one claiming one of our invites marks our outbox as
/// failed, swaps their mailbox or token, or adds a "restored" line.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_contact_cannot_fake_a_restore() {
    use veil_core::content::{Body, ContactIntro};
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    let (a, b) = (&alice.client, &bob.client);
    a.send(a_bob.id, "first".into()).await.unwrap();
    arrives(b, b_alice.id, "first").await;
    let fake = |invite: bool| {
        Body::ContactIntro(ContactIntro {
            mailbox_id: vec![7; 32],
            delivery_token: vec![8; 32],
            display_name: Some("Bob".into()),
            invite_id: invite.then(|| vec![0xEE; 16]),
            invite_proof: invite.then(|| vec![0; 32]),
            rekey: None,
        })
    };
    b.raw_send(b_alice.id, vec![1; 16], fake(false)).await.unwrap();
    b.raw_send(b_alice.id, vec![2; 16], fake(true)).await.unwrap();
    b.send(b_alice.id, "after".into()).await.unwrap();
    arrives(a, a_bob.id, "after").await;
    let msgs = a.messages(a_bob.id).await.unwrap();
    assert!(!msgs.iter().any(|m| m.kind == "restored"), "a faked restore line");
    assert!(
        msgs.iter().filter(|m| m.mine).all(|m| m.status != "failed"),
        "our outbox was marked failed"
    );
    // Bob's mailbox and token are what they were: Alice still reaches him.
    a.send(a_bob.id, "still here".into()).await.unwrap();
    arrives(b, b_alice.id, "still here").await;
}

/// Reviews BK-4 and BK-5: only a newer re-key invite replaces the one held; a restore that
/// redeems a stale one (the contact renewed it after the backup) is not taken as a success
/// for ever: after a week with no answer the contact is marked as needing an invite.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_rekey_invite_ends_as_needs_invite() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    let (a, b) = (&alice.client, &bob.client);
    within(std::time::Duration::from_secs(30), || async {
        a.has_rekey(a_bob.id).await.unwrap().then_some(())
    })
    .await;
    let (file, code) = backup(a).await;

    // Bob renews his invite after the backup: the newer one replaces the older (BK-4).
    let first = of(a, a_bob.id, "rekey_until").await;
    let renew = || async {
        let before = of(b, b_alice.id, "rekey_mine_id IS NULL").await;
        assert_eq!(before, 0);
        b.test_exec(&format!(
            "UPDATE contacts SET rekey_mine_until = 0 WHERE id = {}",
            b_alice.id
        ))
        .await
        .unwrap();
        within(std::time::Duration::from_secs(30), || async {
            (of(b, b_alice.id, "rekey_mine_until").await > 0).then_some(())
        })
        .await;
    };
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    renew().await;
    let second = within(std::time::Duration::from_secs(30), || async {
        let v = of(a, a_bob.id, "rekey_until").await;
        (v > first).then_some(v)
    })
    .await;
    // An older one does not replace a newer one: pretend Alice holds one from the far future,
    // then let Bob renew again; what arrives after it is read, and the far one is kept.
    let far = second + 10_000_000;
    a.test_exec(&format!(
        "UPDATE contacts SET rekey_until = {far} WHERE id = {}",
        a_bob.id
    ))
    .await
    .unwrap();
    renew().await;
    b.send(b_alice.id, "after the renewal".into()).await.unwrap();
    arrives(a, a_bob.id, "after the renewal").await;
    assert_eq!(of(a, a_bob.id, "rekey_until").await, far);

    // Alice restores the backup, which holds Bob's first, revoked invite.
    drop(alice);
    let dir = tempfile::tempdir().unwrap();
    let alice2 = start(dir.path(), std::sync::Arc::default());
    let view = alice2.restore(input(&file, &code)).await.unwrap();
    assert_eq!((view.contacts, view.need_invite), (1, 0));
    assert!(of(&alice2, a_bob.id, "rekey_pending_ms").await > 0);
    // Bob cannot read it: no restore line on his side.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    assert!(
        !b.messages(b_alice.id)
            .await
            .unwrap()
            .iter()
            .any(|m| m.kind == "restored")
    );
    // A week goes by without an answer.
    alice2
        .test_exec("UPDATE contacts SET rekey_pending_ms = rekey_pending_ms - 8 * 86400000 WHERE rekey_pending_ms > 0")
        .await
        .unwrap();
    within(std::time::Duration::from_secs(30), || async {
        alice2
            .contacts()
            .await
            .unwrap()
            .iter()
            .any(|c| c.id == a_bob.id && c.needs_invite)
            .then_some(())
    })
    .await;
    let lines: Vec<(bool, String)> = alice2
        .messages(a_bob.id)
        .await
        .unwrap()
        .into_iter()
        .filter(|m| m.kind == "restored")
        .map(|m| (m.mine, m.text))
        .collect();
    assert!(lines.contains(&(true, "no-reply".into())), "{lines:?}");
}

/// Review BK-9: after a restore that could not reach Carol, she sends a new ordinary invite;
/// the restored Alice redeems it. Carol takes it as the same contact, and the token Alice now
/// delivers with stays valid after that invite expires.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_invite_after_a_restore_outlives_its_ttl() {
    let r = relay().await;
    let alice = user(&r, "Alice").await;
    let carol = user_at(&r, &r.addr, "Carol", Some(std::time::Duration::from_secs(6))).await;
    let (a_carol, c_alice) = pair(&alice.client, &carol.client).await;
    let (a, c) = (&alice.client, &carol.client);
    a.send(a_carol.id, "hello Carol".into()).await.unwrap();
    arrives(c, c_alice.id, "hello Carol").await;
    // Carol's re-key invite never reached Alice.
    a.test_exec(&format!(
        "UPDATE contacts SET rekey_link = NULL, rekey_sealed = NULL WHERE id = {}",
        a_carol.id
    ))
    .await
    .unwrap();
    let (file, code) = backup(a).await;
    drop(alice);
    let dir = tempfile::tempdir().unwrap();
    let alice2 = start(dir.path(), std::sync::Arc::default());
    let view = alice2.restore(input(&file, &code)).await.unwrap();
    assert_eq!(view.need_invite, 1);

    let inv = c.create_invite().await.unwrap();
    let back = alice2.accept_invite(inv.link).await.unwrap();
    assert_eq!(back.id, a_carol.id, "the same contact");
    assert!(!back.needs_invite);
    eventually(|| async {
        c.messages(c_alice.id)
            .await
            .unwrap()
            .iter()
            .any(|m| m.kind == "restored")
            .then_some(())
    })
    .await;
    // The invite is used up at once, and its token is now Carol's token for Alice.
    assert_eq!(c.test_query("SELECT count(*) FROM invites").await.unwrap(), 0);
    alice2.send(a_carol.id, "back again".into()).await.unwrap();
    arrives(c, c_alice.id, "back again").await;
    // Past the invite's lifetime, and the clean-up after it.
    tokio::time::sleep(std::time::Duration::from_secs(12)).await;
    assert_eq!(
        c.test_query("SELECT count(*) FROM token_removals").await.unwrap(),
        0
    );
    alice2.send(a_carol.id, "a week later".into()).await.unwrap();
    arrives(c, c_alice.id, "a week later").await;
}
