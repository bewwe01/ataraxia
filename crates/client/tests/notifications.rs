//! Milestone 4: the client tells the app shell when something new arrives, never what or (while
//! locked) from whom; a locked Veil hears the relay's notices only with notifications on.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::time::Duration;

use common::*;
use veil_client::service::{ChangeKind, NotifyView, PrivacyView, SetupInput};
use veil_client::unlock::SecretKind;
use zeroize::Zeroizing;

fn incoming(u: &User) -> Vec<Option<i64>> {
    u.events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.0 == ChangeKind::Incoming)
        .map(|e| e.1)
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unlocked_incoming_names_the_conversation_only() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    assert!(
        alice.client.notify_settings().await.unwrap().enabled,
        "on by default"
    );
    let on = PrivacyView {
        read_receipts: true,
        typing: true,
    };
    alice.client.set_privacy(on).await.unwrap();
    bob.client.set_privacy(on).await.unwrap();
    // Typing is not something to notify about.
    bob.client.typing(b_alice.id, true).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(incoming(&alice).is_empty());
    bob.client.send(b_alice.id, "hello".into()).await.unwrap();
    eventually(|| async { (incoming(&alice) == vec![Some(a_bob.id)]).then_some(()) }).await;
    // Our own sends are not incoming.
    alice.client.send(a_bob.id, "hi".into()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(incoming(&alice), vec![Some(a_bob.id)]);
}

/// Locked: a notice without a contact, from the relay's push alone (ADR-0016).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn locked_veil_hears_that_something_arrived() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (_, b_alice) = pair(&alice.client, &bob.client).await;
    alice.client.lock().await.unwrap();
    within(Duration::from_secs(30), || async {
        // Keep sending until the locked side has connected and heard one.
        bob.client
            .send(b_alice.id, "are you there?".into())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        incoming(&alice).contains(&None).then_some(())
    })
    .await;
    // At most one notice a minute, whatever arrives.
    let n = incoming(&alice).len();
    for _ in 0..3 {
        bob.client.send(b_alice.id, "more".into()).await.unwrap();
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(incoming(&alice).len(), n);
    // Unlocking works as usual, and the messages are all there.
    alice
        .client
        .unlock(Zeroizing::new("correct horse battery".into()))
        .await
        .unwrap();
    let a_bob = alice.client.contacts().await.unwrap()[0].id;
    eventually(|| async {
        texts(&alice.client, a_bob)
            .await
            .contains(&"more".to_owned())
            .then_some(())
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn notifications_off_means_nothing_while_locked() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (_, b_alice) = pair(&alice.client, &bob.client).await;
    alice
        .client
        .set_notify(NotifyView { enabled: false })
        .await
        .unwrap();
    alice.client.lock().await.unwrap();
    for _ in 0..8 {
        bob.client.send(b_alice.id, "anyone?".into()).await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(incoming(&alice).is_empty());
}

/// The locked-state watcher, and the mailbox key it holds, exists only while locked with
/// notifications on: unlock, reset and the Purge PIN all drop it (INV-REST-4, review M4-4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_locked_state_key_goes_on_every_path() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (_, b_alice) = pair(&alice.client, &bob.client).await;
    let c = &alice.client;
    let pass = || Zeroizing::new("correct horse battery".to_owned());
    assert!(!c.watcher_live().await.unwrap(), "never while unlocked");

    // Unlock drops it; no "may have" notice comes after, whatever arrives.
    c.lock().await.unwrap();
    assert!(c.watcher_live().await.unwrap());
    c.unlock(pass()).await.unwrap();
    assert!(!c.watcher_live().await.unwrap());
    let before = incoming(&alice).iter().filter(|e| e.is_none()).count();
    for _ in 0..3 {
        bob.client.send(b_alice.id, "after unlock".into()).await.unwrap();
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(incoming(&alice).iter().filter(|e| e.is_none()).count(), before);

    // Notifications off: nothing is kept when locking.
    c.set_notify(NotifyView { enabled: false }).await.unwrap();
    c.lock().await.unwrap();
    assert!(!c.watcher_live().await.unwrap());
    c.unlock(pass()).await.unwrap();
    c.set_notify(NotifyView { enabled: true }).await.unwrap();

    // The Purge PIN drops it (a PIN user: the Purge PIN goes with PIN unlock).
    let dir = tempfile::tempdir().unwrap();
    let dave = start(dir.path(), Events::default());
    dave.setup(SetupInput {
        relay: r.addr.clone(),
        pin: r.pin.clone(),
        name: "Dave".into(),
        kind: SecretKind::Pin,
        passphrase: Zeroizing::new("482913".into()),
    })
    .await
    .unwrap();
    dave.set_purge(Zeroizing::new("482913".into()), Zeroizing::new("999999".into()))
        .await
        .unwrap();
    dave.lock().await.unwrap();
    assert!(dave.watcher_live().await.unwrap());
    dave.unlock(Zeroizing::new("999999".into())).await.unwrap();
    assert!(!dave.watcher_live().await.unwrap());

    // So does starting over.
    let carol = user(&r, "Carol").await;
    carol.client.lock().await.unwrap();
    assert!(carol.client.watcher_live().await.unwrap());
    carol.client.reset().await.unwrap();
    assert!(!carol.client.watcher_live().await.unwrap());
}
