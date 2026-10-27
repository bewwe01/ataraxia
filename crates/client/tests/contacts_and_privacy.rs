//! Milestone 1 end to end through the real relay: blocking, deleting, the key-change warning,
//! disappearing messages, and the opt-in read receipts and typing indicators.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::format_collect,
    clippy::too_many_lines
)]

mod common;

use std::time::Duration;

use common::*;
use veil_client::ClientError;
use veil_client::service::{ChangeKind, PrivacyView};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_unblock_and_delete() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    bob.client.send(b_alice.id, "hello".into()).await.unwrap();
    arrives(&alice.client, a_bob.id, "hello").await;

    // Blocked: the relay refuses Bob's deposits, and Alice cannot send to him.
    alice.client.set_blocked(a_bob.id, true).await.unwrap();
    assert!(alice.client.contacts().await.unwrap()[0].blocked);
    assert_eq!(
        alice.client.send(a_bob.id, "x".into()).await.unwrap_err(),
        ClientError::Blocked
    );
    let m = bob.client.send(b_alice.id, "while blocked".into()).await.unwrap();
    assert_eq!(m.status, "failed");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !texts(&alice.client, a_bob.id)
            .await
            .contains(&"while blocked".to_owned())
    );

    // Unblocked: Bob gets a new token in a mailbox update and can write again.
    alice.client.set_blocked(a_bob.id, false).await.unwrap();
    assert!(!alice.client.contacts().await.unwrap()[0].blocked);
    eventually(|| async {
        let m = bob.client.send(b_alice.id, "after unblock".into()).await.ok()?;
        (m.status == "sent").then_some(())
    })
    .await;
    arrives(&alice.client, a_bob.id, "after unblock").await;
    alice.client.send(a_bob.id, "welcome back".into()).await.unwrap();
    arrives(&bob.client, b_alice.id, "welcome back").await;

    // Deleted: the contact, the conversation and the session are gone, and so is Bob's
    // token at the relay.
    alice.client.delete_contact(a_bob.id).await.unwrap();
    assert!(alice.client.contacts().await.unwrap().is_empty());
    assert_eq!(
        alice.client.messages(a_bob.id).await.unwrap().len(),
        0,
        "messages deleted with the contact"
    );
    let m = bob.client.send(b_alice.id, "after delete".into()).await.unwrap();
    assert_eq!(m.status, "failed");

    // Only a new invite brings them together again, with a new session.
    let (a_bob2, b_alice2) = pair(&alice.client, &bob.client).await;
    assert_eq!(b_alice2.id, b_alice.id, "Bob's side keeps its contact");
    assert!(!a_bob2.key_warning);
    bob.client.send(b_alice.id, "new start".into()).await.unwrap();
    arrives(&alice.client, a_bob2.id, "new start").await;
    assert!(
        !texts(&alice.client, a_bob2.id)
            .await
            .contains(&"after delete".to_owned())
    );
    alice.client.send(a_bob2.id, "hi again".into()).await.unwrap();
    arrives(&bob.client, b_alice.id, "hi again").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lookalike_name_gets_a_key_warning() {
    let r = relay().await;
    let alice = user(&r, "Alice").await;
    let bob = user(&r, "Bob").await;
    // Someone else, using Bob's name (or Bob after a reinstall: a new key either way).
    let imposter = user(&r, " bob ").await;
    let (a_bob, _) = pair(&alice.client, &bob.client).await;
    assert!(!a_bob.key_warning);
    let (a_imp, _) = pair(&alice.client, &imposter.client).await;
    assert!(a_imp.key_warning, "same name, new key: warn");
    assert_ne!(a_imp.id, a_bob.id, "never merged into the existing contact");
    assert!(texts(&alice.client, a_imp.id).await.is_empty());

    // Verifying the safety number does not settle it: the user still decides between
    // accepting (the old conversation moves) and keeping the two apart (dismissing).
    alice.client.set_verified(a_imp.id, true).await.unwrap();
    let c = alice.client.contacts().await.unwrap();
    assert!(c.iter().find(|c| c.id == a_imp.id).unwrap().key_warning);
    let imposter2 = user(&r, "BOB").await;
    let (a_imp2, _) = pair(&alice.client, &imposter2.client).await;
    assert!(a_imp2.key_warning);
    alice.client.dismiss_key_warning(a_imp2.id).await.unwrap();
    let c = alice.client.contacts().await.unwrap();
    assert!(!c.iter().find(|c| c.id == a_imp2.id).unwrap().key_warning);
    assert!(
        !c.iter().find(|c| c.id == a_imp2.id).unwrap().verified,
        "dismissing is not verifying"
    );
}

/// Nothing that was waiting to go to the old key is sent after a merge (P6-7): hidden rows go,
/// unsent messages and uploads stay "not sent", and the new contact never gets them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_merge_sends_nothing_sealed_to_the_old_key() {
    let r = relay().await;
    let hop = Proxy::to(&r.addr).await;
    let alice = user_at(&r, &hop.addr, "Alice", None).await;
    let bob = user(&r, "Bob").await;
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    bob.client.send(b_alice.id, "hello".into()).await.unwrap();
    let hello = arrives_id(&alice.client, a_bob.id, "hello").await;
    let bob2 = user(&r, "Bob").await;
    let (a_bob2, second_phone_alice) = pair(&alice.client, &bob2.client).await;
    // Offline: a text, a reaction and a file to the old Bob wait to go out.
    hop.cut();
    online(&alice.client, false).await;
    let queued = alice
        .client
        .send(a_bob.id, "queued for the old key".into())
        .await
        .unwrap();
    alice.client.react(hello, "👍".into(), true).await.unwrap();
    let file = alice
        .client
        .send_attachment(
            a_bob.id,
            veil_client::service::AttachmentInput {
                kind: "file".into(),
                mime: "application/octet-stream".into(),
                name: Some("old.bin".into()),
                data: zeroize::Zeroizing::new(vec![7u8; 100_000]),
                thumbnail: None,
                duration_ms: None,
                waveform: None,
            },
        )
        .await
        .unwrap();
    assert!(alice.client.hidden_rows(a_bob.id).await.unwrap() > 0);
    alice.client.accept_key_change(a_bob2.id).await.unwrap();
    assert_eq!(
        alice.client.hidden_rows(a_bob2.id).await.unwrap(),
        0,
        "hidden rows dropped"
    );
    hop.restore();
    online(&alice.client, true).await;
    // Something new does arrive, so anything queued would have gone out by now.
    alice
        .client
        .send(a_bob2.id, "after the merge".into())
        .await
        .unwrap();
    arrives(&bob2.client, second_phone_alice.id, "after the merge").await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let got = texts(&bob2.client, second_phone_alice.id).await;
    assert!(!got.contains(&"queued for the old key".to_owned()));
    assert!(
        bob2.client
            .messages(second_phone_alice.id)
            .await
            .unwrap()
            .iter()
            .all(|m| m.attachment.is_none())
    );
    assert!(
        texts(&bob.client, b_alice.id)
            .await
            .iter()
            .all(|t| t != "queued for the old key")
    );
    let mine = alice.client.messages(a_bob2.id).await.unwrap();
    let q = mine.iter().find(|m| m.id == queued.id).unwrap();
    assert_eq!(q.status, "failed", "stays not sent");
    let f = mine.iter().find(|m| m.id == file.id).unwrap();
    assert_eq!(f.attachment.as_ref().unwrap().state, "failed");
}

/// Accepting a key change: the earlier conversation moves to the new contact and the old one
/// is gone, by the user's choice only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepting_a_key_change_moves_the_old_conversation() {
    let r = relay().await;
    let alice = user(&r, "Alice").await;
    let bob = user(&r, "Bob").await;
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    bob.client
        .send(b_alice.id, "before the new phone".into())
        .await
        .unwrap();
    arrives(&alice.client, a_bob.id, "before the new phone").await;
    alice.client.send(a_bob.id, "my answer".into()).await.unwrap();
    assert_eq!(
        alice.client.accept_key_change(a_bob.id).await.unwrap_err(),
        ClientError::BadInput,
        "only after a warning"
    );

    // Someone else calls themselves Bob too; Alice keeps them apart.
    let other = user(&r, "Bob").await;
    let (a_other, other_alice) = pair(&alice.client, &other.client).await;
    other
        .client
        .send(other_alice.id, "not the real one".into())
        .await
        .unwrap();
    arrives(&alice.client, a_other.id, "not the real one").await;
    alice.client.dismiss_key_warning(a_other.id).await.unwrap();

    // Bob's new phone: same name, new key.
    let bob2 = user(&r, "Bob").await;
    let (a_bob2, new_phone_alice) = pair(&alice.client, &bob2.client).await;
    assert!(a_bob2.key_warning);
    // The warning names the contact it is about: the first Bob, not the other one (P6-1).
    let warned = alice
        .client
        .contacts()
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.id == a_bob2.id)
        .unwrap();
    assert_eq!(warned.previous.as_ref().map(|p| p.id), Some(a_bob.id));
    alice.client.accept_key_change(a_bob2.id).await.unwrap();
    let c = alice.client.contacts().await.unwrap();
    let ids: Vec<i64> = c.iter().map(|c| c.id).collect();
    assert!(
        ids.contains(&a_bob2.id) && ids.contains(&a_other.id),
        "only the first Bob merged"
    );
    assert!(!ids.contains(&a_bob.id), "the old contact is gone");
    assert!(!c.iter().find(|c| c.id == a_bob2.id).unwrap().key_warning);
    let t = texts(&alice.client, a_bob2.id).await;
    assert!(t.contains(&"before the new phone".to_owned()) && t.contains(&"my answer".to_owned()));
    assert!(!t.contains(&"not the real one".to_owned()));
    assert_eq!(
        texts(&alice.client, a_other.id).await,
        vec!["not the real one".to_owned()]
    );
    // The conversation goes on with the new key, in the same chat.
    bob2.client
        .send(new_phone_alice.id, "it's me".into())
        .await
        .unwrap();
    arrives(&alice.client, a_bob2.id, "it's me").await;
    alice.client.send(a_bob2.id, "welcome back".into()).await.unwrap();
    arrives(&bob2.client, new_phone_alice.id, "welcome back").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disappearing_messages() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    assert_eq!(
        alice.client.set_timer(a_bob.id, 2_419_201).await.unwrap_err(),
        ClientError::BadInput
    );
    alice.client.set_timer(a_bob.id, 1).await.unwrap();
    // Bob's side follows, with a notice in the conversation.
    eventually(|| async {
        let c = bob.client.contacts().await.unwrap();
        (c[0].timer_secs == 1).then_some(())
    })
    .await;
    let notice = bob.client.messages(b_alice.id).await.unwrap();
    assert!(
        notice
            .iter()
            .any(|m| m.kind == "timer" && m.timer_secs == Some(1))
    );

    let sent = bob.client.send(b_alice.id, "self destruct".into()).await.unwrap();
    assert!(sent.expires_at_ms.is_some());
    // Gone on both sides once the timer runs out (the sweeper runs on the tick).
    eventually(|| async { texts(&bob.client, b_alice.id).await.is_empty().then_some(()) }).await;
    eventually(|| async {
        let got = alice.client.messages(a_bob.id).await.unwrap();
        (!got.iter().any(|m| m.text == "self destruct")).then_some(())
    })
    .await;

    // Off again: messages stay.
    alice.client.set_timer(a_bob.id, 0).await.unwrap();
    eventually(|| async { (bob.client.contacts().await.unwrap()[0].timer_secs == 0).then_some(()) }).await;
    let m = bob.client.send(b_alice.id, "stays".into()).await.unwrap();
    assert!(m.expires_at_ms.is_none());
    arrives(&alice.client, a_bob.id, "stays").await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(texts(&alice.client, a_bob.id).await.contains(&"stays".to_owned()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receipts_and_typing_are_opt_in() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    let p = alice.client.privacy().await.unwrap();
    assert!(!p.read_receipts && !p.typing, "off by default");

    // Off: nothing beyond "sent", and no typing events.
    bob.client.typing(b_alice.id, true).await.unwrap();
    let m = bob.client.send(b_alice.id, "one".into()).await.unwrap();
    arrives(&alice.client, a_bob.id, "one").await;
    alice.client.mark_read(a_bob.id).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let st = bob.client.messages(b_alice.id).await.unwrap();
    assert_eq!(st.iter().find(|x| x.id == m.id).unwrap().status, "sent");
    assert!(
        !alice
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.0 == ChangeKind::Typing)
    );

    // On for both: delivered, then read; typing shows.
    let on = PrivacyView {
        read_receipts: true,
        typing: true,
    };
    alice.client.set_privacy(on).await.unwrap();
    bob.client.set_privacy(on).await.unwrap();
    bob.client.typing(b_alice.id, true).await.unwrap();
    eventually(|| async {
        alice
            .events
            .lock()
            .unwrap()
            .contains(&(ChangeKind::Typing, Some(a_bob.id)))
            .then_some(())
    })
    .await;
    let m = bob.client.send(b_alice.id, "two".into()).await.unwrap();
    arrives(&alice.client, a_bob.id, "two").await;
    let status = |want: &'static str| {
        let bob = bob.client.clone();
        let (cid, mid) = (b_alice.id, m.id);
        async move {
            eventually(|| async {
                let s = bob.messages(cid).await.unwrap();
                (s.iter().find(|x| x.id == mid).unwrap().status == want).then_some(())
            })
            .await;
        }
    };
    status("delivered").await;
    alice.client.mark_read(a_bob.id).await.unwrap();
    status("read").await;
    // "one" arrived and was read while Alice had receipts off: turning them on later does not
    // report it (review M1-4).
    let st = bob.client.messages(b_alice.id).await.unwrap();
    assert_eq!(st.iter().find(|x| x.text == "one").unwrap().status, "sent");

    // Alice turns receipts off again: Bob's next message stays at "sent".
    alice
        .client
        .set_privacy(PrivacyView {
            read_receipts: false,
            typing: false,
        })
        .await
        .unwrap();
    let m3 = bob.client.send(b_alice.id, "three".into()).await.unwrap();
    arrives(&alice.client, a_bob.id, "three").await;
    alice.client.mark_read(a_bob.id).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let st = bob.client.messages(b_alice.id).await.unwrap();
    assert_eq!(st.iter().find(|x| x.id == m3.id).unwrap().status, "sent");
}

/// Blocking while offline: queued messages to them are never sent, and their token is
/// withdrawn once the relay is back (INV-CONT-1, review M1-2, M1-8).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_while_offline() {
    let r = relay().await;
    let hop = Proxy::to(&r.addr).await;
    let alice = user_at(&r, &hop.addr, "Alice", None).await;
    let bob = user(&r, "Bob").await;
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    bob.client.send(b_alice.id, "hi".into()).await.unwrap();
    arrives(&alice.client, a_bob.id, "hi").await;

    hop.cut();
    online(&alice.client, false).await;
    let m = alice
        .client
        .send(a_bob.id, "queued before the block".into())
        .await
        .unwrap();
    assert_eq!(m.status, "failed");
    alice.client.set_blocked(a_bob.id, true).await.unwrap();
    // The relay has not heard of the block yet.
    let m = bob
        .client
        .send(b_alice.id, "still accepted".into())
        .await
        .unwrap();
    assert_eq!(m.status, "sent");

    hop.restore();
    online(&alice.client, true).await;
    within(Duration::from_secs(20), || async {
        let m = bob.client.send(b_alice.id, "refused?".into()).await.unwrap();
        (m.status == "failed").then_some(())
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !texts(&bob.client, b_alice.id)
            .await
            .contains(&"queued before the block".to_owned())
    );
    let mine = alice.client.messages(a_bob.id).await.unwrap();
    assert!(
        !mine
            .iter()
            .any(|m| m.text == "still accepted" || m.text == "refused?")
    );
}

/// An unsent message whose timer runs out is deleted unsent, from the database (the list
/// does not filter expired rows, so this sees the sweeper) (INV-REST-9, review M1-8).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_unsent_message_is_never_sent() {
    let r = relay().await;
    let hop = Proxy::to(&r.addr).await;
    let alice = user_at(&r, &hop.addr, "Alice", None).await;
    let bob = user(&r, "Bob").await;
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    alice.client.set_timer(a_bob.id, 1).await.unwrap();
    eventually(|| async { (bob.client.contacts().await.unwrap()[0].timer_secs == 1).then_some(()) }).await;

    hop.cut();
    online(&alice.client, false).await;
    let m = alice.client.send(a_bob.id, "too late".into()).await.unwrap();
    assert_eq!(m.status, "failed");
    eventually(|| async { texts(&alice.client, a_bob.id).await.is_empty().then_some(()) }).await;
    hop.restore();
    online(&alice.client, true).await;
    alice.client.set_timer(a_bob.id, 0).await.unwrap();
    alice.client.send(a_bob.id, "on time".into()).await.unwrap();
    arrives(&bob.client, b_alice.id, "on time").await;
    assert!(
        !texts(&bob.client, b_alice.id)
            .await
            .contains(&"too late".to_owned())
    );
}

/// Expired invites give their tokens back: with room for one batch of 8 tokens, a ninth
/// invite only fits once the first eight have expired and been withdrawn (review M1-8).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_invites_release_their_tokens() {
    let r = relay_with(|c| {
        c.quotas.max_tokens_per_mailbox = 8;
        c.quotas.token_floor_per_mailbox = 8;
    })
    .await;
    let alice = user_at(&r, &r.addr, "Alice", Some(Duration::from_secs(4))).await;
    for _ in 0..8 {
        alice.client.create_invite().await.unwrap();
    }
    assert!(alice.client.create_invite().await.is_err(), "no token left");
    // Each failed try costs one of the relay's token updates (1 per second), so try slowly
    // and leave room for the withdrawal itself.
    for _ in 0..12 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if alice.client.create_invite().await.is_ok() {
            return;
        }
    }
    panic!("expired invites never gave their tokens back");
}

/// An unblock update that waited while offline must not reach them after a newer one: it
/// names a token that was withdrawn since (review M1R2-1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_unblock_update_is_never_delivered() {
    let r = relay().await;
    let hop = Proxy::to(&r.addr).await;
    let alice = user_at(&r, &hop.addr, "Alice", None).await;
    let bob = user(&r, "Bob").await;
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    alice.client.set_blocked(a_bob.id, true).await.unwrap();

    // Offline: unblock (token from the local spare pool, update queued), then block again.
    hop.cut();
    online(&alice.client, false).await;
    alice.client.set_blocked(a_bob.id, false).await.unwrap();
    let c = alice.client.contacts().await.unwrap();
    assert!(c[0].unblock_pending, "the update is still waiting");
    alice.client.set_blocked(a_bob.id, true).await.unwrap();

    // Online: unblock for real, then reconnect so anything pending is retried.
    hop.restore();
    online(&alice.client, true).await;
    alice.client.set_blocked(a_bob.id, false).await.unwrap();
    hop.cut();
    online(&alice.client, false).await;
    hop.restore();
    online(&alice.client, true).await;
    assert!(!alice.client.contacts().await.unwrap()[0].unblock_pending);

    tokio::time::sleep(Duration::from_secs(1)).await;
    within(Duration::from_secs(20), || async {
        let m = bob.client.send(b_alice.id, "can you hear me".into()).await.ok()?;
        (m.status == "sent").then_some(())
    })
    .await;
    arrives(&alice.client, a_bob.id, "can you hear me").await;
}
