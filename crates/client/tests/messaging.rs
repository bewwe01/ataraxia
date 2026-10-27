//! Milestone 2 end to end through the real relay: replies, reactions, edits, deletes, local
//! search and verifying a contact by scanning their safety code.
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
use veil_client::service::{Client, MessageView};
use veil_core::content::{Body, Delete, Edit, Reaction, Text};

async fn find(c: &Client, contact: i64, text: &str) -> MessageView {
    eventually(|| async {
        c.messages(contact)
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.text == text)
    })
    .await
}

async fn by_id(c: &Client, contact: i64, id: i64) -> Option<MessageView> {
    c.messages(contact)
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.id == id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replies_reactions_edits_and_deletes() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;

    // Bob asks, Alice answers with a quote.
    let q = bob
        .client
        .send(b_alice.id, "where do we meet?".into())
        .await
        .unwrap();
    assert!(q.actionable);
    let q_at_alice = find(&alice.client, a_bob.id, "where do we meet?").await;
    let ans = alice
        .client
        .reply(a_bob.id, "at the station".into(), q_at_alice.id)
        .await
        .unwrap();
    let reply = ans.reply.as_ref().unwrap();
    assert_eq!(
        (reply.id, reply.mine, reply.text.as_str()),
        (Some(q_at_alice.id), Some(false), "where do we meet?")
    );
    let ans_at_bob = find(&bob.client, b_alice.id, "at the station").await;
    let reply = ans_at_bob.reply.unwrap();
    assert_eq!(
        (reply.id, reply.mine, reply.text.as_str()),
        (Some(q.id), Some(true), "where do we meet?")
    );
    // A quote must be in the same conversation.
    let carol = user(&r, "Carol").await;
    let (a_carol, _) = pair(&alice.client, &carol.client).await;
    assert_eq!(
        alice
            .client
            .reply(a_carol.id, "x".into(), q_at_alice.id)
            .await
            .unwrap_err(),
        ClientError::BadInput
    );

    // Reactions: up to three different ones each, added and removed one by one, on either
    // side's messages.
    let theirs = |m: &MessageView| {
        let mut v: Vec<String> = m
            .reactions
            .iter()
            .filter(|x| !x.mine)
            .map(|x| x.emoji.clone())
            .collect();
        v.sort();
        v
    };
    let react = |e: &str, on: bool| alice.client.react(q_at_alice.id, e.into(), on);
    react("👍", true).await.unwrap();
    bob.client.react(q.id, "❤️".into(), true).await.unwrap();
    react("😂", true).await.unwrap();
    react("🎉", true).await.unwrap();
    react("👍", true).await.unwrap(); // already there: nothing happens
    assert_eq!(
        react("🔥", true).await.unwrap_err(),
        ClientError::TooManyReactions
    );
    eventually(|| async {
        let m = by_id(&bob.client, b_alice.id, q.id).await?;
        (theirs(&m) == ["🎉", "👍", "😂"] && m.reactions.iter().any(|x| x.mine && x.emoji == "❤️"))
            .then_some(())
    })
    .await;
    react("👍", false).await.unwrap();
    eventually(|| async {
        let m = by_id(&bob.client, b_alice.id, q.id).await?;
        (theirs(&m) == ["🎉", "😂"]).then_some(())
    })
    .await;
    assert_eq!(
        react("not an emoji at all", true).await.unwrap_err(),
        ClientError::BadInput
    );
    // An older Veil (one reaction each): a new reaction is added, the newest three are kept,
    // and its removal (a placeholder emoji) clears all of its reactions.
    let target = alice.client.msg_id(q_at_alice.id).await.unwrap();
    let old = |emoji: &str, remove: bool| {
        Body::Reaction(Reaction {
            target_id: target.clone(),
            emoji: emoji.into(),
            remove,
        })
    };
    for (n, e) in ["🍕", "🍔", "🌮", "🍜"].iter().enumerate() {
        bob.client
            .raw_send(
                b_alice.id,
                vec![200 + u8::try_from(n).unwrap(); 16],
                old(e, false),
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    eventually(|| async {
        let m = by_id(&alice.client, a_bob.id, q_at_alice.id).await?;
        (theirs(&m) == ["🌮", "🍔", "🍜"]).then_some(())
    })
    .await;
    bob.client
        .raw_send(b_alice.id, vec![210; 16], old("x", true))
        .await
        .unwrap();
    eventually(|| async {
        let m = by_id(&alice.client, a_bob.id, q_at_alice.id).await?;
        theirs(&m).is_empty().then_some(())
    })
    .await;

    // Edit: only one's own messages, shown as edited on both sides.
    bob.client
        .edit_message(q.id, "where do we meet tomorrow?".into())
        .await
        .unwrap();
    let edited = find(&alice.client, a_bob.id, "where do we meet tomorrow?").await;
    assert!(edited.edited);
    assert_eq!(
        alice
            .client
            .edit_message(q_at_alice.id, "hijack".into())
            .await
            .unwrap_err(),
        ClientError::TooLate
    );

    // Delete for everyone: the text is gone on both sides, the quote too.
    bob.client.delete_for_everyone(q.id).await.unwrap();
    eventually(|| async {
        let m = by_id(&alice.client, a_bob.id, q_at_alice.id).await?;
        (m.deleted && m.text.is_empty() && m.reactions.is_empty()).then_some(())
    })
    .await;
    let ans_now = by_id(&alice.client, a_bob.id, ans.id).await.unwrap();
    assert_eq!(
        ans_now.reply.unwrap().text,
        "",
        "quote of a deleted message shows nothing"
    );
    assert!(
        !by_id(&alice.client, a_bob.id, q_at_alice.id)
            .await
            .unwrap()
            .actionable
    );
    assert_eq!(
        alice.client.delete_for_everyone(q_at_alice.id).await.unwrap_err(),
        ClientError::TooLate
    );

    // Delete for me: gone here, still there.
    alice.client.delete_for_me(ans.id).await.unwrap();
    assert!(by_id(&alice.client, a_bob.id, ans.id).await.is_none());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(by_id(&bob.client, b_alice.id, ans_at_bob.id).await.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_search() {
    let r = relay().await;
    let (alice, bob, carol) = (
        user(&r, "Alice").await,
        user(&r, "Bob").await,
        user(&r, "Carol").await,
    );
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    let (a_carol, c_alice) = pair(&alice.client, &carol.client).await;
    bob.client
        .send(b_alice.id, "The Eagle lands at midnight".into())
        .await
        .unwrap();
    carol
        .client
        .send(c_alice.id, "no eagles here, 100% sure".into())
        .await
        .unwrap();
    alice
        .client
        .send(a_bob.id, "an_underscore and more".into())
        .await
        .unwrap();
    find(&alice.client, a_bob.id, "The Eagle lands at midnight").await;
    find(&alice.client, a_carol.id, "no eagles here, 100% sure").await;

    let hits = alice.client.search("eagle".into()).await.unwrap();
    assert_eq!(hits.len(), 2);
    assert!(
        hits.iter()
            .any(|h| h.contact == a_bob.id && h.contact_name == "Bob" && h.snippet.contains("Eagle"))
    );
    // LIKE wildcards are literal.
    let pct = alice.client.search("0%".into()).await.unwrap();
    assert_eq!(pct.len(), 1);
    assert_eq!(
        alice.client.search("e_g".into()).await.unwrap().len(),
        0,
        "_ is not a wildcard"
    );
    assert_eq!(alice.client.search("n_und".into()).await.unwrap().len(), 1);
    // Too short: nothing.
    assert!(alice.client.search("e".into()).await.unwrap().is_empty());
    // Deleted for everyone: not found.
    let m = find(&alice.client, a_bob.id, "an_underscore and more").await;
    alice.client.delete_for_everyone(m.id).await.unwrap();
    assert!(alice.client.search("underscore".into()).await.unwrap().is_empty());
    // Long messages give a short excerpt around the match.
    let long = format!("{} needle {}", "x".repeat(300), "y".repeat(300));
    bob.client.send(b_alice.id, long.clone()).await.unwrap();
    find(&alice.client, a_bob.id, &long).await;
    let hit = &alice.client.search("needle".into()).await.unwrap()[0];
    assert!(hit.snippet.contains("needle") && hit.snippet.chars().count() <= 122);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verify_by_scanning_their_code() {
    let r = relay().await;
    let (alice, bob, carol) = (
        user(&r, "Alice").await,
        user(&r, "Bob").await,
        user(&r, "Carol").await,
    );
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    let (_, c_alice) = pair(&alice.client, &carol.client).await;
    let bobs_code = bob.client.safety(b_alice.id).await.unwrap();
    assert_eq!(bobs_code.qr_modules.len(), bobs_code.qr_size * bobs_code.qr_size);
    let carols_code = carol.client.safety(c_alice.id).await.unwrap().code;

    // Someone else's code never verifies Bob.
    assert!(!alice.client.verify_scanned(a_bob.id, carols_code).await.unwrap());
    assert!(!alice.client.contacts().await.unwrap().iter().any(|c| c.verified));
    assert_eq!(
        alice
            .client
            .verify_scanned(a_bob.id, "veil://invite/abc".into())
            .await
            .unwrap_err(),
        ClientError::NotAVerifyCode
    );
    let mut flipped = bobs_code.code.clone().into_bytes();
    let last = flipped.len() - 1;
    flipped[last] = if flipped[last] == b'0' { b'1' } else { b'0' };
    assert!(
        !alice
            .client
            .verify_scanned(a_bob.id, String::from_utf8(flipped).unwrap())
            .await
            .unwrap()
    );

    // Bob's own code does.
    assert!(
        alice
            .client
            .verify_scanned(a_bob.id, bobs_code.code)
            .await
            .unwrap()
    );
    let c = alice.client.contacts().await.unwrap();
    assert!(c.iter().find(|c| c.id == a_bob.id).unwrap().verified);
}

fn text(body: &str, reply_to: Option<Vec<u8>>) -> Body {
    Body::Text(Text {
        body: body.into(),
        reply_to,
        expire_timer_secs: None,
    })
}

/// A hostile contact sends crafted content: edits, deletes and reactions naming messages that
/// are not theirs, and repeated message ids (INV-MSG-8, review M2-2, M2-9).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crafted_content_from_a_contact_stays_in_its_lane() {
    let r = relay().await;
    let (alice, mallory, carol) = (
        user(&r, "Alice").await,
        user(&r, "Mallory").await,
        user(&r, "Carol").await,
    );
    let (a_mal, m_alice) = pair(&alice.client, &mallory.client).await;
    let (a_carol, c_alice) = pair(&alice.client, &carol.client).await;
    // Alice's own message to Mallory, and Carol's message to Alice.
    let mine = alice.client.send(a_mal.id, "my words".into()).await.unwrap();
    let my_id = alice.client.msg_id(mine.id).await.unwrap();
    carol
        .client
        .send(c_alice.id, "carol's words".into())
        .await
        .unwrap();
    let carols = find(&alice.client, a_carol.id, "carol's words").await;
    let carol_id = alice.client.msg_id(carols.id).await.unwrap();

    let id = |n: u8| vec![n; 16];
    for (i, body) in [
        Body::Edit(Edit {
            target_id: my_id.clone(),
            body: "hacked".into(),
        }),
        Body::Delete(Delete {
            target_id: my_id.clone(),
        }),
        Body::Edit(Edit {
            target_id: carol_id.clone(),
            body: "hacked".into(),
        }),
        Body::Delete(Delete {
            target_id: carol_id.clone(),
        }),
        Body::Reaction(Reaction {
            target_id: carol_id.clone(),
            emoji: "💩".into(),
            remove: false,
        }),
    ]
    .into_iter()
    .enumerate()
    {
        mallory
            .client
            .raw_send(m_alice.id, id(u8::try_from(i).unwrap()), body)
            .await
            .unwrap();
    }
    // The same id three times, then replies quoting it.
    for _ in 0..3 {
        mallory
            .client
            .raw_send(m_alice.id, id(42), text("same id", None))
            .await
            .unwrap();
    }
    for n in 0..3 {
        mallory
            .client
            .raw_send(m_alice.id, id(50 + n), text("quoting", Some(id(42))))
            .await
            .unwrap();
    }
    // A repeated id with a new body edits their own text (a lost-reply re-send), never ours.
    mallory
        .client
        .raw_send(m_alice.id, id(42), text("same id, edited", None))
        .await
        .unwrap();
    mallory
        .client
        .raw_send(m_alice.id, my_id.clone(), text("hacked via repeat", None))
        .await
        .unwrap();
    mallory
        .client
        .raw_send(m_alice.id, id(99), text("done", None))
        .await
        .unwrap();
    find(&alice.client, a_mal.id, "done").await;

    let with_mal = alice.client.messages(a_mal.id).await.unwrap();
    let m = with_mal.iter().find(|m| m.id == mine.id).unwrap();
    assert_eq!((m.text.as_str(), m.edited, m.deleted), ("my words", false, false));
    let with_carol = alice.client.messages(a_carol.id).await.unwrap();
    let c = with_carol.iter().find(|m| m.id == carols.id).unwrap();
    assert_eq!(
        (c.text.as_str(), c.edited, c.deleted),
        ("carol's words", false, false)
    );
    assert!(c.reactions.is_empty());
    assert_eq!(
        with_mal.iter().filter(|m| m.text.starts_with("same id")).count(),
        1
    );
    assert!(with_mal.iter().any(|m| m.text == "same id, edited" && m.edited));
    assert!(!with_mal.iter().any(|m| m.text == "hacked via repeat"));
    let quotes: Vec<_> = with_mal.iter().filter(|m| m.text == "quoting").collect();
    assert_eq!(quotes.len(), 3);
    assert!(
        quotes
            .iter()
            .all(|q| q.reply.as_ref().unwrap().text == "same id, edited")
    );
    let mut ids: Vec<i64> = with_mal.iter().map(|m| m.id).collect();
    ids.dedup();
    assert_eq!(ids.len(), with_mal.len(), "no row twice");
}

/// Editing a message that has not gone out yet changes what goes out; reacting to it waits
/// (review M2-1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn editing_an_unsent_message() {
    let r = relay().await;
    let hop = Proxy::to(&r.addr).await;
    let alice = user_at(&r, &hop.addr, "Alice", None).await;
    let bob = user(&r, "Bob").await;
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    hop.cut();
    online(&alice.client, false).await;
    let m = alice.client.send(a_bob.id, "first draft".into()).await.unwrap();
    assert_eq!(m.status, "failed");
    assert_eq!(
        alice.client.react(m.id, "👍".into(), true).await.unwrap_err(),
        ClientError::NotSentYet
    );
    alice
        .client
        .edit_message(m.id, "final words".into())
        .await
        .unwrap();
    hop.restore();
    online(&alice.client, true).await;
    let got = find(&bob.client, b_alice.id, "final words").await;
    assert!(!got.edited);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !bob.client
            .messages(b_alice.id)
            .await
            .unwrap()
            .iter()
            .any(|m| m.text == "first draft")
    );
}

/// An edit queued offline for a disappearing message is dropped with it, never sent
/// (INV-REST-9, review M2-3); search never finds an expired message (INV-REST-10).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn edits_and_search_respect_disappearing_messages() {
    let r = relay().await;
    let hop = Proxy::to(&r.addr).await;
    let alice = user_at(&r, &hop.addr, "Alice", None).await;
    let bob = user(&r, "Bob").await;
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    alice.client.set_timer(a_bob.id, 2).await.unwrap();
    eventually(|| async { (bob.client.contacts().await.unwrap()[0].timer_secs == 2).then_some(()) }).await;
    let m = alice.client.send(a_bob.id, "short lived".into()).await.unwrap();
    find(&bob.client, b_alice.id, "short lived").await;
    assert_eq!(alice.client.search("short".into()).await.unwrap().len(), 1);

    hop.cut();
    online(&alice.client, false).await;
    alice
        .client
        .edit_message(m.id, "secret edit".into())
        .await
        .unwrap();
    // Both copies expire; the queued edit goes with them.
    eventually(|| async { texts(&alice.client, a_bob.id).await.is_empty().then_some(()) }).await;
    assert!(alice.client.search("short".into()).await.unwrap().is_empty());
    assert!(alice.client.search("secret".into()).await.unwrap().is_empty());
    // The queued edit went with its message (review M2-3, M2R2-5).
    assert_eq!(alice.client.hidden_rows(a_bob.id).await.unwrap(), 0);
    hop.restore();
    online(&alice.client, true).await;
    alice.client.set_timer(a_bob.id, 0).await.unwrap();
    alice.client.send(a_bob.id, "after".into()).await.unwrap();
    find(&bob.client, b_alice.id, "after").await;
    assert!(
        !bob.client
            .messages(b_alice.id)
            .await
            .unwrap()
            .iter()
            .any(|m| m.text == "secret edit")
    );
}

/// Edits and deletes have time limits: ours 24 h after sending, theirs applied only to their
/// messages received in the last 48 h (INV-MSG-8, review M2R2-4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn edit_and_delete_time_windows() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    let old = alice
        .client
        .send(a_bob.id, "yesterday's words".into())
        .await
        .unwrap();
    alice.client.backdate(old.id, 25 * 3600 * 1000).await.unwrap();
    assert_eq!(
        alice.client.edit_message(old.id, "x".into()).await.unwrap_err(),
        ClientError::TooLate
    );
    assert_eq!(
        alice.client.delete_for_everyone(old.id).await.unwrap_err(),
        ClientError::TooLate
    );

    // Bob's message is old on Alice's side: his edit and delete are ignored there.
    let b = bob
        .client
        .send(b_alice.id, "older than two days".into())
        .await
        .unwrap();
    let at_alice = find(&alice.client, a_bob.id, "older than two days").await;
    alice
        .client
        .backdate(at_alice.id, 49 * 3600 * 1000)
        .await
        .unwrap();
    bob.client
        .edit_message(b.id, "rewritten history".into())
        .await
        .unwrap();
    bob.client.delete_for_everyone(b.id).await.unwrap();
    bob.client.send(b_alice.id, "marker".into()).await.unwrap();
    find(&alice.client, a_bob.id, "marker").await;
    let m = by_id(&alice.client, a_bob.id, at_alice.id).await.unwrap();
    assert_eq!(
        (m.text.as_str(), m.edited, m.deleted),
        ("older than two days", false, false)
    );
}
