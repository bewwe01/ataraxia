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
        (Some(q_at_alice.id), false, "where do we meet?")
    );
    let ans_at_bob = find(&bob.client, b_alice.id, "at the station").await;
    let reply = ans_at_bob.reply.unwrap();
    assert_eq!(
        (reply.id, reply.mine, reply.text.as_str()),
        (Some(q.id), true, "where do we meet?")
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

    // Reactions: one per person, changeable and removable, on either side's messages.
    alice
        .client
        .react(q_at_alice.id, Some("👍".into()))
        .await
        .unwrap();
    bob.client.react(q.id, Some("❤️".into())).await.unwrap();
    eventually(|| async {
        let m = by_id(&bob.client, b_alice.id, q.id).await?;
        (m.reactions.len() == 2).then_some(())
    })
    .await;
    alice
        .client
        .react(q_at_alice.id, Some("😂".into()))
        .await
        .unwrap();
    eventually(|| async {
        let m = by_id(&bob.client, b_alice.id, q.id).await?;
        m.reactions
            .iter()
            .any(|x| !x.mine && x.emoji == "😂")
            .then_some(())
    })
    .await;
    alice.client.react(q_at_alice.id, None).await.unwrap();
    eventually(|| async {
        let m = by_id(&bob.client, b_alice.id, q.id).await?;
        (m.reactions.len() == 1 && m.reactions[0].mine).then_some(())
    })
    .await;
    assert_eq!(
        alice
            .client
            .react(q_at_alice.id, Some("not an emoji at all".into()))
            .await
            .unwrap_err(),
        ClientError::BadInput
    );

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
