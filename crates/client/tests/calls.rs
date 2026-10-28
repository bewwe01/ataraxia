//! Milestone 6: call signaling between two clients through a real relay (ADR-0018). Media
//! itself runs in the webview; here we check what Rust controls: TURN servers handed to the
//! webview, relay-only SDP in both directions, delivery of offer, answer, hangup and busy,
//! and that nothing of a call is kept at rest.
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
use veil_client::service::{CallSignal, Client};
use veil_relay::turn::TurnConfig;
use zeroize::Zeroizing;

const FP: &str =
    "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";
const UFRAG: &str = "wTb2Qz7xK";

/// A browser-like SDP with audio (and video), and candidates of every kind: only the relay
/// candidates at a public address or at the user's own relay host (127.0.0.1 in tests) may
/// survive.
fn sdp(setup: &str, video: bool) -> String {
    let mut lines = vec![
        "v=0".to_owned(),
        "o=- 4611731400430051336 2 IN IP4 127.0.0.1".into(),
        "s=-".into(),
        "t=0 0".into(),
        format!("a=group:BUNDLE 0{}", if video { " 1" } else { "" }),
    ];
    let section = |kind: &str, mid: u8, pt: &str, rtpmap: &str| -> Vec<String> {
        vec![
            format!("m={kind} 9 UDP/TLS/RTP/SAVPF {pt}"),
            "c=IN IP4 0.0.0.0".into(),
            "a=candidate:1 1 udp 2122260223 192.168.1.20 47810 typ host generation 0".into(),
            "a=candidate:2 1 udp 41885439 127.0.0.1 49170 typ relay raddr 1.1.1.1 rport 47810 generation 0"
                .into(),
            "a=candidate:3 1 udp 41885438 10.0.0.1 49171 typ relay raddr 1.1.1.1 rport 47810 generation 0"
                .into(),
            "a=candidate:4 1 udp 41885437 8.8.4.4 3478 typ relay raddr 1.1.1.1 rport 47810 generation 0"
                .into(),
            format!("a=ice-ufrag:{UFRAG}"),
            "a=ice-pwd:1Kf7oZ/3qR+8tYgH2jL4nM9p".into(),
            format!("a=fingerprint:sha-256 {FP}"),
            format!("a=setup:{setup}"),
            format!("a=mid:{mid}"),
            "a=sendrecv".into(),
            "a=rtcp-mux".into(),
            format!("a=rtpmap:{pt} {rtpmap}"),
        ]
    };
    lines.extend(section("audio", 0, "111", "opus/48000/2"));
    if video {
        lines.extend(section("video", 1, "96", "VP8/90000"));
    }
    lines.join("\r\n") + "\r\n"
}

fn turn(urls: &[&str]) -> TurnConfig {
    TurnConfig {
        secret: Zeroizing::new(b"0123456789abcdef0123456789abcdef".to_vec()),
        urls: urls.iter().map(|u| (*u).to_owned()).collect(),
        ttl_secs: 3600,
    }
}

async fn signal(c: &Client, kind: &str) -> CallSignal {
    within(Duration::from_secs(15), || async {
        c.call_signals()
            .await
            .unwrap()
            .into_iter()
            .find(|s| s.kind == kind)
    })
    .await
}

const CALL: &str = "00112233445566778899aabbccddeeff";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_call_is_signalled_relay_only() {
    let r = relay_with(|c| {
        c.turn = Some(turn(&[
            "turn:127.0.0.1:3478?transport=udp",
            "turn:192.168.1.5:3478",
            "turn:router.lan:3478",
            "turns:turn.example.org:443?transport=tcp",
        ]));
    })
    .await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;

    // The webview gets the relay's TURN servers, minus any that point into a network that is
    // not the user's own relay host (ADR-0018).
    let setup = alice.client.call_setup(a_bob.id).await.unwrap();
    let urls = &setup.ice_servers[0].urls;
    assert_eq!(
        urls,
        &vec![
            "turn:127.0.0.1:3478?transport=udp".to_owned(),
            "turns:turn.example.org:443?transport=tcp".to_owned()
        ]
    );
    assert!(!setup.ice_servers[0].username.is_empty() && !setup.ice_servers[0].credential.is_empty());

    // Offer: only relay candidates at a public address or our own relay host get through.
    alice
        .client
        .call_send(a_bob.id, CALL.into(), "offer", Some(sdp("actpass", true)))
        .await
        .unwrap();
    let offer = signal(&bob.client, "offer").await;
    assert_eq!(
        (offer.contact, offer.call_id.as_str(), offer.video),
        (b_alice.id, CALL, true)
    );
    let sdp_in = offer.sdp.unwrap();
    assert!(sdp_in.contains(" 127.0.0.1 49170 typ relay") && sdp_in.contains(" 8.8.4.4 3478 typ relay"));
    for gone in ["192.168.1.20", "10.0.0.1", "typ host", "raddr 1.1.1.1"] {
        assert!(!sdp_in.contains(gone), "{gone} must not reach the peer");
    }
    assert!(sdp_in.contains(&format!("a=fingerprint:sha-256 {FP}")));

    // Answer, then hangup, back the other way.
    bob.client
        .call_send(b_alice.id, CALL.into(), "answer", Some(sdp("active", true)))
        .await
        .unwrap();
    let answer = signal(&alice.client, "answer").await;
    assert_eq!(answer.call_id, CALL);
    assert!(!answer.sdp.unwrap().contains("192.168.1.20"));
    bob.client
        .call_send(b_alice.id, CALL.into(), "hangup", None)
        .await
        .unwrap();
    signal(&alice.client, "hangup").await;
    // Busy, for a call that cannot be taken.
    bob.client
        .call_send(b_alice.id, CALL.into(), "busy", None)
        .await
        .unwrap();
    signal(&alice.client, "busy").await;
    // Each signal is handed out once.
    assert!(alice.client.call_signals().await.unwrap().is_empty());

    // What the webview sends is checked too: no fingerprint, a wrong DTLS role, a bad id.
    let no_fp = sdp("actpass", false).replace(&format!("a=fingerprint:sha-256 {FP}\r\n"), "");
    for (id, kind, body) in [
        (CALL, "offer", Some(no_fp)),
        (CALL, "answer", Some(sdp("actpass", false))),
        (CALL, "offer", None),
        ("abc", "hangup", None),
        (CALL, "ring", None),
    ] {
        assert_eq!(
            alice
                .client
                .call_send(a_bob.id, id.into(), kind, body)
                .await
                .unwrap_err(),
            ClientError::BadInput,
            "{kind}"
        );
    }

    // Nothing of the call is kept at rest: not the SDP, not its ICE credentials.
    alice.client.lock().await.unwrap();
    bob.client.lock().await.unwrap();
    for d in [alice.dir(), bob.dir()] {
        assert!(!tree_contains(d, UFRAG.as_bytes()), "call SDP found at rest");
    }
    // And locking drops whatever was waiting.
    bob.client
        .unlock(Zeroizing::new("correct horse battery".into()))
        .await
        .unwrap();
    assert!(bob.client.call_signals().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_calls_without_turn_and_none_from_blocked_contacts() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    assert_eq!(
        alice.client.call_setup(a_bob.id).await.unwrap_err(),
        ClientError::NoCalls
    );

    // Bob blocks Alice: he cannot call her, and her offer never rings for him.
    bob.client.set_blocked(b_alice.id, true).await.unwrap();
    assert_eq!(
        bob.client.call_setup(b_alice.id).await.unwrap_err(),
        ClientError::Blocked
    );
    let _ = alice
        .client
        .call_send(a_bob.id, CALL.into(), "offer", Some(sdp("actpass", false)))
        .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(bob.client.call_signals().await.unwrap().is_empty());
    assert!(
        bob.events
            .lock()
            .unwrap()
            .iter()
            .all(|e| e.0 != veil_client::service::ChangeKind::Ringing)
    );
}

/// A call signal that cannot be delivered is gone, not queued: after the connection comes
/// back, the contact must not ring for a call the caller already gave up on (review C6-2), and
/// nothing of it stays in the database (C6-6).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_undelivered_offer_is_never_sent_later() {
    let r = relay_with(|c| c.turn = Some(turn(&["turn:127.0.0.1:3478?transport=udp"]))).await;
    let hop = Proxy::to(&r.addr).await;
    let alice = user_at(&r, &hop.addr, "Alice", None).await;
    let bob = user(&r, "Bob").await;
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    alice.client.call_setup(a_bob.id).await.unwrap();

    hop.cut();
    online(&alice.client, false).await;
    assert_eq!(
        alice
            .client
            .call_send(a_bob.id, CALL.into(), "offer", Some(sdp("actpass", false)))
            .await
            .unwrap_err(),
        ClientError::Unreachable
    );
    assert_eq!(alice.client.hidden_rows(a_bob.id).await.unwrap(), 0);

    hop.restore();
    online(&alice.client, true).await;
    // Something that is retried does arrive, so the connection really is back.
    alice.client.send(a_bob.id, "back".into()).await.unwrap();
    arrives(&bob.client, b_alice.id, "back").await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(bob.client.call_signals().await.unwrap().is_empty());
    assert!(
        bob.events
            .lock()
            .unwrap()
            .iter()
            .all(|e| e.0 != veil_client::service::ChangeKind::Ringing)
    );
}
