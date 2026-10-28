//! Smoke test against a deployed relay (e.g. the `deploy/` container), using the same pinned
//! client as the integration tests. Ignored by default; run with
//!
//! ```text
//! VEIL_SMOKE_ADDR=127.0.0.1:8443 VEIL_SMOKE_PIN=<hex pin> \
//!   cargo test -p veil-relay --test smoke -- --ignored --nocapture
//! ```
//!
//! With `VEIL_SMOKE_TURN_OUT=<file>` it also writes seven freshly minted TURN username/credential
//! pairs there (two lines each) so they can be checked against coturn with `turnutils_uclient`;
//! separate credentials keep coturn's per-user allocation quota from coupling the checks.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::fmt::Write as _;
use std::io::Write as _;

use common::Client;
use veil_wire::{ENVELOPE_BUCKETS, Request, Response};

fn pin_from_hex(s: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex pin"))
        .collect();
    bytes.try_into().expect("32-byte pin")
}

#[tokio::test]
#[ignore = "needs a running relay: set VEIL_SMOKE_ADDR and VEIL_SMOKE_PIN"]
async fn deployed_relay_round_trip() {
    let addr = std::env::var("VEIL_SMOKE_ADDR")
        .expect("VEIL_SMOKE_ADDR")
        .parse()
        .unwrap();
    let pin = pin_from_hex(&std::env::var("VEIL_SMOKE_PIN").expect("VEIL_SMOKE_PIN"));

    // A wrong pin must be refused before any frame is exchanged.
    let mut wrong = pin;
    wrong[0] ^= 1;
    assert!(Client::connect(addr, wrong).await.is_err());

    let mut owner = Client::connect(addr, pin).await.unwrap();
    let mut sender = Client::connect(addr, pin).await.unwrap();
    let m: [u8; 32] = rand::random();
    let tok: [u8; 32] = rand::random();
    owner.new_mailbox(pin, m).await;
    owner.add_token(m, tok).await;
    let envelope = vec![0x5a; ENVELOPE_BUCKETS[0]];
    sender.deposit(m, tok, envelope.clone()).await.unwrap();
    let got = owner.fetch(m, 0).await.unwrap();
    assert_eq!(got.items.len(), 1);
    assert_eq!(got.items[0].envelope, envelope);

    let mut turn = String::new();
    for _ in 0..7 {
        match owner
            .call(Request::TurnCredentials(veil_wire::MailboxRef {
                mailbox_id: m.to_vec(),
            }))
            .await
        {
            Ok(Response::Turn(t)) => {
                assert!(!t.urls.is_empty());
                writeln!(turn, "{}\n{}", t.username, t.credential).unwrap();
            }
            other => panic!("TURN credentials: {other:?}"),
        }
    }
    if let Ok(path) = std::env::var("VEIL_SMOKE_TURN_OUT") {
        std::fs::write(path, turn).unwrap();
    }

    owner
        .call(Request::DeleteMailbox(veil_wire::MailboxRef {
            mailbox_id: m.to_vec(),
        }))
        .await
        .unwrap();
    owner.close().await;
    sender.close().await;
}

/// Load test for review P3-1: fills a deployed relay with `VEIL_SOAK_MB` megabytes of
/// 64 KiB envelopes from several connections at once. CI then checks that the container
/// survived two sweep intervals under its memory limit. Ignored by default; run with
///
/// ```text
/// VEIL_SMOKE_ADDR=… VEIL_SMOKE_PIN=… VEIL_SOAK_MB=1100 \
///   cargo test -p veil-relay --test smoke deployed_relay_soak -- --ignored
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a running relay: set VEIL_SMOKE_ADDR, VEIL_SMOKE_PIN and VEIL_SOAK_MB"]
async fn deployed_relay_soak() {
    const PER_MAILBOX: usize = 5_000; // the relay's per-mailbox cap
    const TOKENS: usize = 100; // each token stays within its deposit burst (60)
    const WORKERS: usize = 8;
    let addr: std::net::SocketAddr = std::env::var("VEIL_SMOKE_ADDR").unwrap().parse().unwrap();
    let pin = pin_from_hex(&std::env::var("VEIL_SMOKE_PIN").unwrap());
    let mb: usize = std::env::var("VEIL_SOAK_MB").unwrap().parse().unwrap();
    let total = mb * 1024 * 1024 / ENVELOPE_BUCKETS[3];
    let mailboxes = total.div_ceil(PER_MAILBOX);
    assert!(
        mailboxes <= 4,
        "one owner connection may create at most 4 mailboxes"
    );

    // Owner: mailboxes and tokens. Kept open so the mailboxes stay authenticated.
    let mut owner = Client::connect(addr, pin).await.unwrap();
    let mut plan: Vec<([u8; 32], [u8; 32])> = Vec::new(); // (mailbox, token) per deposit
    for _ in 0..mailboxes {
        let m: [u8; 32] = rand::random();
        owner.new_mailbox(pin, m).await;
        let tokens: Vec<[u8; 32]> = (0..TOKENS).map(|_| rand::random()).collect();
        for chunk in tokens.chunks(50) {
            owner
                .call(Request::UpdateTokens(veil_wire::UpdateTokens {
                    mailbox_id: m.to_vec(),
                    add: chunk
                        .iter()
                        .map(|t| veil_relay::server::token_hash(t).to_vec())
                        .collect(),
                    remove: vec![],
                }))
                .await
                .unwrap();
        }
        for i in 0..PER_MAILBOX {
            plan.push((m, tokens[i % TOKENS]));
        }
    }
    plan.truncate(total);

    let started = std::time::Instant::now();
    let mut tasks = Vec::new();
    for w in 0..WORKERS {
        let mine: Vec<_> = plan.iter().skip(w).step_by(WORKERS).copied().collect();
        tasks.push(tokio::spawn(async move {
            let mut c = Client::connect(addr, pin).await.unwrap();
            let envelope = vec![0x5a; ENVELOPE_BUCKETS[3]];
            for (m, t) in mine {
                loop {
                    match c.deposit(m, t, envelope.clone()).await {
                        Ok(_) => break,
                        Err(veil_wire::ErrorCode::RateLimited) => {
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        }
                        Err(e) => panic!("deposit: {e:?}"),
                    }
                }
            }
            c.close().await;
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert!(owner.try_ping().await, "owner connection still served");
    writeln!(
        std::io::stdout(),
        "soak: deposited {total} × 64 KiB ({} MiB) into {mailboxes} mailboxes in {:?}",
        total * ENVELOPE_BUCKETS[3] / (1024 * 1024),
        started.elapsed()
    )
    .unwrap();
}
