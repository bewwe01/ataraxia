//! Smoke test against a deployed relay (e.g. the `deploy/` container), using the same pinned
//! client as the integration tests. Ignored by default; run with
//!
//! ```text
//! VEIL_SMOKE_ADDR=127.0.0.1:8443 VEIL_SMOKE_PIN=<hex pin> \
//!   cargo test -p veil-relay --test smoke -- --ignored --nocapture
//! ```
//!
//! With `VEIL_SMOKE_TURN_OUT=<file>` it also writes three freshly minted TURN username/credential
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
    for _ in 0..3 {
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
