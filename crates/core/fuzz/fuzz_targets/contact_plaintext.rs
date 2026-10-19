#![no_main]
//! A legitimate contact encrypts arbitrary plaintext over the real Triple Ratchet session,
//! bypassing the sender-side content validation (review round 1 M5, round 2 N1). With the
//! first input byte even, the rest is block-padded like real content, so it reaches strict
//! decoding, validation, invite-proof handling and the transaction logic; odd bytes test
//! unpadding with raw input. Must never panic, and whatever opens must be valid content.
//!
//! The fixture is deterministic (`pairing.rs`, review round 4 R4-1): Bob's live re-key invite
//! has the same id in every run, so committed seeds carry a *valid* proof and reach the
//! invite-proof branches of `consume_invite_if_proven`. Write those seeds with
//! `VEIL_WRITE_SEEDS=corpus/contact_plaintext cargo fuzz run contact_plaintext -- -runs=0`.
//! Setup coverage lands in the INITED baseline (see the empty-input check below).
//!
//! Refused messages do not advance the recipient's ratchet while the sender's keeps moving,
//! so after ~25 000 refusals libsignal would report "too far in the future". The fixture is
//! therefore rebuilt every `REPAIR_EVERY` inputs.
#[allow(dead_code)] // shared fixture; this target does not use every field
mod pairing;
use std::cell::RefCell;

use pairing::{Fixture, NOW, paired, rng};
use prost::Message as _;
use veil_core::account::Opened;
use veil_core::content::{Body, ContactIntro, Content};

const REPAIR_EVERY: u32 = 2_000;

thread_local! {
    static STATE: RefCell<(Fixture, u32)> = RefCell::new({
        if let Ok(dir) = std::env::var("VEIL_WRITE_SEEDS") {
            write_seeds(&dir);
        }
        drop(paired()); // setup and teardown code into the INITED baseline (review R5-2)
        (paired(), 0)
    });
}

/// Re-key intros against Bob's live invite: a valid proof, a wrong one, and an unknown id.
fn write_seeds(dir: &str) {
    pairing::assert_deterministic();
    let f = paired();
    let good = f.rekey.fuzz_proof(f.alice.identity().public()).expect("proof").to_vec();
    let cases = [
        ("valid", f.rekey.id.to_vec(), good.clone()),
        ("badproof", f.rekey.id.to_vec(), vec![7; 32]),
        ("unknownid", vec![0xEE; 16], good),
    ];
    for (name, id, proof) in cases {
        let c = Content {
            id: vec![1; 16],
            sent_at_ms: 1,
            body: Some(Body::ContactIntro(ContactIntro {
                mailbox_id: vec![6; 32],
                delivery_token: vec![7; 32],
                display_name: None,
                invite_id: Some(id),
                invite_proof: Some(proof),
                rekey: None,
            })),
        };
        let mut seed = vec![0u8]; // "pad" mode
        seed.extend_from_slice(&c.encode_to_vec());
        // Self-check on a fresh fixture: each seed takes the branch it is meant for.
        let g = paired();
        let r = futures_executor::block_on(async {
            let env = g.alice.fuzz_seal_plaintext(&mut rng(), &g.bob.identity().address(), &seed, NOW).await?;
            g.bob.open(&mut rng(), &env, NOW).await
        });
        // The outcome *and* the invite's fate tell the three branches apart (review R5-1).
        let live = g.bob.fuzz_has_invite(&g.rekey.id);
        match name {
            "badproof" => {
                assert_eq!(r.err(), Some(veil_core::CoreError::AuthFailed), "{name}");
                assert!(live, "a bad proof must not consume the invite");
            }
            "valid" => {
                assert!(matches!(r, Ok(Opened::Message { .. })), "{name}");
                assert!(!live, "a valid proof must consume the invite");
            }
            _ => {
                assert!(matches!(r, Ok(Opened::Message { .. })), "{name}");
                assert!(live, "an unknown id must leave the invite alone");
            }
        }
        std::fs::write(format!("{dir}/seed-rekey-{name}"), seed).expect("write seed");
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // Return *before* touching the fixture on libFuzzer's first, empty run (whose coverage is
    // discarded): the fixture is then built on the first real input, so setup code is part of
    // the INITED baseline and a later re-pair adds no spurious "new" coverage (review R4-1).
    if data.is_empty() {
        return;
    }
    STATE.with(|cell| {
        let mut state = cell.borrow_mut();
        // Rebuild every REPAIR_EVERY inputs, and as soon as an input has consumed Bob's re-key
        // invite, so the invite-proof branches (valid and bad) stay reachable (review R5-1).
        if state.1 >= REPAIR_EVERY || !state.0.bob.fuzz_has_invite(&state.0.rekey.id) {
            *state = (paired(), 0);
        }
        state.1 += 1;
        let f = &state.0;
        futures_executor::block_on(async {
            let to = f.bob.identity().address();
            let Ok(env) = f.alice.fuzz_seal_plaintext(&mut rng(), &to, data, NOW).await else { return };
            if let Ok(Opened::Message { content, .. }) = f.bob.open(&mut rng(), &env, NOW).await {
                assert!(content.validate().is_ok(), "invalid content accepted");
            }
        });
    });
});
