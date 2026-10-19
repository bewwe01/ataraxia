#![no_main]
//! A legitimate, authenticated contact sends arbitrary inner libsignal message bytes, of
//! any message type, inside a correctly sealed envelope with a valid certificate (review
//! round 1, M5). This reaches libsignal's message parsing, the SPQR ratchet, PQXDH with the
//! Kyber step, and Veil's version checks, which random bytes never get past the
//! sealed-sender MAC to reach. Must never panic; anything that opens must be valid content.
//!
//! The fixture is deterministic (`pairing.rs`), so the committed genuine seeds match it
//! (review round 4, R4-1): Whisper messages from Alice, and a PreKey message redeeming
//! Bob's live re-key invite. The fixture is rebuilt whenever an input consumes that invite,
//! so the Kyber step stays reachable for every later input (review round 5, R5-1). Write them with
//! `VEIL_WRITE_SEEDS=corpus/contact_inner cargo fuzz run contact_inner -- -runs=0`.
mod pairing;
use std::cell::RefCell;

use pairing::{Fixture, NOW, paired, rng};
use veil_core::account::{IntroFields, Opened};
use veil_core::content::{Body, Content, Text};

thread_local! {
    static PAIR: RefCell<Fixture> = RefCell::new({
        if let Ok(dir) = std::env::var("VEIL_WRITE_SEEDS") {
            write_seeds(&dir);
        }
        // Build and drop one throwaway fixture first, so setup *and* teardown code are part of
        // the INITED baseline instead of being credited to a later re-pair (review R5-2).
        drop(paired());
        paired()
    });
}

fn write_seeds(dir: &str) {
    pairing::assert_deterministic();
    let Fixture { alice, bob, rekey, rekey_package, mut det } = paired();
    let seeds = futures_executor::block_on(async {
        let mut seeds = Vec::new();
        for n in [0usize, 1, 200, 2000] {
            let c = Content {
                id: vec![n as u8; 16],
                sent_at_ms: 1,
                body: Some(Body::Text(Text { body: "m".repeat(n), ..Default::default() })),
            };
            let env = alice.seal(&mut det, &bob.identity().address(), &c, NOW).await.expect("seal");
            seeds.push(bob.fuzz_inner_of(&env).await.expect("inner"));
        }
        // A PreKey message (with ML-KEM ciphertext): Alice, already a contact, redeems Bob's
        // live re-key invite (the re-key flow). The harness seals inputs as Alice, so the inner
        // message's identity matches and libsignal goes on to PQXDH and the Kyber step.
        let fields = IntroFields { mailbox_id: [1; 32], delivery_token: [2; 32], display_name: None, rekey: None };
        let red = alice
            .redeem_invite(&mut det, &rekey, &rekey_package, fields, NOW)
            .await
            .expect("redeem rekey");
        let (ty, inner) = bob.fuzz_inner_of(&red.envelope).await.expect("inner");
        assert_eq!(ty, 3, "redeem must be a PreKey message");
        seeds.push((ty, inner));
        seeds
    });
    for (i, (ty, inner)) in seeds.into_iter().enumerate() {
        // Self-check on a fresh fixture: every genuine seed opens (so it gets past libsignal's
        // identity check and, for the PreKey seed, through PQXDH and the Kyber step).
        let g = paired();
        let opened = futures_executor::block_on(async {
            let env = g.alice.fuzz_seal_inner(&mut rng(), &g.bob.identity().address(), ty, &inner, NOW).await?;
            g.bob.open(&mut rng(), &env, NOW).await
        });
        assert!(matches!(opened, Ok(Opened::Message { .. })), "seed {i} does not open: {opened:?}");
        let mut seed = vec![ty];
        seed.extend_from_slice(&inner);
        std::fs::write(format!("{dir}/seed-genuine-{i}"), seed).expect("write seed");
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // Empty input (libFuzzer's discarded first run) never touches the fixture, so the fixture
    // is built on the first real input and its setup code is part of the INITED baseline.
    let Some((&ty, inner)) = data.split_first() else { return };
    PAIR.with(|cell| {
        let mut f = cell.borrow_mut();
        futures_executor::block_on(async {
            let to = f.bob.identity().address();
            if let Ok(env) = f.alice.fuzz_seal_inner(&mut rng(), &to, ty, inner, NOW).await {
                if let Ok(Opened::Message { content, .. }) = f.bob.open(&mut rng(), &env, NOW).await {
                    assert!(content.validate().is_ok(), "invalid content accepted");
                }
            }
        });
        // Once an input has consumed Bob's re-key invite (and with it the Kyber prekey), later
        // PreKey inputs could no longer reach PQXDH/ML-KEM decapsulation: rebuild the fixture
        // (review round 5, R5-1).
        if !f.bob.fuzz_has_invite(&f.rekey.id) {
            *f = paired();
        }
    });
});
