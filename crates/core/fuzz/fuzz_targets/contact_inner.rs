#![no_main]
//! A legitimate, authenticated contact sends arbitrary inner libsignal message bytes, of
//! any message type, inside a correctly sealed envelope with a valid certificate (review
//! round 1, M5). This reaches libsignal's message parsing, the SPQR ratchet and Veil's
//! version checks, which random bytes never get past the sealed-sender MAC to reach.
//! Must never panic; a hostile inner message must never open.
mod pairing;
use pairing::{Acc, NOW, paired, rng};

thread_local! {
    static PAIR: (Acc, Acc) = paired();
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&ty, inner)) = data.split_first() else { return };
    PAIR.with(|(alice, bob)| {
        futures_executor::block_on(async {
            let to = bob.identity().address();
            if let Ok(env) = alice.fuzz_seal_inner(&mut rng(), &to, ty, inner, NOW).await {
                assert!(bob.open(&mut rng(), &env, NOW).await.is_err(), "forged inner message opened");
            }
        });
    });
});
