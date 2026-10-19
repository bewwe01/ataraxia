#![no_main]
//! A legitimate contact encrypts arbitrary plaintext over the real Triple Ratchet session,
//! bypassing the sender-side content validation (review round 1, M5). This reaches unpadding,
//! strict content decoding, validation, invite-proof handling and the transaction logic.
//! Must never panic. Whatever is accepted must re-encode canonically.
mod pairing;
use pairing::{Acc, NOW, paired, rng};
use veil_core::account::Opened;

thread_local! {
    static PAIR: (Acc, Acc) = paired();
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    PAIR.with(|(alice, bob)| {
        futures_executor::block_on(async {
            let to = bob.identity().address();
            let Ok(env) = alice.fuzz_seal_plaintext(&mut rng(), &to, data, NOW).await else { return };
            if let Ok(Opened::Message { content, .. }) = bob.open(&mut rng(), &env, NOW).await {
                assert!(content.validate().is_ok(), "invalid content accepted");
            }
        });
    });
});
