#![no_main]
//! A legitimate contact encrypts arbitrary plaintext over the real Triple Ratchet session,
//! bypassing the sender-side content validation (review round 1 M5, round 2 N1). With the
//! first input byte even, the rest is block-padded like real content, so it reaches strict
//! decoding, validation, invite-proof handling and the transaction logic; odd bytes test
//! unpadding with raw input. Must never panic, and whatever opens must be valid content.
//!
//! Coverage caveat (review round 3, R3-1): the re-pair at input #2001 adds ~3 900 edges of
//! setup code, which libFuzzer credits to that input. Pairing twice at start-up did not move
//! the jump, so it is reported rather than hidden; see TEST_REPORT for the fuzz-driven gain.
//!
//! Not reached (deferred to Phase 8, review round 3, R3-1): the invite-proof branches of
//! `consume_invite_if_proven`. They need a live invite id and proof, which are random per run
//! and so cannot appear in a committed corpus. They are covered by the mutation-checked
//! unit test `pairing_tests::known_contact_rekey_invite_paths`.
//!
//! Refused messages do not advance the recipient's ratchet while the sender's keeps moving,
//! so after ~25 000 refusals libsignal would report "too far in the future". The pair is
//! therefore re-created every `REPAIR_EVERY` inputs.
mod pairing;
use std::cell::RefCell;

use pairing::{Acc, NOW, paired, rng};
use veil_core::account::Opened;

const REPAIR_EVERY: u32 = 2_000;

thread_local! {
    static PAIR: RefCell<(Acc, Acc, u32)> = RefCell::new({
        let (a, b) = paired();
        (a, b, 0)
    });
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    PAIR.with(|cell| {
        let mut state = cell.borrow_mut();
        if state.2 >= REPAIR_EVERY {
            let (a, b) = paired();
            *state = (a, b, 0);
        }
        state.2 += 1;
        let (alice, bob, _) = &*state;
        futures_executor::block_on(async {
            let to = bob.identity().address();
            let Ok(env) = alice.fuzz_seal_plaintext(&mut rng(), &to, data, NOW).await else { return };
            if let Ok(Opened::Message { content, .. }) = bob.open(&mut rng(), &env, NOW).await {
                assert!(content.validate().is_ok(), "invalid content accepted");
            }
        });
    });
});
