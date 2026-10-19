//! Shared by the contact_* targets: two accounts with an established session.
use rand::TryRngCore as _;
use rand::rngs::OsRng;
use veil_core::account::{Account, IntroFields, Opened};
use veil_core::invite::InviteMode;
use veil_core::store::MemoryBackend;

pub const NOW: u64 = 1_800_000_000;
pub type Acc = Account<MemoryBackend>;

pub fn rng() -> rand::rand_core::UnwrapErr<OsRng> {
    OsRng.unwrap_err()
}

/// Alice redeems Bob's invite, Bob accepts, and both exchange one message, so the fuzzer
/// can act both as a fresh (PreKey) and as an established (Whisper) contact.
pub fn paired() -> (Acc, Acc) {
    futures_executor::block_on(async {
        let alice = Account::create(MemoryBackend::new(), &mut rng()).expect("alice");
        let bob = Account::create(MemoryBackend::new(), &mut rng()).expect("bob");
        let created = bob
            .create_invite(&mut rng(), InviteMode::Remote, "wss://r", [3; 32], [1; 32], [2; 32], NOW, 3600)
            .await
            .expect("invite");
        let fields = IntroFields { mailbox_id: [4; 32], delivery_token: [5; 32], display_name: None, rekey: None };
        let red = alice
            .redeem_invite(&mut rng(), &created.invite, &created.sealed_package, fields, NOW)
            .await
            .expect("redeem");
        assert!(matches!(bob.open(&mut rng(), &red.envelope, NOW).await, Ok(Opened::NewContact { .. })));
        (alice, bob)
    })
}
