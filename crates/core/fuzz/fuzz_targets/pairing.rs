//! Shared by the contact_* targets: two accounts with an established session.
//!
//! The pairing is **deterministic** (review round 4, R4-1): every key, invite and session
//! step draws from one fixed-seed CSPRNG, so committed seeds (genuine inner messages, a
//! valid re-key proof) match the fixture in every run. Fuzz inputs themselves are still
//! sealed with OS randomness.
use rand::rngs::{OsRng, StdRng};
use rand::{SeedableRng as _, TryRngCore as _};
use veil_core::account::{Account, IntroFields, Opened};
use veil_core::content::{Body, Content, Text};
use veil_core::invite::{Invite, InviteMode};
use veil_core::store::MemoryBackend;

pub const NOW: u64 = 1_800_000_000;
const SEED: u64 = 0x7e11_2026_1019;
pub type Acc = Account<MemoryBackend>;

pub fn rng() -> rand::rand_core::UnwrapErr<OsRng> {
    OsRng.unwrap_err()
}

pub struct Fixture {
    pub alice: Acc,
    pub bob: Acc,
    /// A live re-key invite of Bob's that Alice may redeem as a known contact.
    pub rekey: Invite,
    /// Its sealed package (what the relay would hold).
    pub rekey_package: Vec<u8>,
    /// The deterministic RNG, positioned after setup (for writing seeds).
    pub det: StdRng,
}

/// Alice redeems Bob's invite, Bob accepts and replies, Alice reads the reply, and Bob issues
/// a re-key invite. All deterministic.
pub fn paired() -> Fixture {
    futures_executor::block_on(async {
        let mut det = StdRng::seed_from_u64(SEED);
        let alice = Account::create(MemoryBackend::new(), &mut det).expect("alice");
        let bob = Account::create(MemoryBackend::new(), &mut det).expect("bob");
        let created = bob
            .create_invite(&mut det, InviteMode::Remote, "wss://r", [3; 32], [1; 32], [2; 32], NOW, 3600)
            .await
            .expect("invite");
        let fields = IntroFields { mailbox_id: [4; 32], delivery_token: [5; 32], display_name: None, rekey: None };
        let red = alice
            .redeem_invite(&mut det, &created.invite, &created.sealed_package, fields, NOW)
            .await
            .expect("redeem");
        assert!(matches!(bob.open(&mut det, &red.envelope, NOW).await, Ok(Opened::NewContact { .. })));
        let reply = Content {
            id: vec![9; 16],
            sent_at_ms: 1,
            body: Some(Body::Text(Text { body: "reply".into(), ..Default::default() })),
        };
        let env = bob.seal(&mut det, &alice.identity().address(), &reply, NOW).await.expect("reply");
        assert!(matches!(alice.open(&mut det, &env, NOW).await, Ok(Opened::Message { .. })));
        let created = bob
            .create_invite(&mut det, InviteMode::Remote, "wss://r", [6; 32], [7; 32], [8; 32], NOW, 3600)
            .await
            .expect("rekey invite");
        Fixture { alice, bob, rekey: created.invite, rekey_package: created.sealed_package, det }
    })
}

/// Fails loudly if the fixture is not reproducible (then committed seeds would be useless).
pub fn assert_deterministic() {
    let (a, b) = (paired(), paired());
    assert!(a.alice.into_backend() == b.alice.into_backend(), "alice not deterministic");
    assert!(a.bob.into_backend() == b.bob.into_backend(), "bob not deterministic");
}
