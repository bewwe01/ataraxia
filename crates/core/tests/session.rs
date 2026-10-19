//! End-to-end session tests through the public API (INV-CRY-*, INV-MSG-*, INV-PAIR-*).
// Test-only crate: unwraps, panics and arithmetic are fine here.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
use futures_executor::block_on;
use rand::TryRngCore as _;
use rand::rngs::OsRng;
use rand::seq::SliceRandom as _;
use veil_core::CoreError;
use veil_core::account::{Account, IntroFields, Opened, random_id};
use veil_core::content::{Body, Content, Text};
use veil_core::identity::Address;
use veil_core::invite::{Invite, InviteMode};
use veil_core::store::MemoryBackend;

const NOW: u64 = 1_800_000_000;
type Acc = Account<MemoryBackend>;

fn rng() -> rand::rand_core::UnwrapErr<OsRng> {
    OsRng.unwrap_err()
}

fn account() -> Acc {
    Account::create(MemoryBackend::new(), &mut rng()).unwrap()
}

fn intro(n: u8) -> IntroFields {
    IntroFields {
        mailbox_id: [n; 32],
        delivery_token: [n.wrapping_add(1); 32],
        display_name: Some(format!("user{n}")),
        rekey: None,
    }
}

fn text(s: &str) -> Content {
    Content {
        id: random_id(&mut rng()),
        sent_at_ms: 1,
        body: Some(Body::Text(Text {
            body: s.into(),
            ..Default::default()
        })),
    }
}

fn body(c: &Content) -> &str {
    match &c.body {
        Some(Body::Text(t)) => &t.body,
        _ => panic!("not text"),
    }
}

/// Bob invites, Alice redeems, Bob accepts. Returns (alice, bob, invite).
fn paired() -> (Acc, Acc, Invite) {
    block_on(async {
        let alice = account();
        let bob = account();
        let created = bob
            .create_invite(
                &mut rng(),
                InviteMode::Remote,
                "wss://relay.example.org",
                [3; 32],
                [1; 32],
                [2; 32],
                NOW,
                3600,
            )
            .await
            .unwrap();
        let link = created.invite.to_link();
        let invite = Invite::from_link(&link).unwrap();
        let red = alice
            .redeem_invite(&mut rng(), &invite, &created.sealed_package, intro(10), NOW)
            .await
            .unwrap();
        assert_eq!(red.contact, bob.identity().address());
        assert_eq!(red.contact_mailbox_id, [1; 32]);
        match bob.open(&mut rng(), &red.envelope, NOW).await.unwrap() {
            Opened::NewContact {
                from,
                intro,
                invite_mode,
                ..
            } => {
                assert_eq!(from, alice.identity().address());
                assert_eq!(intro.mailbox_id, vec![10; 32]);
                assert_eq!(invite_mode, InviteMode::Remote);
            }
            other @ Opened::Message { .. } => panic!("expected NewContact, got {other:?}"),
        }
        (alice, bob, invite)
    })
}

fn send(from: &Acc, to: &Acc, s: &str) -> Vec<u8> {
    block_on(from.seal(&mut rng(), &to.identity().address(), &text(s), NOW)).unwrap()
}

fn recv(at: &Acc, env: &[u8]) -> Result<(Address, String), CoreError> {
    match block_on(at.open(&mut rng(), env, NOW))? {
        Opened::Message { from, content } => Ok((from, body(&content).to_owned())),
        other @ Opened::NewContact { .. } => panic!("unexpected {other:?}"),
    }
}

#[test]
fn pairing_and_conversation() {
    let (alice, bob, _) = paired();
    for i in 0..30 {
        let (from, to) = if i % 2 == 0 {
            (&bob, &alice)
        } else {
            (&alice, &bob)
        };
        let msg = format!("message {i}");
        let (who, got) = recv(to, &send(from, to, &msg)).unwrap();
        assert_eq!(who, from.identity().address());
        assert_eq!(got, msg);
    }
}

/// The outer sealed-sender v1 structure, as the relay could parse it.
#[derive(Clone, PartialEq, prost::Message)]
struct OuterSealed {
    #[prost(bytes = "vec", optional, tag = "1")]
    ephemeral_public: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    encrypted_static: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    encrypted_message: Option<Vec<u8>>,
}

/// Everything about an envelope's shape that is readable without keys.
fn relay_view(env: &[u8]) -> (usize, u8, u8, usize, usize, usize) {
    use prost::Message as _;
    let sealed = &env[1..];
    let outer = OuterSealed::decode(&sealed[1..]).unwrap();
    (
        env.len(),
        env[0],
        sealed[0],
        outer.ephemeral_public.unwrap().len(),
        outer.encrypted_static.unwrap().len(),
        outer.encrypted_message.unwrap().len(),
    )
}

/// Review round 1, H1 (INV-META-3): within a bucket, nothing the relay can read depends on the
/// content length or on the message type (`PreKey` vs. normal). The old framing exposed a
/// plaintext length field and zero padding.
#[test]
fn relay_learns_only_the_bucket() {
    let (alice, bob, _) = paired();
    // Alice's messages are PreKey messages until Bob replies.
    let mut views = Vec::new();
    for n in [0, 1, 300, 600, 900] {
        let env = send(&alice, &bob, &"a".repeat(n));
        views.push(relay_view(&env));
        recv(&bob, &env).unwrap();
    }
    // After Bob's reply, Alice sends normal (non-PreKey) messages.
    recv(&alice, &send(&bob, &alice, "reply")).unwrap();
    for n in [0, 1, 300, 600, 900] {
        let env = send(&alice, &bob, &"b".repeat(n));
        views.push(relay_view(&env));
        recv(&bob, &env).unwrap();
    }
    // PreKey messages (carrying a 1569-byte ML-KEM ciphertext) never fit the 1 KiB bucket.
    assert!(views[..5].iter().all(|v| v.0 == 4096), "{views:?}");
    for bucket in [1024, 4096] {
        let same: Vec<_> = views.iter().filter(|v| v.0 == bucket).collect();
        assert!(!same.is_empty(), "no envelope in bucket {bucket}");
        assert!(same.iter().all(|v| v == &same[0]), "bucket {bucket}: {views:?}");
    }
    // Every bucket is reachable and exactly filled.
    for n in [0, 3000, 14_000, 60_000] {
        let env = send(&alice, &bob, &"c".repeat(n));
        assert!([1024, 4096, 16_384, 65_536].contains(&env.len()));
        assert_eq!(recv(&bob, &env).unwrap().1.len(), n);
    }
}

#[test]
fn envelopes_are_bucket_sized_and_relay_sees_no_identity() {
    let (alice, bob, _) = paired();
    for s in ["", "hi", &"x".repeat(3000), &"y".repeat(20_000)] {
        let env = send(&alice, &bob, s);
        assert!(
            veil_core::padding::ENVELOPE_BUCKETS.contains(&env.len()),
            "{}",
            env.len()
        );
        // INV-META-1 (core part): no identity key or address appears in the clear.
        for needle in [
            alice.identity().public().serialize().to_vec(),
            alice.identity().address().as_str().as_bytes().to_vec(),
        ] {
            assert!(
                !env.windows(needle.len()).any(|w| w == &needle[..]),
                "identity leaked in envelope"
            );
        }
        assert_eq!(recv(&bob, &env).unwrap().1, s);
    }
}

#[test]
fn every_bit_flip_rejected_and_state_unchanged() {
    let (alice, bob, _) = paired();
    let env = send(&alice, &bob, "integrity");
    let bob_backend_before = {
        let b = bob;
        let snap = b.into_backend();
        (snap.clone(), Account::load(snap).unwrap())
    };
    let (snapshot, bob) = bob_backend_before;
    for i in 0..env.len() {
        let mut t = env.clone();
        t[i] ^= 1 << (i % 8);
        assert!(
            block_on(bob.open(&mut rng(), &t, NOW)).is_err(),
            "flip at byte {i} accepted"
        );
    }
    // INV-MSG-2: no rejected envelope changed state; the genuine one still opens.
    let bob = {
        let be = bob.into_backend();
        assert!(be == snapshot, "state changed by rejected input");
        Account::load(be).unwrap()
    };
    assert_eq!(recv(&bob, &env).unwrap().1, "integrity");
}

#[test]
fn replay_rejected() {
    let (alice, bob, _) = paired();
    let env = send(&alice, &bob, "once");
    assert!(recv(&bob, &env).is_ok());
    assert_eq!(recv(&bob, &env).unwrap_err(), CoreError::Replay);
}

#[test]
fn out_of_order_delivery() {
    let (alice, bob, _) = paired();
    let mut envs: Vec<(usize, Vec<u8>)> = (0..25)
        .map(|i| (i, send(&alice, &bob, &format!("m{i}"))))
        .collect();
    envs.shuffle(&mut rand::rng());
    for (i, e) in envs {
        assert_eq!(recv(&bob, &e).unwrap().1, format!("m{i}"));
    }
}

#[test]
fn invite_is_single_use() {
    block_on(async {
        let (bob, carol) = (account(), account());
        let alice = account();
        let created = bob
            .create_invite(
                &mut rng(),
                InviteMode::Remote,
                "wss://r.example",
                [0; 32],
                [1; 32],
                [2; 32],
                NOW,
                3600,
            )
            .await
            .unwrap();
        let a = alice
            .redeem_invite(
                &mut rng(),
                &created.invite,
                &created.sealed_package,
                intro(1),
                NOW,
            )
            .await
            .unwrap();
        let c = carol
            .redeem_invite(
                &mut rng(),
                &created.invite,
                &created.sealed_package,
                intro(2),
                NOW,
            )
            .await
            .unwrap();
        assert!(matches!(
            bob.open(&mut rng(), &a.envelope, NOW).await,
            Ok(Opened::NewContact { .. })
        ));
        // INV-PAIR-2: a second redemption of the same invite is refused.
        assert_eq!(
            bob.open(&mut rng(), &c.envelope, NOW).await.unwrap_err(),
            CoreError::UnknownSender
        );
        // Replaying the first intro does not create a second contact.
        assert!(bob.open(&mut rng(), &a.envelope, NOW).await.is_err());
    });
}

#[test]
fn expired_and_revoked_invites_refused() {
    block_on(async {
        let (alice, bob) = (account(), account());
        let created = bob
            .create_invite(
                &mut rng(),
                InviteMode::InPerson,
                "wss://r.example",
                [0; 32],
                [1; 32],
                [2; 32],
                NOW,
                60,
            )
            .await
            .unwrap();
        assert_eq!(
            alice
                .redeem_invite(
                    &mut rng(),
                    &created.invite,
                    &created.sealed_package,
                    intro(1),
                    NOW + 60
                )
                .await
                .err(),
            Some(CoreError::InviteInvalid)
        );
        let red = alice
            .redeem_invite(
                &mut rng(),
                &created.invite,
                &created.sealed_package,
                intro(1),
                NOW,
            )
            .await
            .unwrap();
        assert_eq!(
            bob.open(&mut rng(), &red.envelope, NOW + 61).await.unwrap_err(),
            CoreError::InviteInvalid
        );

        let c2 = bob
            .create_invite(
                &mut rng(),
                InviteMode::Remote,
                "wss://r.example",
                [0; 32],
                [1; 32],
                [2; 32],
                NOW,
                600,
            )
            .await
            .unwrap();
        let carol = account();
        let r2 = carol
            .redeem_invite(&mut rng(), &c2.invite, &c2.sealed_package, intro(3), NOW)
            .await
            .unwrap();
        bob.revoke_invite(&c2.invite.id).await.unwrap();
        assert_eq!(
            bob.open(&mut rng(), &r2.envelope, NOW).await.unwrap_err(),
            CoreError::UnknownSender
        );
        assert_eq!(
            bob.sweep_expired_invites(NOW + 10_000).await.unwrap(),
            1,
            "the first (unused) invite expires"
        );
    });
}

#[test]
fn in_person_mode_is_reported() {
    block_on(async {
        let (alice, bob) = (account(), account());
        let c = bob
            .create_invite(
                &mut rng(),
                InviteMode::InPerson,
                "wss://r.example",
                [0; 32],
                [1; 32],
                [2; 32],
                NOW,
                600,
            )
            .await
            .unwrap();
        let r = alice
            .redeem_invite(&mut rng(), &c.invite, &c.sealed_package, intro(1), NOW)
            .await
            .unwrap();
        assert!(matches!(
            bob.open(&mut rng(), &r.envelope, NOW).await,
            Ok(Opened::NewContact {
                invite_mode: InviteMode::InPerson,
                ..
            })
        ));
    });
}

#[test]
fn bundle_must_match_invite_identity() {
    block_on(async {
        let (alice, bob, mallory) = (account(), account(), account());
        let real = bob
            .create_invite(
                &mut rng(),
                InviteMode::Remote,
                "wss://r.example",
                [0; 32],
                [1; 32],
                [2; 32],
                NOW,
                600,
            )
            .await
            .unwrap();
        // Mallory swaps in her own package under Bob's invite id/secret: AEAD binds the identity, so it fails.
        let fake = mallory
            .create_invite(
                &mut rng(),
                InviteMode::Remote,
                "wss://r.example",
                [0; 32],
                [1; 32],
                [2; 32],
                NOW,
                600,
            )
            .await
            .unwrap();
        let err = alice
            .redeem_invite(&mut rng(), &real.invite, &fake.sealed_package, intro(1), NOW)
            .await
            .err();
        assert_eq!(err, Some(CoreError::AuthFailed));
    });
}

#[test]
fn unknown_and_self_senders_refused() {
    let (alice, bob, _) = paired();
    let (_, carol, _) = paired();
    // Carol is a stranger to Alice: she cannot even seal (no session), and Alice drops anything from her.
    assert_eq!(
        block_on(carol.seal(&mut rng(), &alice.identity().address(), &text("hi"), NOW)).unwrap_err(),
        CoreError::NoSession
    );
    // An envelope for Bob cannot be opened by Alice.
    let to_bob = send(&alice, &bob, "x");
    assert!(block_on(alice.open(&mut rng(), &to_bob, NOW)).is_err());
}

#[test]
fn persistence_roundtrip() {
    let (alice, bob, _) = paired();
    let alice = Account::load(alice.into_backend()).unwrap();
    let bob = Account::load(bob.into_backend()).unwrap();
    assert_eq!(
        recv(&bob, &send(&alice, &bob, "after reload")).unwrap().1,
        "after reload"
    );
    assert_eq!(
        recv(&alice, &send(&bob, &alice, "and back")).unwrap().1,
        "and back"
    );
}

#[test]
fn safety_numbers_agree_across_the_pair() {
    let (alice, bob, _) = paired();
    let a = alice.safety_number(&bob.identity().address()).unwrap();
    let b = bob.safety_number(&alice.identity().address()).unwrap();
    assert_eq!(a.digits(), b.digits());
    assert_eq!(a.matches_scanned(b.scannable()), Ok(true));
}

#[test]
fn invalid_content_never_sent() {
    let (alice, bob, _) = paired();
    let bad = Content {
        id: vec![1; 3],
        sent_at_ms: 0,
        body: Some(Body::Text(Text::default())),
    };
    assert_eq!(
        block_on(alice.seal(&mut rng(), &bob.identity().address(), &bad, NOW)).unwrap_err(),
        CoreError::Malformed
    );
}

mod ratchet_properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]
        /// INV-MSG-3/4: random permutation + random drops + random duplicates.
        /// Every delivered message decrypts exactly once with the right body; every duplicate
        /// is a `Replay`; nothing panics; the session keeps working afterwards.
        #[test]
        fn shuffled_dropped_duplicated(
            n in 1usize..30,
            seed in any::<u64>(),
            drop_mask in any::<u32>(),
            dup_mask in any::<u32>(),
        ) {
            use rand::SeedableRng as _;
            let (alice, bob, _) = paired();
            let envs: Vec<(usize, Vec<u8>)> = (0..n).map(|i| (i, send(&alice, &bob, &format!("p{i}")))).collect();
            let mut deliveries: Vec<(usize, Vec<u8>, bool)> = Vec::new();
            for (i, e) in &envs {
                if drop_mask & (1 << (i % 32)) != 0 && *i % 3 == 0 { continue; }
                deliveries.push((*i, e.clone(), false));
                if dup_mask & (1 << (i % 32)) != 0 { deliveries.push((*i, e.clone(), true)); }
            }
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            deliveries.shuffle(&mut rng);
            let mut seen = std::collections::HashSet::new();
            for (i, e, _) in &deliveries {
                match recv(&bob, e) {
                    Ok((_, body)) => {
                        prop_assert_eq!(body, format!("p{i}"));
                        prop_assert!(seen.insert(*i), "message {} accepted twice", i);
                    }
                    Err(err) => {
                        prop_assert_eq!(err, CoreError::Replay);
                        prop_assert!(seen.contains(i), "first delivery of {} rejected", i);
                    }
                }
            }
            // Session still healthy in both directions.
            prop_assert_eq!(recv(&alice, &send(&bob, &alice, "still ok")).unwrap().1, "still ok");
            prop_assert_eq!(recv(&bob, &send(&alice, &bob, "both ways")).unwrap().1, "both ways");
        }
    }
}
