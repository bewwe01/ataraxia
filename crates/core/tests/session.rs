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
use veil_core::store::{KvBackend, MemoryBackend, Write};

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

/// A backend whose next `apply` fails (like a full disk), otherwise a `MemoryBackend`.
struct FlakyBackend {
    inner: MemoryBackend,
    fail_next: std::rc::Rc<std::cell::Cell<bool>>,
    applies: std::rc::Rc<std::cell::Cell<usize>>,
}

impl KvBackend for FlakyBackend {
    fn get(&self, key: &[u8]) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, CoreError> {
        self.inner.get(key)
    }
    fn keys_with_prefix(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, CoreError> {
        self.inner.keys_with_prefix(prefix)
    }
    fn apply(&mut self, batch: &[Write]) -> Result<(), CoreError> {
        self.applies.set(self.applies.get() + 1);
        if self.fail_next.replace(false) {
            return Err(CoreError::Storage);
        }
        self.inner.apply(batch)
    }
}

/// Review round 1, H2 (INV-STATE-1): a storage failure while committing the acceptance of
/// an invite leaves no trace. The old per-key commit had already consumed the invite and
/// recorded the peer, so the retry failed and the contact was broken for good.
#[test]
fn failed_commit_changes_nothing_and_retry_succeeds() {
    block_on(async {
        let alice = account();
        let fail = std::rc::Rc::new(std::cell::Cell::new(false));
        let applies = std::rc::Rc::new(std::cell::Cell::new(0));
        let bob = Account::create(
            FlakyBackend {
                inner: MemoryBackend::new(),
                fail_next: fail.clone(),
                applies: applies.clone(),
            },
            &mut rng(),
        )
        .unwrap();
        let created = bob
            .create_invite(
                &mut rng(),
                InviteMode::Remote,
                "wss://r",
                [3; 32],
                [1; 32],
                [2; 32],
                NOW,
                3600,
            )
            .await
            .unwrap();
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
        let snapshot = {
            let be = bob.into_backend();
            let snap = be.inner.clone();
            (snap, Account::load(be).unwrap())
        };
        let (before, bob) = snapshot;

        fail.set(true);
        assert_eq!(
            bob.open(&mut rng(), &red.envelope, NOW).await.unwrap_err(),
            CoreError::Storage
        );
        let bob = {
            let be = bob.into_backend();
            assert!(be.inner == before, "a failed commit left partial state");
            Account::load(be).unwrap()
        };
        // The same envelope now succeeds and yields a working contact in both directions.
        // Its many writes (session, peer, invite and prekey deletions) reach the backend as
        // exactly one atomic batch.
        let calls = applies.get();
        assert!(matches!(
            bob.open(&mut rng(), &red.envelope, NOW).await.unwrap(),
            Opened::NewContact { .. }
        ));
        assert_eq!(applies.get(), calls + 1, "one transaction must be one batch");
        let env = bob
            .seal(&mut rng(), &alice.identity().address(), &text("after"), NOW)
            .await
            .unwrap();
        match alice.open(&mut rng(), &env, NOW).await.unwrap() {
            Opened::Message { content, .. } => assert_eq!(body(&content), "after"),
            other @ Opened::NewContact { .. } => panic!("unexpected {other:?}"),
        }
        let env = alice
            .seal(&mut rng(), &bob.identity().address(), &text("back"), NOW)
            .await
            .unwrap();
        match bob.open(&mut rng(), &env, NOW).await.unwrap() {
            Opened::Message { content, .. } => assert_eq!(body(&content), "back"),
            other @ Opened::NewContact { .. } => panic!("unexpected {other:?}"),
        }
    });
}

/// Review round 1, M2: no protobuf type prints its fields. prost's derived `Debug` printed
/// message text, tokens, proofs, attachment keys and invite secrets (re-key links).
#[test]
fn debug_output_never_contains_content_or_secrets() {
    use veil_core::content::{Attachment, ContactIntro, RekeyInvite};
    let (alice, bob, _) = paired();
    let canary = "CANARY-7f3a91";
    let env = send(&alice, &bob, canary);
    let opened = block_on(bob.open(&mut rng(), &env, NOW)).unwrap();
    let printed = format!("{opened:?} {opened:#?}");
    assert!(!printed.contains(canary), "{printed}");
    assert!(printed.contains("Content(<redacted>)"), "{printed}");

    let intro = ContactIntro {
        mailbox_id: vec![0xA1; 32],
        delivery_token: vec![0xB2; 32],
        display_name: Some(canary.into()),
        invite_id: Some(vec![0xC3; 16]),
        invite_proof: Some(vec![0xD4; 32]),
        rekey: Some(RekeyInvite {
            link: format!("veil://i/{canary}"),
            ..Default::default()
        }),
    };
    let att = Attachment {
        key: vec![0xE5; 32],
        file_name: Some(canary.into()),
        ..Default::default()
    };
    for printed in [
        format!("{intro:?}"),
        format!("{att:#?}"),
        format!("{:?}", text(canary)),
    ] {
        assert!(!printed.contains(canary), "{printed}");
        for byte in ["161", "178", "195", "212", "229", "a1", "b2", "e5"] {
            assert!(!printed.contains(byte), "{printed}");
        }
        assert!(printed.ends_with("(<redacted>)"), "{printed}");
    }
}

// ---------------------------------------------------------------------------------------
// Hand-built hostile envelopes, using libsignal's public API directly (review round 1, M3).
// ---------------------------------------------------------------------------------------

mod forged {
    use super::*;
    use libsignal_protocol::{
        CiphertextMessageType, ContentHint, DeviceId, IdentityKey, IdentityKeyPair, IdentityKeyStore as _,
        InMemSignalProtocolStore, KeyPair, PreKeySignalMessage, ProtocolAddress, SenderCertificate,
        ServerCertificate, SignalMessage, Timestamp, UnidentifiedSenderMessageContent,
        sealed_sender_encrypt_from_usmc,
    };

    pub fn pair_of(acc: &Acc) -> IdentityKeyPair {
        IdentityKeyPair::try_from(&acc.identity().to_secret_bytes()[..]).unwrap()
    }

    /// A self-issued certificate exactly like Veil's: `subject` is named, `signer_root` signs.
    pub fn cert(subject: &IdentityKeyPair, signer_root: &IdentityKeyPair) -> SenderCertificate {
        let name = veil_core::identity::Address::of(subject.identity_key());
        cert_named(name.as_str(), subject, signer_root)
    }

    pub fn cert_named(
        name: &str,
        subject: &IdentityKeyPair,
        signer_root: &IdentityKeyPair,
    ) -> SenderCertificate {
        let mut r = rng();
        let signer = KeyPair::generate(&mut r);
        let server = ServerCertificate::new(1, signer.public_key, signer_root.private_key(), &mut r).unwrap();
        SenderCertificate::new(
            name.to_owned(),
            None,
            *subject.public_key(),
            DeviceId::new(1).unwrap(),
            Timestamp::from_epoch_millis((NOW + 86_400) * 1000),
            server,
            &signer.private_key,
            &mut r,
        )
        .unwrap()
    }

    /// Seals `inner` to `to` with the outer static key `sealer`, filling a bucket exactly.
    pub fn envelope(
        sealer: &IdentityKeyPair,
        to: &Acc,
        cert: &SenderCertificate,
        ty: CiphertextMessageType,
        inner: &[u8],
    ) -> Vec<u8> {
        let mut store = InMemSignalProtocolStore::new(*sealer, 1).unwrap();
        let dest = ProtocolAddress::new(
            to.identity().address().as_str().to_owned(),
            DeviceId::new(1).unwrap(),
        );
        block_on(store.save_identity(&dest, &ik(to))).unwrap();
        let seal = |hint, filler: Option<usize>| {
            let usmc = UnidentifiedSenderMessageContent::new(
                ty,
                cert.clone(),
                inner.to_vec(),
                hint,
                filler.map(|n| vec![0; n]),
            )
            .unwrap();
            block_on(sealed_sender_encrypt_from_usmc(&dest, &usmc, &store, &mut rng())).unwrap()
        };
        let base = seal(ContentHint::Default, None).len();
        for bucket in [1024usize, 4096, 16_384, 65_536] {
            for hint in [ContentHint::Default, ContentHint::Implicit] {
                for filler in (bucket - 1).saturating_sub(base + 6)..=(bucket - 1).saturating_sub(base) {
                    let s = seal(hint, Some(filler));
                    if s.len() + 1 == bucket {
                        let mut env = vec![veil_core::envelope::VERSION];
                        env.extend_from_slice(&s);
                        return env;
                    }
                }
            }
        }
        panic!("no bucket fits");
    }

    pub fn ik(acc: &Acc) -> IdentityKey {
        *acc.identity().public()
    }

    /// Asserts `env` is refused with `want` and leaves the recipient's state untouched.
    pub fn refused(at: Acc, env: &[u8], want: Option<CoreError>) -> Acc {
        let before = at.into_backend();
        let at = Account::load(before.clone()).unwrap();
        let err = block_on(at.open(&mut rng(), env, NOW)).unwrap_err();
        if let Some(want) = want {
            assert_eq!(err, want);
        }
        let after = at.into_backend();
        assert!(after == before, "state changed by a refused envelope");
        Account::load(after).unwrap()
    }

    pub fn v3_message(from: &Acc, to: &Acc) -> SignalMessage {
        message_v(3, from, to)
    }

    pub fn message_v(version: u8, from: &Acc, to: &Acc) -> SignalMessage {
        SignalMessage::new(
            version,
            &[7; 32],
            None,
            KeyPair::generate(&mut rng()).public_key,
            0,
            0,
            &[0x55; 32],
            &ik(from),
            &ik(to),
            &[],
        )
        .unwrap()
    }

    /// A well-formed v4 `PreKey` message (with a Kyber payload) that matches none of our invites.
    pub fn prekey_with_kyber(from: &Acc, to: &Acc) -> Option<PreKeySignalMessage> {
        let inner = SignalMessage::new(
            4,
            &[7; 32],
            None,
            KeyPair::generate(&mut rng()).public_key,
            0,
            0,
            &[0x55; 32],
            &ik(from),
            &ik(to),
            &[],
        )
        .unwrap();
        PreKeySignalMessage::new(
            4,
            1,
            Some(12_345.into()),
            67_890.into(),
            Some(libsignal_protocol::KyberPayload::new(
                4_242.into(),
                vec![0x33; 1569].into_boxed_slice(),
            )),
            KeyPair::generate(&mut rng()).public_key,
            ik(from),
            inner,
        )
        .ok()
    }

    pub fn prekey_without_kyber(from: &Acc, to: &Acc) -> Option<PreKeySignalMessage> {
        let inner = SignalMessage::new(
            4,
            &[7; 32],
            None,
            KeyPair::generate(&mut rng()).public_key,
            0,
            0,
            &[0x55; 32],
            &ik(from),
            &ik(to),
            &[],
        )
        .unwrap();
        PreKeySignalMessage::new(
            4,
            1,
            Some(1.into()),
            1.into(),
            None,
            KeyPair::generate(&mut rng()).public_key,
            ik(from),
            inner,
        )
        .ok()
    }
}

/// INV-CRY-3: a legitimate contact (valid certificate, valid sealing) sending a version-3
/// message, or a `PreKey` message without a Kyber prekey, is refused before decryption.
#[test]
fn downgraded_messages_refused() {
    use libsignal_protocol::CiphertextMessageType;
    let (alice, bob, _) = paired();
    let a = forged::pair_of(&alice);
    let cert = forged::cert(&a, &a);
    let v3 = forged::v3_message(&alice, &bob);
    let env = forged::envelope(&a, &bob, &cert, CiphertextMessageType::Whisper, v3.serialized());
    let bob = forged::refused(bob, &env, Some(CoreError::UnsupportedVersion));
    // libsignal's parser already refuses this ("Kyber pre key must be present"), before Veil's
    // own `kyber_pre_key_id().is_none()` check (defence in depth). If libsignal ever stops
    // even constructing one, that is an equally good outcome.
    if let Some(pk) = forged::prekey_without_kyber(&alice, &bob) {
        let env = forged::envelope(&a, &bob, &cert, CiphertextMessageType::PreKey, pk.serialized());
        forged::refused(bob, &env, Some(CoreError::AuthFailed));
    }
    // Control: the same path with a genuine message still works.
    let (alice, bob, _) = paired();
    assert_eq!(recv(&bob, &send(&alice, &bob, "ok")).unwrap().1, "ok");
}

/// INV-MSG-6: the certificate's key must equal the outer static key that sealed the message.
/// Mallory seals with her own key but presents a genuine certificate for Alice.
#[test]
fn certificate_key_must_match_sealing_key() {
    use libsignal_protocol::CiphertextMessageType;
    let (alice, bob, _) = paired();
    let mallory = account();
    let (a, m) = (forged::pair_of(&alice), forged::pair_of(&mallory));
    let v4 = forged::v3_message(&alice, &bob); // content is irrelevant: refused before decryption
    let alice_cert = forged::cert(&a, &a);
    let env = forged::envelope(
        &m,
        &bob,
        &alice_cert,
        CiphertextMessageType::Whisper,
        v4.serialized(),
    );
    // libsignal: "sender certificate key does not match message key".
    let bob = forged::refused(bob, &env, Some(CoreError::AuthFailed));
    // A certificate for Mallory's key but signed under another root fails validation.
    let wrong_root = forged::cert(&m, &a);
    let env = forged::envelope(
        &m,
        &bob,
        &wrong_root,
        CiphertextMessageType::Whisper,
        v4.serialized(),
    );
    let bob = forged::refused(bob, &env, Some(CoreError::AuthFailed));
    // A certificate naming Alice's address over Mallory's own key fails the address check.
    let impostor = forged::cert_named(alice.identity().address().as_str(), &m, &m);
    let env = forged::envelope(
        &m,
        &bob,
        &impostor,
        CiphertextMessageType::Whisper,
        v4.serialized(),
    );
    forged::refused(bob, &env, Some(CoreError::AuthFailed));
}

/// INV-MSG-7 (review L7): with a *valid* self-issued certificate and correct sealing, a
/// stranger is still dropped (both message types), and so is a message sealed to ourselves.
#[test]
fn strangers_and_self_addressed_envelopes_dropped() {
    use libsignal_protocol::CiphertextMessageType;
    let (alice, bob, _) = paired();
    let mallory = account();
    let m = forged::pair_of(&mallory);
    let v4 = forged::message_v(4, &mallory, &bob);
    let env = forged::envelope(
        &m,
        &bob,
        &forged::cert(&m, &m),
        CiphertextMessageType::Whisper,
        v4.serialized(),
    );
    let bob = forged::refused(bob, &env, Some(CoreError::UnknownSender));
    let pk = forged::prekey_with_kyber(&mallory, &bob).expect("libsignal builds a v4 PreKey message");
    {
        let env = forged::envelope(
            &m,
            &bob,
            &forged::cert(&m, &m),
            CiphertextMessageType::PreKey,
            pk.serialized(),
        );
        forged::refused(bob, &env, Some(CoreError::UnknownSender));
    }
    // Alice seals to herself with her own key and certificate.
    let a = forged::pair_of(&alice);
    let v = forged::v3_message(&alice, &alice);
    let env = forged::envelope(
        &a,
        &alice,
        &forged::cert(&a, &a),
        CiphertextMessageType::Whisper,
        v.serialized(),
    );
    forged::refused(alice, &env, Some(CoreError::AuthFailed));
}

/// INV-MSG-1 (review L7): every `Body` variant, and every `CallKind`, survives
/// validate → encode → pad → encrypt → seal → frame → unframe → unseal → decrypt → unpad →
/// strict decode unchanged.
#[test]
fn every_body_variant_roundtrips() {
    use veil_core::content::{
        Attachment, Call, CallKind, ContactIntro, Delete, Edit, IceCandidates, MailboxUpdate, Reaction,
        Receipt, ReceiptKind, SessionReset, TimerUpdate, Typing,
    };
    let (alice, bob, _) = paired();
    let id = || random_id(&mut rng()).clone();
    let call = |kind| {
        Body::Call(Call {
            call_id: id(),
            kind: Some(kind),
        })
    };
    let bodies = vec![
        Body::Text(Text {
            body: "héllo ✓".into(),
            reply_to: Some(id()),
            expire_timer_secs: Some(3600),
        }),
        Body::Reaction(Reaction {
            target_id: id(),
            emoji: "👍🏽".into(),
            ..Default::default()
        }),
        Body::Edit(Edit {
            target_id: id(),
            body: "edited".into(),
        }),
        Body::Delete(Delete { target_id: id() }),
        Body::Attachment(Attachment {
            blob_id: vec![1; 32],
            key: vec![2; 32],
            nonce_prefix: vec![3; 19],
            ciphertext_sha256: vec![4; 32],
            size: 1000,
            padded_size: 1024,
            mime: "audio/ogg".into(),
            file_name: Some("note.ogg".into()),
            thumbnail: Some(vec![5; 100]),
            voice_duration_ms: Some(4200),
            waveform: Some(vec![6; 64]),
            expire_timer_secs: Some(60),
        }),
        Body::Receipt(Receipt {
            kind: ReceiptKind::Read.into(),
            ids: vec![id(), id()],
        }),
        Body::Typing(Typing { started: true }),
        Body::TimerUpdate(TimerUpdate { seconds: 86_400 }),
        call(CallKind::Offer("v=0\r\n".into())),
        call(CallKind::Answer("v=0\r\n".into())),
        call(CallKind::Ice(IceCandidates {
            candidates: vec!["candidate:1 1 udp 1 8.8.4.4 9 typ relay".into()],
        })),
        call(CallKind::Hangup("normal".into())),
        call(CallKind::Busy(true)),
        Body::ContactIntro(ContactIntro {
            mailbox_id: vec![7; 32],
            delivery_token: vec![8; 32],
            display_name: Some("Alice".into()),
            ..Default::default()
        }),
        Body::MailboxUpdate(MailboxUpdate {
            new_mailbox_id: vec![9; 32],
            new_delivery_token: vec![10; 32],
            relay_url: Some("wss://relay.example.org".into()),
        }),
        Body::SessionReset(SessionReset {}),
    ];
    for body in bodies {
        let sent = Content {
            id: id(),
            sent_at_ms: 42,
            body: Some(body),
        };
        sent.validate().unwrap();
        let env = block_on(alice.seal(&mut rng(), &bob.identity().address(), &sent, NOW)).unwrap();
        match block_on(bob.open(&mut rng(), &env, NOW)).unwrap() {
            Opened::Message { content, .. } => assert!(content == sent, "variant did not round-trip"),
            other @ Opened::NewContact { .. } => panic!("unexpected {other:?}"),
        }
    }
}
