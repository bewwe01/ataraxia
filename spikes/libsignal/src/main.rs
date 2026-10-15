//! Spike A: libsignal from an external workspace.
//! Each check prints PASS/FAIL; the process exits non-zero on any failure.
#![forbid(unsafe_code)]

use std::time::SystemTime;

use futures_executor::block_on;
use libsignal_protocol::*;
use rand::TryRngCore as _;
use rand::rngs::OsRng;

struct Party {
    addr: ProtocolAddress,
    store: InMemSignalProtocolStore,
}

fn party(name: &str) -> Party {
    let mut rng = OsRng.unwrap_err();
    let identity = IdentityKeyPair::generate(&mut rng);
    Party {
        addr: ProtocolAddress::new(name.to_owned(), DeviceId::new(1).expect("valid device id")),
        store: InMemSignalProtocolStore::new(identity, 1).expect("store"),
    }
}

/// Publishes a PQXDH bundle: EC one-time prekey + signed prekey + signed Kyber1024 (ML-KEM) prekey.
async fn bundle(p: &mut Party) -> PreKeyBundle {
    let mut rng = OsRng.unwrap_err();
    let ik = p.store.get_identity_key_pair().await.unwrap();
    let otk = KeyPair::generate(&mut rng);
    let spk = KeyPair::generate(&mut rng);
    let kyb = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
    let spk_sig = ik.private_key().calculate_signature(&spk.public_key.serialize(), &mut rng).unwrap();
    let kyb_sig = ik.private_key().calculate_signature(&kyb.public_key.serialize(), &mut rng).unwrap();
    p.store.save_pre_key(7.into(), &PreKeyRecord::new(7.into(), &otk)).await.unwrap();
    p.store
        .save_signed_pre_key(8.into(), &SignedPreKeyRecord::new(8.into(), Timestamp::from_epoch_millis(1), &spk, &spk_sig))
        .await
        .unwrap();
    p.store
        .save_kyber_pre_key(9.into(), &KyberPreKeyRecord::new(9.into(), Timestamp::from_epoch_millis(1), &kyb, &kyb_sig))
        .await
        .unwrap();
    PreKeyBundle::new(
        1,
        DeviceId::new(1).unwrap(),
        Some((7.into(), otk.public_key)),
        8.into(),
        spk.public_key,
        spk_sig.to_vec(),
        9.into(),
        kyb.public_key.clone(),
        kyb_sig.to_vec(),
        *ik.identity_key(),
    )
    .unwrap()
}

async fn enc(from: &mut Party, to: &ProtocolAddress, msg: &[u8]) -> CiphertextMessage {
    let mut rng = OsRng.unwrap_err();
    message_encrypt(msg, to, &from.addr, &mut from.store.session_store, &mut from.store.identity_store, SystemTime::now(), &mut rng)
        .await
        .unwrap()
}

async fn dec(to: &mut Party, from: &ProtocolAddress, ct: &CiphertextMessage) -> Result<Vec<u8>, SignalProtocolError> {
    let mut rng = OsRng.unwrap_err();
    let s = &mut to.store;
    message_decrypt(ct, from, &to.addr, &mut s.session_store, &mut s.identity_store, &mut s.pre_key_store, &s.signed_pre_key_store, &mut s.kyber_pre_key_store, &mut rng).await
}

fn reparse(ct: &CiphertextMessage, bytes: &[u8]) -> Option<CiphertextMessage> {
    match ct {
        CiphertextMessage::SignalMessage(_) => SignalMessage::try_from(bytes).ok().map(CiphertextMessage::SignalMessage),
        CiphertextMessage::PreKeySignalMessage(_) => PreKeySignalMessage::try_from(bytes).ok().map(CiphertextMessage::PreKeySignalMessage),
        _ => None,
    }
}

fn main() {
    let mut failures = 0;
    let mut check = |name: &str, ok: bool, detail: String| {
        println!("{} {name}{}", if ok { "PASS" } else { "FAIL" }, if detail.is_empty() { String::new() } else { format!(" ({detail})") });
        if !ok {
            failures += 1;
        }
    };

    block_on(async {
        let mut alice = party("alice");
        let mut bob = party("bob");
        let b = bundle(&mut bob).await;
        let mut rng = OsRng.unwrap_err();
        let r = process_prekey_bundle(&bob.addr, &alice.addr, &mut alice.store.session_store, &mut alice.store.identity_store, &b, SystemTime::now(), &mut rng).await;
        check("PQXDH: Alice processes Bob's bundle (EC + signed Kyber1024 prekey)", r.is_ok(), format!("{r:?}"));

        // First message is a PreKeySignalMessage carrying the KEM ciphertext.
        let first = enc(&mut alice, &bob.addr, b"hello bob").await;
        let (ver, kem_ct) = match &first {
            CiphertextMessage::PreKeySignalMessage(m) => (m.message_version(), m.kyber_ciphertext().map(|k| k.len()).unwrap_or(0)),
            _ => (0, 0),
        };
        check("first message is PreKeySignalMessage v4+ with ML-KEM ciphertext", ver >= 4 && kem_ct > 0, format!("version {ver}, KEM ciphertext {kem_ct} bytes"));
        let pt = dec(&mut bob, &alice.addr, &first).await;
        check("Bob decrypts first message", pt.as_deref().ok() == Some(&b"hello bob"[..]), String::new());

        // Ping-pong 40 rounds; record SPQR (post-quantum ratchet) payload sizes.
        let mut pq_nonempty = 0;
        let mut all_ok = true;
        for i in 0..40u32 {
            let (from, to) = if i % 2 == 0 { (&mut bob, &mut alice) } else { (&mut alice, &mut bob) };
            let msg = format!("msg {i}");
            let ct = enc(from, &to.addr, msg.as_bytes()).await;
            if let CiphertextMessage::SignalMessage(m) = &ct {
                if !m.pq_ratchet().is_empty() {
                    pq_nonempty += 1;
                }
            }
            all_ok &= dec(to, &from.addr, &ct).await.as_deref().ok() == Some(msg.as_bytes());
        }
        check("40 alternating messages decrypt (Double Ratchet steps)", all_ok, String::new());
        check("SPQR triple ratchet active: post-quantum ratchet data present in messages", pq_nonempty > 0, format!("{pq_nonempty}/40 messages carried SPQR data"));

        // Tamper: flip one bit at every byte position of a SignalMessage; all must be rejected,
        // and the genuine message must still decrypt afterwards (no state corruption).
        let genuine = enc(&mut alice, &bob.addr, b"integrity").await;
        let bytes = genuine.serialize().to_vec();
        let mut rejected = 0;
        for pos in 0..bytes.len() {
            let mut t = bytes.clone();
            t[pos] ^= 0x01;
            match reparse(&genuine, &t) {
                None => rejected += 1,
                Some(ct) => {
                    if dec(&mut bob, &alice.addr, &ct).await.is_err() {
                        rejected += 1;
                    }
                }
            }
        }
        check("bit-flip at every byte of a SignalMessage is rejected", rejected == bytes.len(), format!("{rejected}/{} rejected", bytes.len()));
        let ok_after = dec(&mut bob, &alice.addr, &genuine).await;
        check("genuine message still decrypts after tamper attempts", ok_after.as_deref().ok() == Some(&b"integrity"[..]), String::new());

        // Replay: decrypting the same ciphertext twice must fail.
        let replay = dec(&mut bob, &alice.addr, &genuine).await;
        check("replayed message is rejected", matches!(replay, Err(SignalProtocolError::DuplicatedMessage(..))), format!("{replay:?}"));

        // Out of order: 6 messages delivered in reverse.
        let mut batch = Vec::new();
        for i in 0..6 {
            batch.push((i, enc(&mut alice, &bob.addr, format!("ooo {i}").as_bytes()).await));
        }
        let mut ooo_ok = true;
        for (i, ct) in batch.iter().rev() {
            ooo_ok &= dec(&mut bob, &alice.addr, ct).await.as_deref().ok() == Some(format!("ooo {i}").as_bytes());
        }
        check("out-of-order delivery (reverse order) decrypts", ooo_ok, String::new());

        // Identity change: a bundle signed by a NEW identity for the same address must not be silently accepted.
        let mut bob2 = party("bob");
        let b2 = bundle(&mut bob2).await;
        let r = process_prekey_bundle(&bob.addr, &alice.addr, &mut alice.store.session_store, &mut alice.store.identity_store, &b2, SystemTime::now(), &mut rng).await;
        check("changed identity key is refused (UntrustedIdentity)", matches!(r, Err(SignalProtocolError::UntrustedIdentity(_))), format!("{r:?}"));

        // Bad signature on the Kyber prekey must be rejected.
        let mut carol = party("carol");
        let good = bundle(&mut carol).await;
        let mut sig = good.kyber_pre_key_signature().unwrap().to_vec();
        sig[0] ^= 1;
        let forged = PreKeyBundle::new(
            1, DeviceId::new(1).unwrap(), good.pre_key_id().unwrap().zip(good.pre_key_public().unwrap()),
            good.signed_pre_key_id().unwrap(), good.signed_pre_key_public().unwrap(), good.signed_pre_key_signature().unwrap().to_vec(),
            good.kyber_pre_key_id().unwrap(), good.kyber_pre_key_public().unwrap().clone(), sig, *good.identity_key().unwrap(),
        ).unwrap();
        let r = process_prekey_bundle(&carol.addr, &alice.addr, &mut alice.store.session_store, &mut alice.store.identity_store, &forged, SystemTime::now(), &mut rng).await;
        check("bundle with forged Kyber prekey signature is rejected", r.is_err(), format!("{r:?}"));
    });

    if failures > 0 {
        eprintln!("{failures} check(s) failed");
        std::process::exit(1);
    }
    println!("ALL CHECKS PASSED");
}
