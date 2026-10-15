//! INV-REST-4: secret-bearing APIs return self-wiping types, and secret types never
//! print their contents. (Whether freed memory is actually wiped cannot be observed
//! from safe Rust; that guarantee is delegated to the `zeroize` crate.)
// Test-only crate.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
use rand::TryRngCore as _;
use rand::rngs::OsRng;
use veil_core::attachment::AttachmentKey;
use veil_core::identity::Identity;
use veil_core::vault::{self, KdfParams};
use zeroize::Zeroizing;

/// Compile-time assertions: if any of these APIs stopped returning `Zeroizing`, this test
/// would fail to build.
#[test]
fn secret_apis_return_self_wiping_types() {
    let mut rng = OsRng.unwrap_err();
    let id = Identity::generate(&mut rng);
    let _wiped: Zeroizing<Vec<u8>> = id.to_secret_bytes();
    let k = AttachmentKey::generate(&mut rng);
    let _: &[u8; 32] = k.key_bytes(); // borrowed view only; owner wipes on drop
}

#[test]
fn secret_types_redact_debug() {
    let mut rng = OsRng.unwrap_err();
    // External callers cannot go below the Argon2id floor (enforced by `vault::create`).
    let (_, db) = vault::create(&mut rng, b"pw", &[0; 32], KdfParams::FLOOR).unwrap();
    let key_hex = hex(db.expose());
    let printed = format!("{db:?}");
    assert!(!printed.contains(&key_hex[..8]));
    assert_eq!(printed, "DbKey(<redacted>)");
    assert_eq!(
        format!("{:?}", AttachmentKey::generate(&mut rng)),
        "AttachmentKey(<redacted>)"
    );
    let id = Identity::generate(&mut rng);
    let secret_hex = hex(&id.to_secret_bytes());
    assert!(!format!("{id:?}").contains(&secret_hex[..16]));
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[test]
fn kdf_floor_enforced_for_external_callers() {
    let weak = KdfParams {
        m_kib: 1024,
        t: 1,
        p: 1,
    };
    assert!(vault::create(&mut OsRng.unwrap_err(), b"pw", &[0; 32], weak).is_err());
}
