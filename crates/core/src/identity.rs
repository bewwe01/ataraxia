//! Identity keys and key-derived addresses (PROTOCOL §1).
//!
//! An [`Address`] is derived from an identity key, so Veil has no usernames,
//! phone numbers or directory (INV-ID-1).

use core::fmt;

use libsignal_protocol::{IdentityKey, IdentityKeyPair};
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

const ADDR_LABEL: &[u8] = b"veil/v1/addr";
const FP_LABEL: &[u8] = b"veil/v1/fp";
const ADDR_PREFIX: &str = "v1:";
const ADDR_HEX_LEN: usize = 40;

/// A peer's address: `"v1:" || hex(SHA-256("veil/v1/addr" || identity_pub))[0..40]`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address(String);

impl Address {
    /// Derives the address of an identity key.
    pub fn of(identity: &IdentityKey) -> Self {
        let digest = Sha256::new()
            .chain_update(ADDR_LABEL)
            .chain_update(identity.serialize())
            .finalize();
        let mut hex = to_hex(&digest);
        hex.truncate(ADDR_HEX_LEN);
        Self(format!("{ADDR_PREFIX}{hex}"))
    }

    /// Parses an address string, accepting only the canonical form.
    pub fn parse(s: &str) -> Result<Self> {
        let hex = s.strip_prefix(ADDR_PREFIX).ok_or(CoreError::Malformed)?;
        if hex.len() != ADDR_HEX_LEN || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(CoreError::Malformed);
        }
        Ok(Self(s.to_owned()))
    }

    /// The canonical string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Addresses are not secret, but keep logs short and uniform.
        write!(f, "Address({}…)", self.0.get(..11).unwrap_or(""))
    }
}

/// Our long-term identity. The private half never leaves this type except via
/// [`Identity::to_secret_bytes`] (for the encrypted vault / backup).
pub struct Identity {
    pair: IdentityKeyPair,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("address", &self.address())
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// Generates a fresh identity on this device.
    pub fn generate<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self {
            pair: IdentityKeyPair::generate(rng),
        }
    }

    /// Restores an identity from [`Identity::to_secret_bytes`] output.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        IdentityKeyPair::try_from(bytes)
            .map(|pair| Self { pair })
            .map_err(|_| CoreError::Malformed)
    }

    /// Serialized key pair, wiped from memory on drop. Store only inside the vault.
    pub fn to_secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.pair.serialize().into_vec())
    }

    /// Public identity key.
    pub fn public(&self) -> &IdentityKey {
        self.pair.identity_key()
    }

    /// Our address.
    pub fn address(&self) -> Address {
        Address::of(self.public())
    }

    /// Short display fingerprint ("7F3A 91C2 …"): first 16 bytes of
    /// `SHA-256("veil/v1/fp" || identity_pub)` as 8 groups of 4 hex digits.
    /// For display only; verification uses safety numbers.
    pub fn display_fingerprint(&self) -> String {
        display_fingerprint(self.public())
    }

    pub(crate) fn key_pair(&self) -> &IdentityKeyPair {
        &self.pair
    }
}

/// See [`Identity::display_fingerprint`].
pub fn display_fingerprint(key: &IdentityKey) -> String {
    let digest = Sha256::new()
        .chain_update(FP_LABEL)
        .chain_update(key.serialize())
        .finalize();
    let hex = to_hex(digest.get(..16).unwrap_or(&[])).to_ascii_uppercase();
    hex.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        s.push(char::from(HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0')));
        s.push(char::from(
            HEX.get(usize::from(b & 0x0f)).copied().unwrap_or(b'0'),
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::TryRngCore as _;
    use rand::rngs::OsRng;

    #[test]
    fn address_is_deterministic_and_canonical() {
        let id = Identity::generate(&mut OsRng.unwrap_err());
        let a = id.address();
        assert_eq!(a, Address::of(id.public()));
        assert_eq!(Address::parse(a.as_str()).ok(), Some(a.clone()));
        assert_eq!(a.as_str().len(), 43);
    }

    #[test]
    fn address_parse_rejects_noncanonical() {
        for bad in [
            "",
            "v1:",
            "v2:0000000000000000000000000000000000000000",
            "v1:000000000000000000000000000000000000000",
            "v1:00000000000000000000000000000000000000000",
            "v1:000000000000000000000000000000000000000A",
            "v1:000000000000000000000000000000000000000g",
        ] {
            assert_eq!(Address::parse(bad), Err(CoreError::Malformed), "{bad}");
        }
    }

    #[test]
    fn secret_roundtrip() {
        let id = Identity::generate(&mut OsRng.unwrap_err());
        let restored = Identity::from_secret_bytes(&id.to_secret_bytes());
        assert_eq!(restored.map(|r| r.address()).ok(), Some(id.address()));
        assert!(Identity::from_secret_bytes(&[1, 2, 3]).is_err());
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let id = Identity::generate(&mut OsRng.unwrap_err());
        let dbg = format!("{id:?}");
        let secret = id.to_secret_bytes();
        let hexed = to_hex(&secret);
        assert!(!dbg.contains(&hexed));
        assert!(!dbg.contains(&hexed[..16]));
    }

    /// Known-answer vector: fixed identity public key → address and display fingerprint.
    #[test]
    fn address_known_answer() {
        // 0x05 || 32 bytes of 0x01: a syntactically valid Curve25519 public key encoding.
        let mut raw = vec![0x05];
        raw.extend_from_slice(&[0x01; 32]);
        let Ok(key) = IdentityKey::decode(&raw) else {
            panic!("fixture key must decode");
        };
        assert_eq!(Address::of(&key).as_str(), crate::test_vectors::ADDR_OF_05_01X32);
        assert_eq!(display_fingerprint(&key), crate::test_vectors::FP_OF_05_01X32);
    }
}
