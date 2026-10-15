//! Safety numbers (PROTOCOL §5): libsignal `Fingerprint` version 2,
//! 5200 iterations, with Veil addresses as stable identifiers.

use libsignal_protocol::{Fingerprint, IdentityKey, ScannableFingerprint};

use crate::error::{CoreError, Result};
use crate::identity::Address;

const VERSION: u32 = 2;
const ITERATIONS: u32 = 5200;

/// A safety number between us and one contact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyNumber {
    digits: String,
    scannable: Vec<u8>,
}

impl SafetyNumber {
    /// Computes the safety number from both identities.
    pub fn new(local: &Address, local_key: &IdentityKey, remote: &Address, remote_key: &IdentityKey) -> Result<Self> {
        let fp = Fingerprint::new(
            VERSION,
            ITERATIONS,
            local.as_str().as_bytes(),
            local_key,
            remote.as_str().as_bytes(),
            remote_key,
        )
        .map_err(|_| CoreError::Protocol)?;
        let digits = fp.display_string().map_err(|_| CoreError::Protocol)?;
        let scannable = fp.scannable.serialize().map_err(|_| CoreError::Protocol)?;
        if digits.len() != 60 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(CoreError::Protocol);
        }
        Ok(Self { digits, scannable })
    }

    /// 60 digits.
    pub fn digits(&self) -> &str {
        &self.digits
    }

    /// The 12 groups of 5 digits shown in the UI.
    pub fn groups(&self) -> Vec<&str> {
        (0..12).filter_map(|i| self.digits.get(i * 5..i * 5 + 5)).collect()
    }

    /// Bytes to encode in the QR code.
    pub fn scannable(&self) -> &[u8] {
        &self.scannable
    }

    /// Compares a QR code scanned from the other device (constant time inside libsignal).
    /// `Ok(true)` means both sides computed the same safety number.
    pub fn matches_scanned(&self, scanned: &[u8]) -> Result<bool> {
        let ours = ScannableFingerprint::deserialize(&self.scannable).map_err(|_| CoreError::Protocol)?;
        ours.compare(scanned).map_err(|_| CoreError::AuthFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use rand::TryRngCore as _;
    use rand::rngs::OsRng;

    fn pair() -> (Identity, Identity) {
        let mut rng = OsRng.unwrap_err();
        (Identity::generate(&mut rng), Identity::generate(&mut rng))
    }

    fn sn(a: &Identity, b: &Identity) -> SafetyNumber {
        match SafetyNumber::new(&a.address(), a.public(), &b.address(), b.public()) {
            Ok(s) => s,
            Err(e) => panic!("safety number: {e}"),
        }
    }

    #[test]
    fn symmetric_digits_and_cross_scan() {
        let (a, b) = pair();
        let ab = sn(&a, &b);
        let ba = sn(&b, &a);
        assert_eq!(ab.digits(), ba.digits(), "INV-ID-3: both sides see the same number");
        assert_eq!(ab.groups().len(), 12);
        assert_eq!(ab.matches_scanned(ba.scannable()), Ok(true));
        assert_eq!(ba.matches_scanned(ab.scannable()), Ok(true));
    }

    #[test]
    fn changes_when_either_key_changes() {
        let (a, b) = pair();
        let (c, _) = pair();
        let ab = sn(&a, &b);
        assert_ne!(ab.digits(), sn(&a, &c).digits());
        assert_ne!(ab.digits(), sn(&c, &b).digits());
        // A scan of a different pair must not match.
        let cb = sn(&b, &c);
        assert_ne!(ab.matches_scanned(cb.scannable()), Ok(true));
    }

    #[test]
    fn garbage_scan_is_an_error_not_a_match() {
        let (a, b) = pair();
        assert_ne!(sn(&a, &b).matches_scanned(&[0xff; 40]), Ok(true));
    }
}
