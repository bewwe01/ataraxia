//! Short-lived TURN credentials for coturn's `use-auth-secret` mode (PROTOCOL §8).
//!
//! `username = "<expiry unix secs>:<16 random hex>"`, `credential = base64(HMAC-SHA1(secret,
//! username))`. HMAC-SHA1 is what coturn implements (TURN REST API); it is a MAC here, not a
//! signature, and HMAC-SHA1 remains a secure PRF. The username contains no identity and no
//! mailbox id.

use base64::Engine as _;
use hmac::{KeyInit as _, Mac as _};
use rand::{CryptoRng, Rng};
use zeroize::Zeroizing;

pub struct TurnConfig {
    pub secret: Zeroizing<Vec<u8>>,
    pub urls: Vec<String>,
    pub ttl_secs: u32,
}

impl core::fmt::Debug for TurnConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TurnConfig")
            .field("urls", &self.urls)
            .field("ttl_secs", &self.ttl_secs)
            .finish_non_exhaustive()
    }
}

/// Returns `(username, credential)`.
pub fn credentials<R: Rng + CryptoRng>(cfg: &TurnConfig, now: u64, rng: &mut R) -> Option<(String, String)> {
    let mut nonce = [0u8; 8];
    rng.fill(&mut nonce);
    let hex = crate::tls::hex(&nonce);
    let username = format!("{}:{hex}", now.saturating_add(u64::from(cfg.ttl_secs)));
    let mut mac = <hmac::Hmac<sha1::Sha1>>::new_from_slice(&cfg.secret).ok()?;
    mac.update(username.as_bytes());
    let credential = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    Some((username, credential))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The username format, and that the credential is HMAC-SHA1 over exactly that username.
    /// (The primitive itself is pinned by the RFC 2202 vector below.)
    #[test]
    fn format_and_mac() {
        let cfg = TurnConfig {
            secret: Zeroizing::new(b"secret".to_vec()),
            urls: vec![],
            ttl_secs: 3600,
        };
        let (u, c) = credentials(&cfg, 1_700_000_000, &mut rand::rng()).unwrap();
        let (exp, hex) = u.split_once(':').unwrap();
        assert_eq!(exp, "1700003600");
        assert_eq!(hex.len(), 16);
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
        let mut mac = <hmac::Hmac<sha1::Sha1>>::new_from_slice(b"secret").unwrap();
        mac.update(u.as_bytes());
        assert_eq!(
            c,
            base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
        );
    }

    /// RFC 2202 test case 2 for HMAC-SHA1 ("Jefe" / "what do ya want for nothing?").
    #[test]
    fn hmac_sha1_rfc2202() {
        let mut mac = <hmac::Hmac<sha1::Sha1>>::new_from_slice(b"Jefe").unwrap();
        mac.update(b"what do ya want for nothing?");
        let hex = crate::tls::hex(&mac.finalize().into_bytes());
        assert_eq!(hex, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
    }
}
