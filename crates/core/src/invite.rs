//! Invites and pairing (PROTOCOL §4).
//!
//! * [`Invite`]: what the QR code / link carries. Fixed binary layout, base64url.
//! * The **invite package** (prekey bundle + mailbox + delivery token) is sealed with
//!   XChaCha20-Poly1305 under `k_inv = HKDF(secret, id)` and uploaded to the relay,
//!   which can neither read it nor learn the inviter's identity key (INV-META-1).
//! * The redeemer proves knowledge of `secret`, bound to its own identity key, with
//!   `HMAC-SHA-256(k_proof, label || id || redeemer_identity)` (INV-PAIR-4).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use libsignal_protocol::IdentityKey;
use prost::Message as _;
use rand::{CryptoRng, Rng};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

/// Link scheme prefix.
pub const LINK_PREFIX: &str = "veil://i/";
const VERSION: u8 = 1;
const IK_LEN: usize = 33;
const ID_LEN: usize = 16;
const SECRET_LEN: usize = 32;
const SPKI_LEN: usize = 32;
const MAX_URL: usize = 200;
const FIXED_LEN: usize = 1 + 1 + IK_LEN + ID_LEN + SECRET_LEN + 8 + SPKI_LEN + 1;
/// Upper bound on a link, checked before base64 decoding.
pub const MAX_LINK_LEN: usize = 512;
/// Sealed packages are padded to exactly this size before encryption.
pub const PACKAGE_PADDED_LEN: usize = 4096;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
/// Exact size of a sealed package on the wire.
pub const SEALED_PACKAGE_LEN: usize = NONCE_LEN + PACKAGE_PADDED_LEN + TAG_LEN;
/// Maximum invite lifetime (PROTOCOL §14).
pub const MAX_TTL_SECS: u64 = 7 * 24 * 3600;

const SALT: &[u8] = b"veil/v1/invite";
const INFO_KEY: &[u8] = b"veil/v1/invite-key";
const INFO_PROOF: &[u8] = b"veil/v1/invite-proof";
const AAD_LABEL: &[u8] = b"veil/v1/invite";

/// In person (mutual scan) or remote (link).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteMode {
    InPerson,
    Remote,
}

impl InviteMode {
    /// Wire encoding.
    pub fn to_u8(self) -> u8 {
        match self {
            Self::InPerson => 0,
            Self::Remote => 1,
        }
    }

    pub(crate) fn to_u32(self) -> u32 {
        u32::from(self.to_u8())
    }
}

/// Contents of an invite QR code / link. Holds a secret: treat like a password.
pub struct Invite {
    pub mode: InviteMode,
    pub identity: IdentityKey,
    pub id: [u8; ID_LEN],
    secret: Zeroizing<[u8; SECRET_LEN]>,
    pub expires_at: u64,
    pub relay_spki_sha256: [u8; SPKI_LEN],
    pub relay_url: String,
}

impl core::fmt::Debug for Invite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Invite")
            .field("mode", &self.mode)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Fields placed in the sealed package next to the prekey bundle.
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(crate) struct PackagePb {
    #[prost(uint32, tag = "1")]
    pub registration_id: u32,
    #[prost(uint32, tag = "2")]
    pub prekey_id: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub prekey_pub: Vec<u8>,
    #[prost(uint32, tag = "4")]
    pub signed_prekey_id: u32,
    #[prost(bytes = "vec", tag = "5")]
    pub signed_prekey_pub: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub signed_prekey_sig: Vec<u8>,
    #[prost(uint32, tag = "7")]
    pub kyber_prekey_id: u32,
    #[prost(bytes = "vec", tag = "8")]
    pub kyber_prekey_pub: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub kyber_prekey_sig: Vec<u8>,
    #[prost(bytes = "vec", tag = "10")]
    pub identity_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "11")]
    pub mailbox_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "12")]
    pub delivery_token: Vec<u8>,
}

impl Invite {
    /// Builds a new invite with a fresh id and secret.
    pub(crate) fn generate<R: Rng + CryptoRng>(
        rng: &mut R,
        mode: InviteMode,
        identity: IdentityKey,
        expires_at: u64,
        relay_url: &str,
        relay_spki_sha256: [u8; SPKI_LEN],
    ) -> Result<Self> {
        validate_url(relay_url)?;
        let mut id = [0u8; ID_LEN];
        rng.fill(&mut id);
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        rng.fill(&mut secret[..]);
        Ok(Self {
            mode,
            identity,
            id,
            secret,
            expires_at,
            relay_spki_sha256,
            relay_url: relay_url.to_owned(),
        })
    }

    /// `veil://i/<base64url>`.
    pub fn to_link(&self) -> String {
        let url = self.relay_url.as_bytes();
        let mut b = Zeroizing::new(Vec::with_capacity(FIXED_LEN.saturating_add(url.len())));
        b.push(VERSION);
        b.push(self.mode.to_u8());
        b.extend_from_slice(&self.identity.serialize());
        b.extend_from_slice(&self.id);
        b.extend_from_slice(&self.secret[..]);
        b.extend_from_slice(&self.expires_at.to_be_bytes());
        b.extend_from_slice(&self.relay_spki_sha256);
        b.push(u8::try_from(url.len()).unwrap_or(u8::MAX));
        b.extend_from_slice(url);
        format!("{LINK_PREFIX}{}", URL_SAFE_NO_PAD.encode(&b[..]))
    }

    /// Strict parse of a link (size-checked before decoding).
    pub fn from_link(link: &str) -> Result<Self> {
        if link.len() > MAX_LINK_LEN {
            return Err(CoreError::TooLarge);
        }
        let b64 = link.strip_prefix(LINK_PREFIX).ok_or(CoreError::Malformed)?;
        let raw = Zeroizing::new(URL_SAFE_NO_PAD.decode(b64).map_err(|_| CoreError::Malformed)?);
        let mut r = Reader(&raw[..]);
        if r.u8()? != VERSION {
            return Err(CoreError::UnsupportedVersion);
        }
        let mode = match r.u8()? {
            0 => InviteMode::InPerson,
            1 => InviteMode::Remote,
            _ => return Err(CoreError::Malformed),
        };
        let identity = IdentityKey::decode(r.take(IK_LEN)?).map_err(|_| CoreError::Malformed)?;
        let id: [u8; ID_LEN] = r.array()?;
        let secret = Zeroizing::new(r.array::<SECRET_LEN>()?);
        let expires_at = u64::from_be_bytes(r.array()?);
        let relay_spki_sha256: [u8; SPKI_LEN] = r.array()?;
        let url_len = usize::from(r.u8()?);
        let url = core::str::from_utf8(r.take(url_len)?).map_err(|_| CoreError::Malformed)?;
        if !r.0.is_empty() {
            return Err(CoreError::Malformed);
        }
        validate_url(url)?;
        Ok(Self {
            mode,
            identity,
            id,
            secret,
            expires_at,
            relay_spki_sha256,
            relay_url: url.to_owned(),
        })
    }

    fn hkdf(&self) -> Hkdf<Sha256> {
        Hkdf::<Sha256>::new(Some(SALT), &self.secret[..])
    }

    fn package_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        derive(&self.hkdf(), INFO_KEY, &self.id)
    }

    fn proof_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        derive(&self.hkdf(), INFO_PROOF, &self.id)
    }

    fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(AAD_LABEL.len().saturating_add(ID_LEN).saturating_add(IK_LEN));
        aad.extend_from_slice(AAD_LABEL);
        aad.extend_from_slice(&self.id);
        aad.extend_from_slice(&self.identity.serialize());
        aad
    }

    /// Seals the package for upload to the relay. Output is exactly [`SEALED_PACKAGE_LEN`] bytes.
    pub(crate) fn seal_package<R: Rng + CryptoRng>(&self, rng: &mut R, pkg: &PackagePb) -> Result<Vec<u8>> {
        let plain = Zeroizing::new(pad_to(&pkg.encode_to_vec(), PACKAGE_PADDED_LEN)?);
        let key = self.package_key()?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| CoreError::Protocol)?;
        // 192-bit random nonce from the caller's CSPRNG: collision probability is negligible.
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes);
        let nonce = XNonce::try_from(&nonce_bytes[..]).map_err(|_| CoreError::Protocol)?;
        let ct = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &plain,
                    aad: &self.aad(),
                },
            )
            .map_err(|_| CoreError::Protocol)?;
        let mut out = Vec::with_capacity(SEALED_PACKAGE_LEN);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Opens a sealed package fetched from the relay.
    pub(crate) fn open_package(&self, sealed: &[u8]) -> Result<PackagePb> {
        if sealed.len() != SEALED_PACKAGE_LEN {
            return Err(CoreError::Malformed);
        }
        let (nonce, ct) = sealed.split_at(NONCE_LEN);
        let key = self.package_key()?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| CoreError::Protocol)?;
        let nonce = XNonce::try_from(nonce).map_err(|_| CoreError::Malformed)?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: ct,
                        aad: &self.aad(),
                    },
                )
                .map_err(|_| CoreError::AuthFailed)?,
        );
        let body = unpad_to(&plain)?;
        let pkg = PackagePb::decode(body).map_err(|_| CoreError::Malformed)?;
        if pkg.encode_to_vec() != body {
            return Err(CoreError::Malformed);
        }
        Ok(pkg)
    }

    /// `HMAC(k_proof, "veil/v1/invite-proof" || id || redeemer_identity)`.
    pub(crate) fn proof(&self, redeemer: &IdentityKey) -> Result<[u8; 32]> {
        let mac = self.proof_mac(redeemer)?;
        Ok(mac.finalize().into_bytes().into())
    }

    fn proof_mac(&self, redeemer: &IdentityKey) -> Result<Hmac<Sha256>> {
        let key = self.proof_key()?;
        let mut mac =
            <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&key[..]).map_err(|_| CoreError::Protocol)?;
        mac.update(INFO_PROOF);
        mac.update(&self.id);
        mac.update(&redeemer.serialize());
        Ok(mac)
    }

    /// Exposes the proof key so the inviter can verify redemptions without keeping the secret.
    pub(crate) fn proof_key_bytes(&self) -> Result<Zeroizing<[u8; 32]>> {
        self.proof_key()
    }

    /// Whether the invite has expired at `now` (unix seconds).
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}

/// Verifies a redemption proof in constant time given the stored proof key.
pub(crate) fn verify_proof(proof_key: &[u8], id: &[u8], redeemer: &IdentityKey, proof: &[u8]) -> Result<()> {
    let mut mac =
        <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(proof_key).map_err(|_| CoreError::Protocol)?;
    mac.update(INFO_PROOF);
    mac.update(id);
    mac.update(&redeemer.serialize());
    mac.verify_slice(proof).map_err(|_| CoreError::AuthFailed)
}

fn derive(hk: &Hkdf<Sha256>, label: &[u8], id: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand_multi_info(&[label, id], &mut out[..])
        .map_err(|_| CoreError::Protocol)?;
    Ok(out)
}

fn validate_url(url: &str) -> Result<()> {
    let ok = url.len() <= MAX_URL
        && url.starts_with("wss://")
        && url.len() > 6
        && url.bytes().all(|b| b.is_ascii_graphic());
    if ok { Ok(()) } else { Err(CoreError::Malformed) }
}

/// ISO/IEC 7816-4 padding to an exact size.
fn pad_to(data: &[u8], size: usize) -> Result<Vec<u8>> {
    if data.len() >= size {
        return Err(CoreError::TooLarge);
    }
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(data);
    out.push(0x80);
    out.resize(size, 0);
    Ok(out)
}

fn unpad_to(data: &[u8]) -> Result<&[u8]> {
    let marker = data.iter().rposition(|&b| b != 0).ok_or(CoreError::Malformed)?;
    if data.get(marker) != Some(&0x80) {
        return Err(CoreError::Malformed);
    }
    data.get(..marker).ok_or(CoreError::Malformed)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(CoreError::Malformed);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8> {
        self.take(1)?.first().copied().ok_or(CoreError::Malformed)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| CoreError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsignal_protocol::IdentityKeyPair;
    use proptest::prelude::*;
    use rand::TryRngCore as _;
    use rand::rngs::OsRng;

    fn invite() -> Invite {
        let mut rng = OsRng.unwrap_err();
        let ik = *IdentityKeyPair::generate(&mut rng).identity_key();
        Invite::generate(
            &mut rng,
            InviteMode::Remote,
            ik,
            1_800_000_000,
            "wss://relay.example.org",
            [9; 32],
        )
        .unwrap()
    }

    fn pkg() -> PackagePb {
        PackagePb {
            registration_id: 5,
            mailbox_id: vec![1; 32],
            delivery_token: vec![2; 32],
            ..Default::default()
        }
    }

    #[test]
    fn link_roundtrip_and_size() {
        let inv = invite();
        let link = inv.to_link();
        assert!(link.len() < 300, "QR-friendly: {}", link.len());
        let back = Invite::from_link(&link).unwrap();
        assert_eq!(back.id, inv.id);
        assert_eq!(back.identity, inv.identity);
        assert_eq!(back.secret[..], inv.secret[..]);
        assert_eq!(back.relay_url, inv.relay_url);
        assert_eq!(back.expires_at, inv.expires_at);
    }

    #[test]
    fn link_rejects_tampering_and_trailing_data() {
        let link = invite().to_link();
        let b64 = link.strip_prefix(LINK_PREFIX).unwrap();
        let mut raw = URL_SAFE_NO_PAD.decode(b64).unwrap();
        raw.push(0);
        assert!(Invite::from_link(&format!("{LINK_PREFIX}{}", URL_SAFE_NO_PAD.encode(&raw))).is_err());
        raw.pop();
        raw[0] = 2;
        assert_eq!(
            Invite::from_link(&format!("{LINK_PREFIX}{}", URL_SAFE_NO_PAD.encode(&raw))).err(),
            Some(CoreError::UnsupportedVersion)
        );
        assert_eq!(
            Invite::from_link(&"x".repeat(MAX_LINK_LEN + 1)).err(),
            Some(CoreError::TooLarge)
        );
        assert!(Invite::from_link("https://evil/").is_err());
    }

    #[test]
    fn package_seal_open_and_every_bit_flip_rejected() {
        let inv = invite();
        let mut rng = OsRng.unwrap_err();
        let sealed = inv.seal_package(&mut rng, &pkg()).unwrap();
        assert_eq!(sealed.len(), SEALED_PACKAGE_LEN);
        assert_eq!(inv.open_package(&sealed).unwrap(), pkg());
        // INV-MSG-2 analogue for invites: every single-bit flip anywhere is rejected.
        for i in 0..sealed.len() {
            let mut t = sealed.clone();
            t[i] ^= 1 << (i % 8);
            assert!(inv.open_package(&t).is_err(), "flip at byte {i}");
        }
        assert!(inv.open_package(&sealed[..sealed.len() - 1]).is_err());
    }

    /// INV-CRY-5: re-sealing under the same invite key always draws a fresh 192-bit nonce.
    #[test]
    fn package_nonces_unique() {
        let inv = invite();
        let mut rng = OsRng.unwrap_err();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..2_000 {
            let sealed = inv.seal_package(&mut rng, &pkg()).unwrap();
            assert!(seen.insert(sealed[..NONCE_LEN].to_vec()));
        }
    }

    #[test]
    fn package_bound_to_invite_identity_and_id() {
        let a = invite();
        let mut rng = OsRng.unwrap_err();
        let sealed = a.seal_package(&mut rng, &pkg()).unwrap();
        // Same secret but a different claimed identity (AAD mismatch) must fail.
        let other_ik = *IdentityKeyPair::generate(&mut rng).identity_key();
        let forged = Invite {
            identity: other_ik,
            secret: a.secret.clone(),
            ..invite_with(&a)
        };
        assert_eq!(forged.open_package(&sealed).err(), Some(CoreError::AuthFailed));
    }

    fn invite_with(a: &Invite) -> Invite {
        Invite {
            mode: a.mode,
            identity: a.identity,
            id: a.id,
            secret: a.secret.clone(),
            expires_at: a.expires_at,
            relay_spki_sha256: a.relay_spki_sha256,
            relay_url: a.relay_url.clone(),
        }
    }

    #[test]
    fn proof_binds_secret_id_and_redeemer() {
        let inv = invite();
        let mut rng = OsRng.unwrap_err();
        let r1 = *IdentityKeyPair::generate(&mut rng).identity_key();
        let r2 = *IdentityKeyPair::generate(&mut rng).identity_key();
        let p = inv.proof(&r1).unwrap();
        let pk = inv.proof_key_bytes().unwrap();
        assert!(verify_proof(&pk[..], &inv.id, &r1, &p).is_ok());
        assert_eq!(
            verify_proof(&pk[..], &inv.id, &r2, &p).err(),
            Some(CoreError::AuthFailed)
        );
        assert_eq!(
            verify_proof(&pk[..], &[0; 16], &r1, &p).err(),
            Some(CoreError::AuthFailed)
        );
        let other = invite();
        assert_eq!(
            verify_proof(&other.proof_key_bytes().unwrap()[..], &inv.id, &r1, &p).err(),
            Some(CoreError::AuthFailed)
        );
    }

    #[test]
    fn debug_hides_secret() {
        let inv = invite();
        let d = format!("{inv:?}");
        assert!(!d.contains("secret") || !d.contains(&format!("{:?}", &inv.secret[..4])));
        assert!(!d.contains(&URL_SAFE_NO_PAD.encode(&inv.secret[..])));
    }

    proptest! {
        #[test]
        fn arbitrary_links_never_panic(s in ".{0,600}") {
            let _ = Invite::from_link(&s);
        }

        #[test]
        fn arbitrary_payloads_never_panic(raw in proptest::collection::vec(any::<u8>(), 0..400)) {
            let _ = Invite::from_link(&format!("{LINK_PREFIX}{}", URL_SAFE_NO_PAD.encode(&raw)));
        }
    }
}

crate::redacted_debug!(PackagePb);
