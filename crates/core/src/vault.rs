//! Vault key hierarchy for data at rest (PROTOCOL §12, INV-REST-2).
//!
//! ```text
//! pw  = Argon2id(passphrase, salt, m, t, p) → 32 bytes
//! dev = 32-byte secret held by the OS keystore
//! KEK = HKDF-SHA-256(ikm = pw || dev, salt = vault_id, info = "veil/v1/kek")
//! header.wrapped = XChaCha20-Poly1305(KEK, nonce, aad = header fields, DB key)
//! ```
//!
//! Opening requires **both** factors. The header is not secret; tampering with any
//! header field (including the Argon2 parameters) makes unwrapping fail.
//!
//! Two additions (ADR-0012), both derived from the same `pw || dev` input or from a random secret,
//! never from a new primitive:
//!
//! ```text
//! purge_tag = HKDF-SHA-256(ikm = pw || dev, salt = vault_id, info = "veil/v1/purge-tag")
//! skek      = HKDF-SHA-256(ikm = secret || dev, salt = vault_id, info = "veil/v1/secret-kek")
//! wrap      = v || nonce || XChaCha20-Poly1305(skek, nonce, aad = "veil/v1/secret-wrap" || vault_id, DB key)
//! ```
//!
//! The purge tag lets one Argon2id run decide between "this is the passphrase", "this is the
//! Purge PIN" and "wrong". It needs the device secret like the KEK does, so it is no better an
//! offline guessing oracle than the header itself. The secret wrap lets a 256-bit random secret
//! (released by the platform's biometric keystore) open the vault without the passphrase.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::{CryptoRng, Rng};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

const MAGIC: &[u8; 7] = b"VEILVLT";
const VERSION: u8 = 1;
const ID_LEN: usize = 16;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const WRAPPED_LEN: usize = 32 + 16;
/// Encoded header length.
pub const HEADER_LEN: usize = MAGIC.len() + 1 + ID_LEN + 12 + SALT_LEN + NONCE_LEN + WRAPPED_LEN;
const KEK_INFO: &[u8] = b"veil/v1/kek";
const PURGE_INFO: &[u8] = b"veil/v1/purge-tag";
const SECRET_KEK_INFO: &[u8] = b"veil/v1/secret-kek";
const SECRET_WRAP_AAD: &[u8] = b"veil/v1/secret-wrap";
const SECRET_WRAP_VERSION: u8 = 1;
/// Encoded length of a [`wrap_with_secret`] blob.
pub const SECRET_WRAP_LEN: usize = 1 + NONCE_LEN + WRAPPED_LEN;
/// Length of a purge tag.
pub const PURGE_TAG_LEN: usize = 32;
/// Upper bound for passphrases (bytes), enforced before hashing.
pub const MAX_PASSPHRASE: usize = 1024;

/// Argon2id cost parameters. Stored in the header; authenticated as AAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// Desktop default: 256 MiB, 3 passes, 1 lane.
    pub const DESKTOP: Self = Self {
        m_kib: 256 * 1024,
        t: 3,
        p: 1,
    };
    /// Android default: 64 MiB, 4 passes, 1 lane.
    pub const MOBILE: Self = Self {
        m_kib: 64 * 1024,
        t: 4,
        p: 1,
    };
    /// Encrypted backups: 512 MiB, 4 passes.
    pub const BACKUP: Self = Self {
        m_kib: 512 * 1024,
        t: 4,
        p: 1,
    };
    /// Lowest parameters accepted when *creating* a vault (OWASP 2023 minimum for Argon2id).
    pub const FLOOR: Self = Self {
        m_kib: 19 * 1024,
        t: 2,
        p: 1,
    };

    /// Highest parameters accepted when creating *or opening* a vault (review L1). The header
    /// is only authenticated after the KDF has run, so these bounds are what stops a tampered
    /// header from demanding gigabytes of memory or hours of CPU. `BACKUP` is the largest preset.
    pub const CEILING: Self = Self {
        m_kib: 512 * 1024,
        t: 8,
        p: 4,
    };

    fn within_ceiling(self) -> bool {
        self.m_kib <= Self::CEILING.m_kib && self.t <= Self::CEILING.t && self.p <= Self::CEILING.p
    }

    fn validate_for_create(self) -> Result<()> {
        let floor = self.m_kib >= Self::FLOOR.m_kib && self.t >= Self::FLOOR.t && self.p >= 1;
        if !self.within_ceiling() {
            return Err(CoreError::Malformed);
        }
        let ok = floor;
        if ok || cfg!(test) {
            Ok(())
        } else {
            Err(CoreError::Malformed)
        }
    }

    /// Bounds accepted when *opening* (prevents absurd values from a corrupted header).
    fn validate_for_open(self) -> Result<()> {
        let ok = self.m_kib >= 8 && self.t >= 1 && self.p >= 1 && self.within_ceiling();
        if ok { Ok(()) } else { Err(CoreError::Malformed) }
    }
}

/// The 32-byte database key. Zeroized on drop; never `Debug`/`Clone`.
pub struct DbKey(Zeroizing<[u8; 32]>);

impl DbKey {
    /// The raw key, for handing to `SQLCipher`.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for DbKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DbKey(<redacted>)")
    }
}

/// Parsed vault header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHeader {
    pub vault_id: [u8; ID_LEN],
    pub params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    wrapped: [u8; WRAPPED_LEN],
}

impl VaultHeader {
    fn aad(&self) -> Vec<u8> {
        let mut a = Vec::with_capacity(HEADER_LEN);
        a.extend_from_slice(MAGIC);
        a.push(VERSION);
        a.extend_from_slice(&self.vault_id);
        a.extend_from_slice(&self.params.m_kib.to_be_bytes());
        a.extend_from_slice(&self.params.t.to_be_bytes());
        a.extend_from_slice(&self.params.p.to_be_bytes());
        a.extend_from_slice(&self.salt);
        a
    }

    /// Fixed-size binary encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.aad();
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.wrapped);
        out
    }

    /// Strict decoding.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HEADER_LEN {
            return Err(CoreError::Malformed);
        }
        let (magic, rest) = bytes.split_at(MAGIC.len());
        if magic != MAGIC {
            return Err(CoreError::Malformed);
        }
        let (v, rest) = rest.split_first().ok_or(CoreError::Malformed)?;
        if *v != VERSION {
            return Err(CoreError::UnsupportedVersion);
        }
        let (vault_id, rest) = take::<ID_LEN>(rest)?;
        let (m, rest) = take::<4>(rest)?;
        let (t, rest) = take::<4>(rest)?;
        let (p, rest) = take::<4>(rest)?;
        let (salt, rest) = take::<SALT_LEN>(rest)?;
        let (nonce, rest) = take::<NONCE_LEN>(rest)?;
        let (wrapped, rest) = take::<WRAPPED_LEN>(rest)?;
        if !rest.is_empty() {
            return Err(CoreError::Malformed);
        }
        let params = KdfParams {
            m_kib: u32::from_be_bytes(m),
            t: u32::from_be_bytes(t),
            p: u32::from_be_bytes(p),
        };
        params.validate_for_open()?;
        Ok(Self {
            vault_id,
            params,
            salt,
            nonce,
            wrapped,
        })
    }
}

fn take<const N: usize>(b: &[u8]) -> Result<([u8; N], &[u8])> {
    let (a, rest) = b.split_at_checked(N).ok_or(CoreError::Malformed)?;
    Ok((a.try_into().map_err(|_| CoreError::Malformed)?, rest))
}

/// `Argon2id(passphrase) || device_secret`, the input keying material of the KEK and purge tag.
fn derive_ikm(
    passphrase: &[u8],
    device_secret: &[u8; 32],
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; 64]>> {
    if passphrase.is_empty() || passphrase.len() > MAX_PASSPHRASE {
        return Err(CoreError::Malformed);
    }
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(params.m_kib, params.t, params.p, Some(32)).map_err(|_| CoreError::Malformed)?,
    );
    let mut ikm = Zeroizing::new([0u8; 64]);
    let (pw, dev) = ikm.split_at_mut(32);
    argon
        .hash_password_into(passphrase, salt, pw)
        .map_err(|_| CoreError::Malformed)?;
    dev.copy_from_slice(device_secret);
    Ok(ikm)
}

fn expand32(ikm: &[u8], vault_id: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(vault_id), ikm)
        .expand(info, &mut out[..])
        .map_err(|_| CoreError::Protocol)?;
    Ok(out)
}

fn derive_kek(
    passphrase: &[u8],
    device_secret: &[u8; 32],
    vault_id: &[u8],
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; 32]>> {
    let ikm = derive_ikm(passphrase, device_secret, salt, params)?;
    expand32(&ikm[..], vault_id, KEK_INFO)
}

fn seal_key<R: Rng + CryptoRng>(
    rng: &mut R,
    passphrase: &[u8],
    device_secret: &[u8; 32],
    vault_id: [u8; ID_LEN],
    params: KdfParams,
    db_key: &[u8; 32],
) -> Result<VaultHeader> {
    params.validate_for_create()?;
    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt);
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce);
    let mut header = VaultHeader {
        vault_id,
        params,
        salt,
        nonce,
        wrapped: [0; WRAPPED_LEN],
    };
    let kek = derive_kek(passphrase, device_secret, &vault_id, &salt, params)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&kek[..]).map_err(|_| CoreError::Protocol)?;
    let n = XNonce::try_from(&nonce[..]).map_err(|_| CoreError::Protocol)?;
    let ct = cipher
        .encrypt(
            &n,
            Payload {
                msg: db_key,
                aad: &header.aad(),
            },
        )
        .map_err(|_| CoreError::Protocol)?;
    header.wrapped = ct.as_slice().try_into().map_err(|_| CoreError::Protocol)?;
    Ok(header)
}

/// Creates a new vault: a fresh random DB key wrapped under passphrase + device secret.
pub fn create<R: Rng + CryptoRng>(
    rng: &mut R,
    passphrase: &[u8],
    device_secret: &[u8; 32],
    params: KdfParams,
) -> Result<(VaultHeader, DbKey)> {
    let mut vault_id = [0u8; ID_LEN];
    rng.fill(&mut vault_id);
    let mut key = Zeroizing::new([0u8; 32]);
    rng.fill(&mut key[..]);
    let header = seal_key(rng, passphrase, device_secret, vault_id, params, &key)?;
    Ok((header, DbKey(key)))
}

/// Unlocks a vault. Any wrong factor or modified header byte yields `VaultUnlock`.
pub fn unlock(header: &VaultHeader, passphrase: &[u8], device_secret: &[u8; 32]) -> Result<DbKey> {
    let kek = derive_kek(
        passphrase,
        device_secret,
        &header.vault_id,
        &header.salt,
        header.params,
    )
    .map_err(|_| CoreError::VaultUnlock)?;
    open_header(header, &kek)
}

fn open_header(header: &VaultHeader, kek: &[u8; 32]) -> Result<DbKey> {
    let cipher = XChaCha20Poly1305::new_from_slice(&kek[..]).map_err(|_| CoreError::Protocol)?;
    let n = XNonce::try_from(&header.nonce[..]).map_err(|_| CoreError::Protocol)?;
    let pt = Zeroizing::new(
        cipher
            .decrypt(
                &n,
                Payload {
                    msg: &header.wrapped,
                    aad: &header.aad(),
                },
            )
            .map_err(|_| CoreError::VaultUnlock)?,
    );
    let key: [u8; 32] = pt.as_slice().try_into().map_err(|_| CoreError::VaultUnlock)?;
    Ok(DbKey(Zeroizing::new(key)))
}

/// A Purge PIN's tag: compared, never reversed. No `Debug` of the bytes.
pub struct PurgeTag([u8; PURGE_TAG_LEN]);

impl PurgeTag {
    /// A random tag that matches no input. Stored when no Purge PIN is set, so the file
    /// looks the same either way.
    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let mut t = [0u8; PURGE_TAG_LEN];
        rng.fill(&mut t);
        Self(t)
    }

    pub fn to_bytes(&self) -> [u8; PURGE_TAG_LEN] {
        self.0
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        Ok(Self(b.try_into().map_err(|_| CoreError::Malformed)?))
    }
}

impl core::fmt::Debug for PurgeTag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PurgeTag(<redacted>)")
    }
}

/// Result of [`unlock_checking`].
#[derive(Debug)]
pub enum Unlocked {
    /// The input was the passphrase.
    Key(DbKey),
    /// The input was the Purge PIN: the caller must destroy the vault.
    Purge,
}

/// Unlocks with one Argon2id run, also checking the input against a Purge PIN tag.
/// The passphrase always wins; a wrong input yields `VaultUnlock`.
pub fn unlock_checking(
    header: &VaultHeader,
    input: &[u8],
    device_secret: &[u8; 32],
    purge: Option<&PurgeTag>,
) -> Result<Unlocked> {
    let ikm =
        derive_ikm(input, device_secret, &header.salt, header.params).map_err(|_| CoreError::VaultUnlock)?;
    let kek = expand32(&ikm[..], &header.vault_id, KEK_INFO)?;
    if let Ok(key) = open_header(header, &kek) {
        return Ok(Unlocked::Key(key));
    }
    if let Some(tag) = purge {
        let got = expand32(&ikm[..], &header.vault_id, PURGE_INFO)?;
        if bool::from(subtle::ConstantTimeEq::ct_eq(&got[..], &tag.0[..])) {
            return Ok(Unlocked::Purge);
        }
    }
    Err(CoreError::VaultUnlock)
}

/// Computes the tag for a Purge PIN. Refuses an input that opens the vault, so the Purge PIN
/// can never equal the passphrase.
pub fn purge_tag(header: &VaultHeader, input: &[u8], device_secret: &[u8; 32]) -> Result<PurgeTag> {
    let ikm = derive_ikm(input, device_secret, &header.salt, header.params)?;
    let kek = expand32(&ikm[..], &header.vault_id, KEK_INFO)?;
    if open_header(header, &kek).is_ok() {
        return Err(CoreError::Malformed);
    }
    let tag = expand32(&ikm[..], &header.vault_id, PURGE_INFO)?;
    Ok(PurgeTag(*tag))
}

fn secret_wrap_aad(vault_id: &[u8; ID_LEN]) -> Vec<u8> {
    let mut a = SECRET_WRAP_AAD.to_vec();
    a.extend_from_slice(vault_id);
    a
}

/// Wraps the DB key under a random 32-byte secret plus the device secret (biometric unlock).
pub fn wrap_with_secret<R: Rng + CryptoRng>(
    rng: &mut R,
    header: &VaultHeader,
    key: &DbKey,
    secret: &[u8; 32],
    device_secret: &[u8; 32],
) -> Result<Vec<u8>> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    let (a, b) = ikm.split_at_mut(32);
    a.copy_from_slice(secret);
    b.copy_from_slice(device_secret);
    let skek = expand32(&ikm[..], &header.vault_id, SECRET_KEK_INFO)?;
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(&skek[..]).map_err(|_| CoreError::Protocol)?;
    let n = XNonce::try_from(&nonce[..]).map_err(|_| CoreError::Protocol)?;
    let ct = cipher
        .encrypt(
            &n,
            Payload {
                msg: key.expose(),
                aad: &secret_wrap_aad(&header.vault_id),
            },
        )
        .map_err(|_| CoreError::Protocol)?;
    let mut out = Vec::with_capacity(SECRET_WRAP_LEN);
    out.push(SECRET_WRAP_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Opens a [`wrap_with_secret`] blob. Any wrong input yields `VaultUnlock`.
pub fn unwrap_with_secret(
    header: &VaultHeader,
    blob: &[u8],
    secret: &[u8; 32],
    device_secret: &[u8; 32],
) -> Result<DbKey> {
    if blob.len() != SECRET_WRAP_LEN {
        return Err(CoreError::Malformed);
    }
    let (v, rest) = blob.split_first().ok_or(CoreError::Malformed)?;
    if *v != SECRET_WRAP_VERSION {
        return Err(CoreError::UnsupportedVersion);
    }
    let (nonce, ct) = rest.split_at_checked(NONCE_LEN).ok_or(CoreError::Malformed)?;
    let mut ikm = Zeroizing::new([0u8; 64]);
    let (a, b) = ikm.split_at_mut(32);
    a.copy_from_slice(secret);
    b.copy_from_slice(device_secret);
    let skek = expand32(&ikm[..], &header.vault_id, SECRET_KEK_INFO)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&skek[..]).map_err(|_| CoreError::Protocol)?;
    let n = XNonce::try_from(nonce).map_err(|_| CoreError::Malformed)?;
    let pt = Zeroizing::new(
        cipher
            .decrypt(
                &n,
                Payload {
                    msg: ct,
                    aad: &secret_wrap_aad(&header.vault_id),
                },
            )
            .map_err(|_| CoreError::VaultUnlock)?,
    );
    let key: [u8; 32] = pt.as_slice().try_into().map_err(|_| CoreError::VaultUnlock)?;
    Ok(DbKey(Zeroizing::new(key)))
}

/// Changes the passphrase (and optionally the KDF cost) without changing the DB key.
pub fn rewrap<R: Rng + CryptoRng>(
    rng: &mut R,
    header: &VaultHeader,
    old_passphrase: &[u8],
    new_passphrase: &[u8],
    device_secret: &[u8; 32],
    params: KdfParams,
) -> Result<VaultHeader> {
    let key = unlock(header, old_passphrase, device_secret)?;
    seal_key(
        rng,
        new_passphrase,
        device_secret,
        header.vault_id,
        params,
        key.expose(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::TryRngCore as _;
    use rand::rngs::OsRng;

    const FAST: KdfParams = KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };

    fn rng() -> rand::rand_core::UnwrapErr<OsRng> {
        OsRng.unwrap_err()
    }

    #[test]
    fn create_unlock_and_both_factors_required() {
        let mut rng = OsRng.unwrap_err();
        let dev = [7u8; 32];
        let (h, key) = create(&mut rng, b"correct horse", &dev, FAST).unwrap();
        let bytes = h.encode();
        assert_eq!(bytes.len(), HEADER_LEN);
        let h2 = VaultHeader::decode(&bytes).unwrap();
        assert_eq!(
            unlock(&h2, b"correct horse", &dev).unwrap().expose(),
            key.expose()
        );
        // INV-REST-2: either factor alone is insufficient.
        assert_eq!(
            unlock(&h2, b"wrong", &dev).err().map(|e| e.to_string()),
            Some("vault unlock failed".into())
        );
        assert!(unlock(&h2, b"correct horse", &[8u8; 32]).is_err());
    }

    #[test]
    fn every_header_bit_flip_rejected() {
        let mut rng = OsRng.unwrap_err();
        let dev = [1u8; 32];
        let (h, _) = create(&mut rng, b"pw", &dev, FAST).unwrap();
        let bytes = h.encode();
        for i in 0..bytes.len() {
            let mut t = bytes.clone();
            t[i] ^= 1 << (i % 8);
            let ok = VaultHeader::decode(&t)
                .and_then(|hh| unlock(&hh, b"pw", &dev))
                .is_ok();
            assert!(!ok, "flip at byte {i} accepted");
        }
    }

    #[test]
    fn rewrap_keeps_key_and_retires_old_passphrase() {
        let mut rng = OsRng.unwrap_err();
        let dev = [2u8; 32];
        let (h, key) = create(&mut rng, b"old", &dev, FAST).unwrap();
        let h2 = rewrap(&mut rng, &h, b"old", b"new", &dev, FAST).unwrap();
        assert_eq!(unlock(&h2, b"new", &dev).unwrap().expose(), key.expose());
        assert!(unlock(&h2, b"old", &dev).is_err());
        assert_ne!(h.salt, h2.salt);
    }

    #[test]
    fn limits_and_redaction() {
        let mut rng = OsRng.unwrap_err();
        assert!(create(&mut rng, b"", &[0; 32], FAST).is_err());
        assert!(create(&mut rng, &vec![b'a'; MAX_PASSPHRASE + 1], &[0; 32], FAST).is_err());
        let (_, key) = create(&mut rng, b"x", &[0; 32], FAST).unwrap();
        assert_eq!(format!("{key:?}"), "DbKey(<redacted>)");
        assert!(VaultHeader::decode(&[0; 3]).is_err());
        assert!(KdfParams::FLOOR.validate_for_open().is_ok());
    }

    /// Review round 1, L1: a tampered header cannot make opening allocate gigabytes or run
    /// for hours. The cost fields are refused before Argon2 runs.
    #[test]
    fn tampered_cost_parameters_refused_before_kdf() {
        let mut rng = OsRng.unwrap_err();
        let (header, _) = create(&mut rng, b"pw", &[0; 32], FAST).unwrap();
        let good = header.encode();
        // Layout: magic (7) | version (1) | vault_id (16) | m_kib | t | p (u32 BE each) | ...
        for (offset, value) in [
            (24, 4 * 1024 * 1024u32),
            (24, KdfParams::CEILING.m_kib + 1),
            (28, 64),
            (28, 9),
            (32, 8),
            (32, 0),
        ] {
            let mut bad = good.clone();
            bad[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
            let started = std::time::Instant::now();
            assert_eq!(
                VaultHeader::decode(&bad).err(),
                Some(CoreError::Malformed),
                "offset {offset} = {value}"
            );
            assert!(started.elapsed() < std::time::Duration::from_millis(50));
        }
        assert!(
            create(
                &mut rng,
                b"pw",
                &[0; 32],
                KdfParams {
                    m_kib: KdfParams::CEILING.m_kib * 2,
                    ..KdfParams::FLOOR
                }
            )
            .is_err()
        );
        for preset in [
            KdfParams::DESKTOP,
            KdfParams::MOBILE,
            KdfParams::BACKUP,
            KdfParams::FLOOR,
        ] {
            assert!(preset.validate_for_create().is_ok() && preset.validate_for_open().is_ok());
        }
    }

    #[test]
    fn purge_tag_one_kdf_run_decides() {
        let dev = [3u8; 32];
        let (h, key) = create(&mut rng(), b"123456", &dev, FAST).unwrap();
        let tag = purge_tag(&h, b"999999", &dev).unwrap();
        // The passphrase can never be the Purge PIN.
        assert!(purge_tag(&h, b"123456", &dev).is_err());
        match unlock_checking(&h, b"123456", &dev, Some(&tag)).unwrap() {
            Unlocked::Key(k) => assert_eq!(k.expose(), key.expose()),
            Unlocked::Purge => panic!("passphrase treated as purge"),
        }
        assert!(matches!(
            unlock_checking(&h, b"999999", &dev, Some(&tag)).unwrap(),
            Unlocked::Purge
        ));
        assert!(matches!(
            unlock_checking(&h, b"000000", &dev, Some(&tag)),
            Err(CoreError::VaultUnlock)
        ));
        // Without the device secret the purge input is just a wrong guess.
        assert!(matches!(
            unlock_checking(&h, b"999999", &[4u8; 32], Some(&tag)),
            Err(CoreError::VaultUnlock)
        ));
        // A random tag (no Purge PIN set) matches nothing.
        let none = PurgeTag::random(&mut rng());
        assert!(matches!(
            unlock_checking(&h, b"999999", &dev, Some(&none)),
            Err(CoreError::VaultUnlock)
        ));
        // A rewrap re-salts: the old tag no longer matches (the client clears it).
        let h2 = rewrap(&mut rng(), &h, b"123456", b"654321", &dev, FAST).unwrap();
        assert!(matches!(
            unlock_checking(&h2, b"999999", &dev, Some(&tag)),
            Err(CoreError::VaultUnlock)
        ));
        assert_eq!(format!("{tag:?}"), "PurgeTag(<redacted>)");
    }

    #[test]
    fn secret_wrap_needs_secret_and_device_and_survives_rewrap() {
        let dev = [5u8; 32];
        let secret = [6u8; 32];
        let (h, key) = create(&mut rng(), b"passphrase-one", &dev, FAST).unwrap();
        let blob = wrap_with_secret(&mut rng(), &h, &key, &secret, &dev).unwrap();
        assert_eq!(blob.len(), SECRET_WRAP_LEN);
        assert_eq!(
            unwrap_with_secret(&h, &blob, &secret, &dev).unwrap().expose(),
            key.expose()
        );
        assert!(unwrap_with_secret(&h, &blob, &[7u8; 32], &dev).is_err());
        assert!(unwrap_with_secret(&h, &blob, &secret, &[8u8; 32]).is_err());
        for i in 0..blob.len() {
            for bit in 0..8 {
                let mut b = blob.clone();
                b[i] ^= 1 << bit;
                assert!(
                    unwrap_with_secret(&h, &b, &secret, &dev).is_err(),
                    "flip {i}:{bit}"
                );
            }
        }
        assert!(unwrap_with_secret(&h, &blob[1..], &secret, &dev).is_err());
        // Another vault (different id) cannot use this blob.
        let (other, _) = create(&mut rng(), b"passphrase-one", &dev, FAST).unwrap();
        assert!(unwrap_with_secret(&other, &blob, &secret, &dev).is_err());
        // Changing the passphrase keeps the vault id and the DB key, so the wrap still opens.
        let h2 = rewrap(&mut rng(), &h, b"passphrase-one", b"passphrase-two", &dev, FAST).unwrap();
        assert_eq!(
            unwrap_with_secret(&h2, &blob, &secret, &dev).unwrap().expose(),
            key.expose()
        );
    }

    /// Known-answer test against an independent Python oracle (argon2-cffi + HKDF + XChaCha20-Poly1305).
    #[test]
    fn known_answer_unlock() {
        let header = VaultHeader::decode(&crate::test_vectors::VAULT_HEADER).unwrap();
        let key = unlock(
            &header,
            crate::test_vectors::VAULT_PASSPHRASE,
            &crate::test_vectors::VAULT_DEVICE_SECRET,
        )
        .unwrap();
        assert_eq!(key.expose(), &crate::test_vectors::VAULT_DB_KEY);
    }
}
