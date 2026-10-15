//! Attachment encryption (PROTOCOL §9, INV-ATT-1..3).
//!
//! * Plaintext is padded with ISO/IEC 7816-4 to the Padmé length of `size + 1`, so the
//!   relay learns only a coarse size class.
//! * The padded data is split into 64 KiB chunks and encrypted with the **STREAM**
//!   construction (`StreamBE32` over XChaCha20-Poly1305; 19-byte random nonce prefix,
//!   32-bit chunk counter, last-chunk flag). Reordering, swapping, truncation and
//!   extension are all detected.
//! * Each attachment has its own random key, sent inside the E2EE message along with
//!   the SHA-256 of the ciphertext, which is checked **before** any decryption.
//! * Chunks are position-addressable, so uploads/downloads can resume at any chunk.

use aead_stream::{NewStream as _, StreamBE32, StreamPrimitive as _};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{KeyInit, Payload};
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};
use crate::padding::padme_len;

/// Plaintext chunk size.
pub const CHUNK: usize = 64 * 1024;
const TAG: usize = 16;
/// STREAM nonce prefix length for `XChaCha20` (24 − 4-byte counter − 1-byte flag).
pub const NONCE_PREFIX_LEN: usize = 19;
/// Largest plaintext accepted (100 MiB, PROTOCOL §14).
pub const MAX_ATTACHMENT_SIZE: u64 = 100 * 1024 * 1024;
/// Largest padded size (Padmé of `MAX_ATTACHMENT_SIZE + 1`, rounded up generously).
pub const MAX_ATTACHMENT_PADDED: u64 = 110 * 1024 * 1024;
const AAD: &[u8] = b"veil/v1/attachment";

/// Per-attachment key material, sent inside the E2EE `Attachment` message.
pub struct AttachmentKey {
    key: Zeroizing<[u8; 32]>,
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
}

impl core::fmt::Debug for AttachmentKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AttachmentKey(<redacted>)")
    }
}

impl AttachmentKey {
    pub fn generate<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        rng.fill(&mut key[..]);
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        rng.fill(&mut nonce_prefix);
        Self { key, nonce_prefix }
    }

    /// Rebuilds from the fields of a received `Attachment` message.
    pub fn from_parts(key: &[u8], nonce_prefix: &[u8]) -> Result<Self> {
        let key: [u8; 32] = key.try_into().map_err(|_| CoreError::Malformed)?;
        let nonce_prefix = nonce_prefix.try_into().map_err(|_| CoreError::Malformed)?;
        Ok(Self {
            key: Zeroizing::new(key),
            nonce_prefix,
        })
    }

    /// Key bytes for the outgoing message.
    pub fn key_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Nonce prefix for the outgoing message.
    pub fn nonce_prefix(&self) -> &[u8; NONCE_PREFIX_LEN] {
        &self.nonce_prefix
    }

    fn stream(&self) -> Result<StreamBE32<XChaCha20Poly1305>> {
        let aead = XChaCha20Poly1305::new_from_slice(&self.key[..]).map_err(|_| CoreError::Protocol)?;
        let prefix = aead_stream::Nonce::<XChaCha20Poly1305, StreamBE32<XChaCha20Poly1305>>::try_from(
            &self.nonce_prefix[..],
        )
        .map_err(|_| CoreError::Protocol)?;
        Ok(StreamBE32::from_aead(aead, &prefix))
    }
}

/// Encrypted attachment and the metadata the recipient needs.
pub struct Encrypted {
    pub ciphertext: Vec<u8>,
    pub ciphertext_sha256: [u8; 32],
    pub size: u64,
    pub padded_size: u64,
}

/// Number of chunks for a padded size.
pub fn chunk_count(padded_size: u64) -> Result<u32> {
    let chunk = u64::try_from(CHUNK).map_err(|_| CoreError::Protocol)?;
    u32::try_from(padded_size.div_ceil(chunk)).map_err(|_| CoreError::TooLarge)
}

/// Ciphertext length for a padded size.
pub fn ciphertext_len(padded_size: u64) -> Result<u64> {
    let tags = u64::from(chunk_count(padded_size)?).saturating_mul(16);
    padded_size.checked_add(tags).ok_or(CoreError::TooLarge)
}

/// Padded size for a plaintext size.
pub fn padded_size(size: u64) -> Result<u64> {
    if size > MAX_ATTACHMENT_SIZE {
        return Err(CoreError::TooLarge);
    }
    let p = padme_len(size.saturating_add(1));
    if p > MAX_ATTACHMENT_PADDED {
        Err(CoreError::TooLarge)
    } else {
        Ok(p)
    }
}

/// Encrypts a whole attachment.
pub fn encrypt<R: Rng + CryptoRng>(rng: &mut R, plaintext: &[u8]) -> Result<(AttachmentKey, Encrypted)> {
    let key = AttachmentKey::generate(rng);
    let size = u64::try_from(plaintext.len()).map_err(|_| CoreError::TooLarge)?;
    let padded_size = padded_size(size)?;
    let mut padded = Zeroizing::new(Vec::with_capacity(
        usize::try_from(padded_size).map_err(|_| CoreError::TooLarge)?,
    ));
    padded.extend_from_slice(plaintext);
    padded.push(0x80);
    padded.resize(usize::try_from(padded_size).map_err(|_| CoreError::TooLarge)?, 0);

    let total = chunk_count(padded_size)?;
    let mut ciphertext =
        Vec::with_capacity(usize::try_from(ciphertext_len(padded_size)?).map_err(|_| CoreError::TooLarge)?);
    for (i, chunk) in padded.chunks(CHUNK).enumerate() {
        let index = u32::try_from(i).map_err(|_| CoreError::TooLarge)?;
        ciphertext.extend_from_slice(&encrypt_chunk(
            &key,
            index,
            index.saturating_add(1) == total,
            chunk,
        )?);
    }
    let ciphertext_sha256 = Sha256::digest(&ciphertext).into();
    Ok((
        key,
        Encrypted {
            ciphertext,
            ciphertext_sha256,
            size,
            padded_size,
        },
    ))
}

/// Encrypts one chunk at a position (for resumable uploads of large files).
pub fn encrypt_chunk(
    key: &AttachmentKey,
    index: u32,
    is_last: bool,
    plaintext_chunk: &[u8],
) -> Result<Vec<u8>> {
    if plaintext_chunk.is_empty() || plaintext_chunk.len() > CHUNK {
        return Err(CoreError::Malformed);
    }
    key.stream()?
        .encrypt(
            index,
            is_last,
            Payload {
                msg: plaintext_chunk,
                aad: AAD,
            },
        )
        .map_err(|_| CoreError::Protocol)
}

/// Decrypts one chunk at a position (for resumable downloads).
pub fn decrypt_chunk(
    key: &AttachmentKey,
    index: u32,
    is_last: bool,
    chunk_ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if chunk_ct.len() <= TAG || chunk_ct.len() > CHUNK.saturating_add(TAG) {
        return Err(CoreError::Malformed);
    }
    key.stream()?
        .decrypt(
            index,
            is_last,
            Payload {
                msg: chunk_ct,
                aad: AAD,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CoreError::AuthFailed)
}

/// Verifies the ciphertext hash, then decrypts and unpads. `size`/`padded_size` come from the
/// authenticated `Attachment` message and must be consistent with the ciphertext.
pub fn decrypt(
    key: &AttachmentKey,
    ciphertext: &[u8],
    expected_sha256: &[u8],
    size: u64,
    padded_size: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    // INV-ATT-2: hash first, before touching the AEAD.
    let digest: [u8; 32] = Sha256::digest(ciphertext).into();
    if expected_sha256.len() != 32 || !bool::from(digest.ct_eq(expected_sha256)) {
        return Err(CoreError::AuthFailed);
    }
    if padded_size != padded_size_checked(size)?
        || u64::try_from(ciphertext.len()).ok() != Some(ciphertext_len(padded_size)?)
    {
        return Err(CoreError::Malformed);
    }
    let total = chunk_count(padded_size)?;
    let mut out = Zeroizing::new(Vec::with_capacity(
        usize::try_from(padded_size).map_err(|_| CoreError::TooLarge)?,
    ));
    for (i, chunk) in ciphertext.chunks(CHUNK.saturating_add(TAG)).enumerate() {
        let index = u32::try_from(i).map_err(|_| CoreError::TooLarge)?;
        out.extend_from_slice(&decrypt_chunk(
            key,
            index,
            index.saturating_add(1) == total,
            chunk,
        )?);
    }
    let marker = out.iter().rposition(|&b| b != 0).ok_or(CoreError::Malformed)?;
    if out.get(marker) != Some(&0x80) || u64::try_from(marker).ok() != Some(size) {
        return Err(CoreError::Malformed);
    }
    out.truncate(marker);
    Ok(out)
}

fn padded_size_checked(size: u64) -> Result<u64> {
    padded_size(size).map_err(|_| CoreError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand::TryRngCore as _;
    use rand::rngs::OsRng;

    fn roundtrip(data: &[u8]) {
        let mut rng = OsRng.unwrap_err();
        let (k, e) = encrypt(&mut rng, data).unwrap();
        assert_eq!(e.ciphertext.len() as u64, ciphertext_len(e.padded_size).unwrap());
        let out = decrypt(&k, &e.ciphertext, &e.ciphertext_sha256, e.size, e.padded_size).unwrap();
        assert_eq!(&out[..], data);
    }

    #[test]
    fn sizes() {
        for n in [0, 1, 100, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK + 17] {
            roundtrip(&vec![0x5A; n]);
        }
    }

    #[test]
    fn tamper_reorder_truncate_extend_swap_all_rejected() {
        let mut rng = OsRng.unwrap_err();
        let data: Vec<u8> = (0..(3 * CHUNK + 100)).map(|i| (i % 251) as u8).collect();
        let (k, e) = encrypt(&mut rng, &data).unwrap();
        let fix = |ct: &[u8]| -> [u8; 32] { Sha256::digest(ct).into() };
        // Bit flips (hash recomputed so the AEAD itself must catch them): sample every 997th byte.
        for i in (0..e.ciphertext.len()).step_by(997) {
            let mut t = e.ciphertext.clone();
            t[i] ^= 1;
            assert!(
                decrypt(&k, &t, &fix(&t), e.size, e.padded_size).is_err(),
                "flip at {i}"
            );
        }
        // Hash mismatch alone (unmodified ciphertext, wrong digest) is rejected before decryption.
        assert_eq!(
            decrypt(&k, &e.ciphertext, &[0; 32], e.size, e.padded_size).err(),
            Some(CoreError::AuthFailed)
        );
        let c = CHUNK + TAG;
        // Reorder chunks 0 and 1.
        let mut r = e.ciphertext.clone();
        let (a, b) = r.split_at_mut(c);
        a.swap_with_slice(&mut b[..c]);
        assert!(decrypt(&k, &r, &fix(&r), e.size, e.padded_size).is_err());
        // Truncate the last chunk away (claiming a smaller file).
        let t = e.ciphertext[..3 * c].to_vec();
        assert!(decrypt(&k, &t, &fix(&t), 3 * CHUNK as u64 - 1, 3 * CHUNK as u64).is_err());
        // Extend with a duplicated chunk.
        let mut x = e.ciphertext.clone();
        x.extend_from_slice(&e.ciphertext[..c]);
        assert!(decrypt(&k, &x, &fix(&x), e.size, e.padded_size).is_err());
        // Chunk swapped in from another file encrypted under a different key.
        let (_, e2) = encrypt(&mut rng, &data).unwrap();
        let mut s = e.ciphertext.clone();
        s[..c].copy_from_slice(&e2.ciphertext[..c]);
        assert!(decrypt(&k, &s, &fix(&s), e.size, e.padded_size).is_err());
        // Lying about the size.
        assert!(decrypt(&k, &e.ciphertext, &e.ciphertext_sha256, e.size - 1, e.padded_size).is_err());
    }

    #[test]
    fn resumable_chunks_match_whole_file() {
        let mut rng = OsRng.unwrap_err();
        let data = vec![9u8; 2 * CHUNK + 5];
        let (k, e) = encrypt(&mut rng, &data).unwrap();
        let n = chunk_count(e.padded_size).unwrap();
        let mut out = Vec::new();
        for (i, c) in e.ciphertext.chunks(CHUNK + TAG).enumerate() {
            let i = i as u32;
            out.extend_from_slice(&decrypt_chunk(&k, i, i + 1 == n, c).unwrap());
        }
        assert_eq!(&out[..data.len()], &data[..]);
        // Decrypting the last chunk as non-last must fail (truncation detection).
        let last = e.ciphertext.chunks(CHUNK + TAG).last().unwrap();
        assert!(decrypt_chunk(&k, n - 1, false, last).is_err());
    }

    #[test]
    fn limits_and_redaction() {
        assert_eq!(padded_size(MAX_ATTACHMENT_SIZE + 1), Err(CoreError::TooLarge));
        assert!(padded_size(MAX_ATTACHMENT_SIZE).unwrap() <= MAX_ATTACHMENT_PADDED);
        let k = AttachmentKey::generate(&mut OsRng.unwrap_err());
        assert_eq!(format!("{k:?}"), "AttachmentKey(<redacted>)");
        assert!(AttachmentKey::from_parts(&[0; 31], &[0; 19]).is_err());
    }

    /// Known-answer test against an independent Python STREAM/XChaCha20-Poly1305 implementation.
    #[test]
    fn known_answer() {
        use crate::test_vectors as v;
        let k = AttachmentKey::from_parts(&v::ATT_KEY, &v::ATT_PREFIX).unwrap();
        let ct = encrypt_chunk(&k, 0, true, v::ATT_PLAIN_PADDED).unwrap();
        assert_eq!(ct, v::ATT_CT);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn prop_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..200_000)) {
            roundtrip(&data);
        }
    }
}
