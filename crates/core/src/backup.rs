//! Encrypted backups (PROTOCOL §12, ADR-0021).
//!
//! A backup is sealed under a **backup code** Veil generates: 32 Crockford base32 characters
//! (160 random bits), shown to the user once to write down. A code rather than a chosen
//! password means a stolen backup file cannot be guessed offline, whatever the user picks.
//!
//! File: `"VEILBAK" | v=1 | m_kib, t, p (u32 BE) | salt (16) | nonce prefix (19)` (the
//! 55-byte header), then a 16-byte marker as chunk 0 (it tells a wrong code from a damaged
//! file), then the plaintext in 64 KiB chunks from chunk 1, sealed with the **STREAM**
//! construction (`StreamBE32` over XChaCha20-Poly1305, the same as attachments). Each chunk's
//! AAD is the whole header, so the KDF parameters and salt are authenticated, and the last
//! chunk carries STREAM's last-chunk flag, so truncation, reordering and extension all fail.
//! The key is `Argon2id(code, salt)`; parameters are bounded before Argon2 runs (as for the
//! vault, review L1).

use std::io::{Read, Write};

use aead_stream::{NewStream as _, StreamBE32, StreamPrimitive as _};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{KeyInit, Payload};
use rand::{CryptoRng, Rng};
use zeroize::Zeroizing;

use crate::attachment::{CHUNK, NONCE_PREFIX_LEN};
use crate::error::{CoreError, Result};
use crate::vault::KdfParams;

const MAGIC: &[u8; 7] = b"VEILBAK";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
/// The header's length.
pub const HEADER_LEN: usize = MAGIC.len() + 1 + 12 + SALT_LEN + NONCE_PREFIX_LEN;
const TAG: usize = 16;
/// The plaintext of chunk 0.
const MARKER: &[u8; 16] = b"veil/v1/backup\0\0";
/// Offsets in the header: KDF parameters, salt, nonce prefix.
const AT: usize = MAGIC.len() + 1;
const SALT_AT: usize = AT + 12;
const PREFIX_AT: usize = SALT_AT + SALT_LEN;
/// Characters in a backup code (Crockford base32: no I, L, O or U).
pub const CODE_LEN: usize = 32;
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// The KDF cost for backups: the phone preset, so a backup made on a desktop also opens on a
/// phone. The code's 160 bits, not the cost, are what stops guessing.
pub const KDF: KdfParams = KdfParams::MOBILE;

/// Key prefixes in the core's store that a backup must not contain: ratchet sessions (reusing
/// them after a restore would reuse message keys) and our prekeys and invites (a restore issues
/// fresh ones, and an old one-time prekey must never be used twice). Peer identities, our
/// identity key and registration id are kept.
pub const NOT_BACKED_UP: [&[u8]; 5] = [
    crate::store::keys::SESSION,
    crate::store::keys::PREKEY,
    crate::store::keys::SIGNED_PREKEY,
    crate::store::keys::KYBER_PREKEY,
    crate::store::keys::INVITE,
];

/// A backup code. No `Debug`, `Clone` or `Serialize`: it opens the backup.
pub struct BackupCode(Zeroizing<String>);

impl BackupCode {
    /// A fresh random code.
    pub fn generate<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let mut s = Zeroizing::new(String::with_capacity(CODE_LEN));
        for _ in 0..CODE_LEN {
            let i = rng.random_range(0..ALPHABET.len());
            s.push(char::from(ALPHABET.get(i).copied().unwrap_or(b'0')));
        }
        Self(s)
    }

    /// A code as the user typed it: spaces and dashes ignored, any case, and the letters
    /// that look like digits (O, I, L) read as them, per Crockford.
    pub fn parse(input: &str) -> Result<Self> {
        let mut s = Zeroizing::new(String::with_capacity(CODE_LEN));
        for c in input.chars() {
            let c = match c.to_ascii_uppercase() {
                ' ' | '-' => continue,
                'O' => '0',
                'I' | 'L' => '1',
                c => c,
            };
            if !u8::try_from(c).is_ok_and(|b| ALPHABET.contains(&b)) {
                return Err(CoreError::Malformed);
            }
            s.push(c);
        }
        if s.len() == CODE_LEN {
            Ok(Self(s))
        } else {
            Err(CoreError::Malformed)
        }
    }

    /// The code as stored (32 characters, no separators).
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The code as shown: eight groups of four.
    pub fn display(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(CODE_LEN + 7));
        for (i, c) in self.0.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                out.push('-');
            }
            out.push(c);
        }
        out
    }
}

fn be32(b: &[u8], at: usize) -> Result<u32> {
    let v = b
        .get(at..at.checked_add(4).ok_or(CoreError::Malformed)?)
        .ok_or(CoreError::Malformed)?;
    Ok(u32::from_be_bytes(
        v.try_into().map_err(|_| CoreError::Malformed)?,
    ))
}

fn stream(
    code: &BackupCode,
    params: KdfParams,
    salt: &[u8],
    prefix: &[u8],
) -> Result<StreamBE32<XChaCha20Poly1305>> {
    let ok = |v: u32, lo: u32, hi: u32| v >= lo && v <= hi;
    if !ok(params.m_kib, KdfParams::FLOOR.m_kib, KdfParams::CEILING.m_kib)
        || !ok(params.t, KdfParams::FLOOR.t, KdfParams::CEILING.t)
        || !ok(params.p, 1, KdfParams::CEILING.p)
    {
        return Err(CoreError::Malformed);
    }
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(params.m_kib, params.t, params.p, Some(32)).map_err(|_| CoreError::Malformed)?,
    );
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(code.expose().as_bytes(), salt, &mut key[..])
        .map_err(|_| CoreError::Malformed)?;
    let aead = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| CoreError::Protocol)?;
    let nonce = aead_stream::Nonce::<XChaCha20Poly1305, StreamBE32<XChaCha20Poly1305>>::try_from(prefix)
        .map_err(|_| CoreError::Protocol)?;
    Ok(StreamBE32::from_aead(aead, &nonce))
}

/// Reads up to `buf.len()` bytes, fewer only at the end of `r`.
fn fill<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        let rest = buf.get_mut(n..).ok_or(CoreError::Storage)?;
        match r.read(rest) {
            Ok(0) => break,
            Ok(k) => n = n.checked_add(k).ok_or(CoreError::Storage)?,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(CoreError::Storage),
        }
    }
    Ok(n)
}

/// Seals everything `input` yields into `out`. `input` must not be empty.
pub fn seal<R: Rng + CryptoRng, I: Read, O: Write>(
    rng: &mut R,
    code: &BackupCode,
    input: I,
    out: O,
) -> Result<()> {
    seal_with(rng, code, KDF, input, out)
}

/// [`seal`] with chosen KDF parameters (tests use cheap ones).
fn seal_with<R: Rng + CryptoRng, I: Read, O: Write>(
    rng: &mut R,
    code: &BackupCode,
    kdf: KdfParams,
    mut input: I,
    mut out: O,
) -> Result<()> {
    let mut salt = [0u8; SALT_LEN];
    let mut prefix = [0u8; NONCE_PREFIX_LEN];
    rng.fill(&mut salt);
    rng.fill(&mut prefix);
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    for v in [kdf.m_kib, kdf.t, kdf.p] {
        header.extend_from_slice(&v.to_be_bytes());
    }
    header.extend_from_slice(&salt);
    header.extend_from_slice(&prefix);
    let s = stream(code, kdf, &salt, &prefix)?;
    out.write_all(&header).map_err(|_| CoreError::Storage)?;
    // Chunk 0 is a fixed marker: if it opens, the code is right, so a later failure means the
    // file was damaged, not that the code was mistyped.
    let marker = s
        .encrypt(
            0,
            false,
            Payload {
                msg: MARKER,
                aad: &header,
            },
        )
        .map_err(|_| CoreError::Protocol)?;
    out.write_all(&marker).map_err(|_| CoreError::Storage)?;

    // One chunk read ahead, so the last one is known when it is sealed.
    let mut cur = Zeroizing::new(vec![0u8; CHUNK]);
    let mut next = Zeroizing::new(vec![0u8; CHUNK]);
    let mut len = fill(&mut input, &mut cur)?;
    if len == 0 {
        return Err(CoreError::Malformed);
    }
    let mut index = 1u32;
    loop {
        let next_len = fill(&mut input, &mut next)?;
        let last = next_len == 0;
        let msg = cur.get(..len).ok_or(CoreError::Storage)?;
        let ct = s
            .encrypt(index, last, Payload { msg, aad: &header })
            .map_err(|_| CoreError::Protocol)?;
        out.write_all(&ct).map_err(|_| CoreError::Storage)?;
        if last {
            return out.flush().map_err(|_| CoreError::Storage);
        }
        core::mem::swap(&mut cur, &mut next);
        len = next_len;
        index = index.checked_add(1).ok_or(CoreError::TooLarge)?;
    }
}

/// Opens a backup, handing each plaintext chunk to `sink` in order. Fails (after `sink` may
/// have seen earlier chunks) if the code is wrong or the file was changed, cut short or
/// extended; the caller discards what it got in that case.
pub fn open<I: Read>(
    code: &BackupCode,
    mut input: I,
    mut sink: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    let mut header = [0u8; HEADER_LEN];
    if fill(&mut input, &mut header)? != HEADER_LEN || header.get(..MAGIC.len()) != Some(&MAGIC[..]) {
        return Err(CoreError::Malformed);
    }
    if header.get(MAGIC.len()) != Some(&VERSION) {
        return Err(CoreError::UnsupportedVersion);
    }
    let params = KdfParams {
        m_kib: be32(&header, AT)?,
        t: be32(&header, AT + 4)?,
        p: be32(&header, AT + 8)?,
    };
    let salt = header.get(SALT_AT..PREFIX_AT).ok_or(CoreError::Malformed)?;
    let prefix = header.get(PREFIX_AT..HEADER_LEN).ok_or(CoreError::Malformed)?;
    let s = stream(code, params, salt, prefix)?;
    let mut marker = [0u8; MARKER.len() + TAG];
    if fill(&mut input, &mut marker)? != marker.len() {
        return Err(CoreError::Malformed);
    }
    let opened = s
        .decrypt(
            0,
            false,
            Payload {
                msg: &marker[..],
                aad: &header,
            },
        )
        .map_err(|_| CoreError::AuthFailed)?;
    if opened != MARKER {
        return Err(CoreError::AuthFailed);
    }

    let full = CHUNK.checked_add(TAG).ok_or(CoreError::Malformed)?;
    let mut cur = vec![0u8; full];
    let mut next = vec![0u8; full];
    let mut len = fill(&mut input, &mut cur)?;
    let mut index = 1u32;
    loop {
        if len <= TAG {
            return Err(CoreError::Malformed);
        }
        let next_len = fill(&mut input, &mut next)?;
        let last = next_len == 0;
        let msg = cur.get(..len).ok_or(CoreError::Malformed)?;
        let plain = Zeroizing::new(
            // The code was right (the marker opened): this is damage.
            s.decrypt(index, last, Payload { msg, aad: &header })
                .map_err(|_| CoreError::Malformed)?,
        );
        sink(&plain)?;
        if last {
            return Ok(());
        }
        core::mem::swap(&mut cur, &mut next);
        len = next_len;
        index = index.checked_add(1).ok_or(CoreError::TooLarge)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng as _;

    fn rng() -> rand::rngs::StdRng {
        rand::rngs::StdRng::seed_from_u64(7)
    }

    fn roundtrip(code: &BackupCode, file: &[u8]) -> Result<Vec<u8>> {
        let mut got = Vec::new();
        open(code, file, |c| {
            got.extend_from_slice(c);
            Ok(())
        })?;
        Ok(got)
    }

    #[test]
    fn backups_round_trip_and_detect_any_change() {
        let code = BackupCode::generate(&mut rng());
        for size in [1, 100, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK + 5] {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let mut file = Vec::new();
            seal_with(&mut rng(), &code, KdfParams::FLOOR, &data[..], &mut file).unwrap();
            assert_eq!(roundtrip(&code, &file).unwrap(), data, "{size}");
            // Truncated at a chunk boundary, or by a byte: refused.
            if size > CHUNK {
                assert!(roundtrip(&code, &file[..HEADER_LEN + CHUNK + TAG]).is_err());
            }
            assert!(roundtrip(&code, &file[..file.len() - 1]).is_err());
            // Extended: refused.
            let mut longer = file.clone();
            longer.extend_from_slice(&[0; 40]);
            assert!(roundtrip(&code, &longer).is_err());
            // Damage past the marker is told apart from a wrong code.
            let mut past = file.clone();
            let at = HEADER_LEN + MARKER.len() + TAG + 3;
            past[at] ^= 1;
            assert_eq!(roundtrip(&code, &past).err(), Some(CoreError::Malformed));
            // Any bit, header included: refused.
            for at in [0, 8, 20, HEADER_LEN - 1, HEADER_LEN, file.len() - 1] {
                let mut bad = file.clone();
                bad[at] ^= 1;
                assert!(roundtrip(&code, &bad).is_err(), "bit at {at}");
            }
        }
        let other = BackupCode::generate(&mut rand::rngs::StdRng::seed_from_u64(8));
        let mut file = Vec::new();
        seal(&mut rng(), &code, &b"secret"[..], &mut file).unwrap();
        assert_eq!(roundtrip(&other, &file).err(), Some(CoreError::AuthFailed));
        assert!(seal(&mut rng(), &code, &b""[..], &mut Vec::new()).is_err());
    }

    #[test]
    fn kdf_parameters_are_bounded_before_argon2_runs() {
        let code = BackupCode::generate(&mut rng());
        let mut file = Vec::new();
        seal_with(&mut rng(), &code, KdfParams::FLOOR, &b"x"[..], &mut file).unwrap();
        // m = 4 GiB would be refused before allocating anything.
        let mut huge = file.clone();
        huge[8..12].copy_from_slice(&(4 * 1024 * 1024u32).to_be_bytes());
        assert_eq!(roundtrip(&code, &huge).err(), Some(CoreError::Malformed));
        let mut weak = file.clone();
        weak[12..16].copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(roundtrip(&code, &weak).err(), Some(CoreError::Malformed));
        let mut v2 = file;
        v2[7] = 2;
        assert_eq!(roundtrip(&code, &v2).err(), Some(CoreError::UnsupportedVersion));
        assert!(roundtrip(&code, b"VEILBAK").is_err());
    }

    #[test]
    fn codes_are_typed_forgivingly_but_strictly_checked() {
        let code = BackupCode::generate(&mut rng());
        assert_eq!(code.expose().len(), CODE_LEN);
        let shown = code.display();
        assert_eq!(shown.len(), CODE_LEN + 7);
        let typed = shown.to_lowercase().replace('-', " ");
        assert_eq!(BackupCode::parse(&typed).unwrap().expose(), code.expose());
        let with_lookalikes = code.expose().replace('0', "o").replace('1', "l");
        assert_eq!(
            BackupCode::parse(&with_lookalikes).unwrap().expose(),
            code.expose()
        );
        assert!(BackupCode::parse(&code.expose()[1..]).is_err());
        assert!(BackupCode::parse(&format!("{}U", &code.expose()[1..])).is_err());
        assert!(BackupCode::parse(&format!("{}é", &code.expose()[1..])).is_err());
    }
}
