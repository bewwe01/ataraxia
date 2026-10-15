//! Length-hiding padding (PROTOCOL §6, §9).
//!
//! * [`pad_block`] / [`unpad_block`]: ISO/IEC 7816-4 padding to a multiple of
//!   256 bytes, applied to plaintext `Content` *inside* the encryption.
//! * [`ENVELOPE_BUCKETS`] / [`bucket_for`]: fixed envelope sizes on the wire.
//! * [`padme_len`]: the Padmé function for attachments (Nikitin et al., 2019),
//!   which leaks at most O(log log L) bits of the length.

use crate::error::{CoreError, Result};

/// Block size for content padding.
pub const BLOCK: usize = 256;

/// The only envelope sizes that may appear on the wire (INV-META-3).
pub const ENVELOPE_BUCKETS: [usize; 4] = [1024, 4096, 16_384, 65_536];

/// Pads `data` with `0x80` followed by zero bytes to the next multiple of [`BLOCK`].
/// Always adds at least one byte, so the padding is unambiguous.
pub fn pad_block(data: &[u8]) -> Vec<u8> {
    let target = data.len().div_ceil(BLOCK).max(1).saturating_mul(BLOCK);
    let target = if target == data.len() {
        target.saturating_add(BLOCK)
    } else {
        target
    };
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(data);
    out.push(0x80);
    out.resize(target, 0);
    out
}

/// Removes ISO/IEC 7816-4 padding added by [`pad_block`]. Rejects any other shape.
pub fn unpad_block(data: &[u8]) -> Result<&[u8]> {
    if data.is_empty() || !data.len().is_multiple_of(BLOCK) {
        return Err(CoreError::Malformed);
    }
    let marker = data.iter().rposition(|&b| b != 0).ok_or(CoreError::Malformed)?;
    // Padding must be at most one block long, and must start with 0x80.
    if data.len().saturating_sub(marker) > BLOCK || data.get(marker) != Some(&0x80) {
        return Err(CoreError::Malformed);
    }
    data.get(..marker).ok_or(CoreError::Malformed)
}

/// Smallest envelope bucket that fits `len` bytes, or `TooLarge`.
pub fn bucket_for(len: usize) -> Result<usize> {
    ENVELOPE_BUCKETS
        .iter()
        .copied()
        .find(|&b| b >= len)
        .ok_or(CoreError::TooLarge)
}

/// Padmé: the padded length for an attachment of `len` bytes.
/// Returns `len` unchanged for `len < 2`.
pub fn padme_len(len: u64) -> u64 {
    if len < 2 {
        return len;
    }
    // E = floor(log2 L), S = floor(log2 E) + 1, lastBits = E - S
    let e = 63_u32.saturating_sub(len.leading_zeros());
    let s = 32_u32.saturating_sub(e.leading_zeros());
    let last_bits = e.saturating_sub(s);
    let mask = (1_u64 << last_bits).saturating_sub(1);
    len.checked_add(mask).map_or(u64::MAX, |v| v & !mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn block_padding_examples() {
        assert_eq!(pad_block(&[]).len(), 256);
        assert_eq!(pad_block(&[1; 255]).len(), 256);
        assert_eq!(pad_block(&[1; 256]).len(), 512);
        assert_eq!(unpad_block(&pad_block(b"hi")).ok(), Some(&b"hi"[..]));
    }

    #[test]
    fn unpad_rejects_bad_shapes() {
        assert_eq!(unpad_block(&[]), Err(CoreError::Malformed));
        assert_eq!(unpad_block(&[0u8; 256]), Err(CoreError::Malformed));
        let mut p = pad_block(b"x");
        if let Some(b) = p.get_mut(1) {
            *b = 0x81;
        }
        assert_eq!(unpad_block(&p), Err(CoreError::Malformed));
        // marker followed by more than one block of zeros
        let mut long = vec![0x80];
        long.resize(512, 0);
        assert_eq!(unpad_block(&long), Err(CoreError::Malformed));
    }

    #[test]
    fn buckets() {
        assert_eq!(bucket_for(0), Ok(1024));
        assert_eq!(bucket_for(1024), Ok(1024));
        assert_eq!(bucket_for(1025), Ok(4096));
        assert_eq!(bucket_for(65_536), Ok(65_536));
        assert_eq!(bucket_for(65_537), Err(CoreError::TooLarge));
    }

    #[test]
    fn padme_known_answers() {
        // Reference values from an independent Python implementation of the paper's formula.
        for (l, p) in [
            (0, 0),
            (1, 1),
            (2, 2),
            (5, 5),
            (9, 10),
            (255, 256),
            (257, 272),
            (1000, 1024),
            (65_536, 65_536),
            (1_000_000, 1_015_808),
            (1_048_577, 1_081_344),
            (104_857_600, 104_857_600),
        ] {
            assert_eq!(padme_len(l), p, "padme({l})");
        }
    }

    proptest! {
        #[test]
        fn block_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..2000)) {
            let p = pad_block(&data);
            prop_assert_eq!(p.len() % BLOCK, 0);
            prop_assert!(p.len() > data.len());
            prop_assert_eq!(unpad_block(&p).ok(), Some(&data[..]));
        }

        #[test]
        fn padme_monotone_and_bounded(len in 2u64..(1u64 << 40)) {
            let p = padme_len(len);
            prop_assert!(p >= len);
            // overhead is at most 12% for len >= 2^10 (paper's bound); allow small lens freely
            if len >= 1024 { prop_assert!(p - len <= len / 8); }
            prop_assert!(padme_len(len + 1) >= p);
        }
    }
}
