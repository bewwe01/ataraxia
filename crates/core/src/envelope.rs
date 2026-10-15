//! Wire framing of sealed envelopes (PROTOCOL §6.1 step 6, INV-META-3).
//!
//! `envelope = version (1) || len (u32 BE) || sealed (len bytes) || zero padding`,
//! with the total length always exactly one of [`ENVELOPE_BUCKETS`]. Parsing is strict:
//! the size must be a bucket, the version known, the length in range, and every padding
//! byte zero (so the padding cannot be used as a covert or malleable channel).

use crate::error::{CoreError, Result};
use crate::padding::{ENVELOPE_BUCKETS, bucket_for};

/// Current envelope framing version.
pub const VERSION: u8 = 1;
const HEADER: usize = 5;
/// Largest sealed payload that fits in the largest bucket.
pub const MAX_SEALED: usize = 65_536 - HEADER;

/// Frames a sealed-sender payload into a bucket-sized envelope.
pub fn frame(sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() > MAX_SEALED {
        return Err(CoreError::TooLarge);
    }
    let size = bucket_for(sealed.len().saturating_add(HEADER))?;
    let len = u32::try_from(sealed.len()).map_err(|_| CoreError::TooLarge)?;
    let mut out = Vec::with_capacity(size);
    out.push(VERSION);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(sealed);
    out.resize(size, 0);
    Ok(out)
}

/// Strictly parses an envelope and returns the sealed payload.
pub fn unframe(envelope: &[u8]) -> Result<&[u8]> {
    if !ENVELOPE_BUCKETS.contains(&envelope.len()) {
        return Err(if envelope.len() > MAX_SEALED.saturating_add(HEADER) {
            CoreError::TooLarge
        } else {
            CoreError::Malformed
        });
    }
    let (header, rest) = envelope.split_at_checked(HEADER).ok_or(CoreError::Malformed)?;
    let (version, len_bytes) = header.split_first().ok_or(CoreError::Malformed)?;
    if *version != VERSION {
        return Err(CoreError::UnsupportedVersion);
    }
    let len_arr: [u8; 4] = len_bytes.try_into().map_err(|_| CoreError::Malformed)?;
    let len = usize::try_from(u32::from_be_bytes(len_arr)).map_err(|_| CoreError::Malformed)?;
    let (sealed, padding) = rest.split_at_checked(len).ok_or(CoreError::Malformed)?;
    // Must be the smallest bucket that fits, and padding must be all zero.
    if bucket_for(len.saturating_add(HEADER))? != envelope.len() || padding.iter().any(|&b| b != 0) {
        return Err(CoreError::Malformed);
    }
    Ok(sealed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn sizes_are_buckets() {
        for n in [0, 1, 1019, 1020, 4091, 4092, 16_000, MAX_SEALED] {
            let e = frame(&vec![0xAB; n]).unwrap();
            assert!(ENVELOPE_BUCKETS.contains(&e.len()), "{n} -> {}", e.len());
            assert_eq!(unframe(&e).unwrap(), &vec![0xAB; n][..]);
        }
        assert_eq!(frame(&vec![0; MAX_SEALED + 1]), Err(CoreError::TooLarge));
    }

    #[test]
    fn strict_parsing() {
        let e = frame(b"hello").unwrap();
        let mut bad = e.clone();
        bad[0] = 2;
        assert_eq!(unframe(&bad), Err(CoreError::UnsupportedVersion));
        let mut bad = e.clone();
        *bad.last_mut().unwrap() = 1;
        assert_eq!(unframe(&bad), Err(CoreError::Malformed), "non-zero padding");
        let mut bad = e.clone();
        bad[1] = 0xFF;
        assert!(unframe(&bad).is_err(), "length beyond envelope");
        // Note: a length change that stays inside the zero padding cannot be detected by the
        // (unauthenticated) framing; the sealed-sender layer rejects it. That is covered by
        // tests/session.rs::every_bit_flip_rejected_and_state_unchanged.
        assert!(unframe(&e[..1023]).is_err());
        // Payload that would fit a smaller bucket but is sent in a bigger one.
        let mut big = vec![VERSION, 0, 0, 0, 5];
        big.extend_from_slice(b"hello");
        big.resize(4096, 0);
        assert_eq!(unframe(&big), Err(CoreError::Malformed));
    }

    proptest! {
        #[test]
        fn roundtrip(data in proptest::collection::vec(any::<u8>(), 0..20_000)) {
            let e = frame(&data).unwrap();
            prop_assert_eq!(unframe(&e).unwrap(), &data[..]);
        }

        #[test]
        fn arbitrary_never_panics(data in proptest::collection::vec(any::<u8>(), 0..5000)) {
            let _ = unframe(&data);
        }
    }
}
