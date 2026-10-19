//! Wire framing of sealed envelopes (PROTOCOL §6.1 step 6, INV-META-3).
//!
//! `envelope = version (1) || sealed`, where the whole envelope is exactly one of
//! [`ENVELOPE_BUCKETS`]. There is no length field and no padding outside the encryption:
//! the sealer fills the bucket *inside* the sealed-sender ciphertext (see
//! `Account::seal`), so nothing the relay can read depends on the content length or on
//! the message type (review round 1, H1).

use crate::error::{CoreError, Result};
use crate::padding::ENVELOPE_BUCKETS;

/// Current envelope framing version.
pub const VERSION: u8 = 2;
/// Bytes in front of the sealed payload.
pub const HEADER: usize = 1;
/// Largest sealed payload (fills the largest bucket).
pub const MAX_SEALED: usize = 65_536 - HEADER;

/// Sealed payload size that exactly fills `bucket`.
pub const fn sealed_len_for(bucket: usize) -> usize {
    bucket.saturating_sub(HEADER)
}

/// Frames a sealed-sender payload. It must already fill a bucket exactly.
pub fn frame(sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() > MAX_SEALED {
        return Err(CoreError::TooLarge);
    }
    if !ENVELOPE_BUCKETS.contains(&sealed.len().saturating_add(HEADER)) {
        return Err(CoreError::Malformed);
    }
    let mut out = Vec::with_capacity(sealed.len().saturating_add(HEADER));
    out.push(VERSION);
    out.extend_from_slice(sealed);
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
    let (version, sealed) = envelope.split_first().ok_or(CoreError::Malformed)?;
    if *version != VERSION {
        return Err(CoreError::UnsupportedVersion);
    }
    Ok(sealed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn sizes_are_buckets() {
        for b in ENVELOPE_BUCKETS {
            let sealed = vec![0xAB; sealed_len_for(b)];
            let e = frame(&sealed).unwrap();
            assert_eq!(e.len(), b);
            assert_eq!(unframe(&e).unwrap(), &sealed[..]);
        }
        assert_eq!(frame(&vec![0; MAX_SEALED + 1]), Err(CoreError::TooLarge));
        // A payload that does not fill a bucket exactly is refused, never zero-padded.
        assert_eq!(frame(b"hello"), Err(CoreError::Malformed));
        assert_eq!(
            frame(&vec![0; sealed_len_for(1024) - 1]),
            Err(CoreError::Malformed)
        );
    }

    #[test]
    fn strict_parsing() {
        let e = frame(&[7; 1023]).unwrap();
        let mut bad = e.clone();
        bad[0] = 1;
        assert_eq!(
            unframe(&bad),
            Err(CoreError::UnsupportedVersion),
            "old v1 framing"
        );
        assert!(unframe(&e[..1022]).is_err());
        assert!(unframe(&[]).is_err());
        let mut long = e.clone();
        long.push(0);
        assert!(unframe(&long).is_err());
    }

    proptest! {
        #[test]
        fn roundtrip(idx in 0usize..4, fill in any::<u8>()) {
            let sealed = vec![fill; sealed_len_for(ENVELOPE_BUCKETS[idx])];
            let e = frame(&sealed).unwrap();
            prop_assert_eq!(unframe(&e).unwrap(), &sealed[..]);
        }

        #[test]
        fn arbitrary_never_panics(data in proptest::collection::vec(any::<u8>(), 0..5000)) {
            let _ = unframe(&data);
        }
    }
}
