//! Known-answer vectors, computed independently (Python `hashlib`, `cryptography`,
//! `argon2-cffi`) and NOT by this crate, so the tests compare against an outside oracle.
//! Regenerate with `crates/core/tests/vectors/gen.py`.
#![cfg(test)]

/// `Address::of(0x05 || 0x01 * 32)`
pub const ADDR_OF_05_01X32: &str = "v1:eab28c3f15575401c12c958fab4b3049d34c8c4c";
/// `display_fingerprint(0x05 || 0x01 * 32)`
pub const FP_OF_05_01X32: &str = "AD28 79F0 B1AC 2827 7FC3 4898 63F9 1591";
