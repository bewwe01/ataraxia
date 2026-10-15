//! Known-answer vectors, computed independently by `tests/vectors/gen.py` (Python stdlib +
//! argon2-cffi + pyca/cryptography, with HChaCha20/STREAM implemented from the specs), NOT by
//! this crate, so tests compare against an outside oracle. Regenerate: `python3 gen.py`.
#![cfg(test)]

/// `Address::of(0x05 || 0x01 * 32)`
pub const ADDR_OF_05_01X32: &str = "v1:eab28c3f15575401c12c958fab4b3049d34c8c4c";
/// `display_fingerprint(0x05 || 0x01 * 32)`
pub const FP_OF_05_01X32: &str = "AD28 79F0 B1AC 2827 7FC3 4898 63F9 1591";
/// Passphrase for `VAULT_HEADER`.
pub const VAULT_PASSPHRASE: &[u8] = b"lantern orbit maple quietly";
/// Device secret for `VAULT_HEADER`.
pub const VAULT_DEVICE_SECRET: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
    29, 30, 31,
];
/// DB key wrapped in `VAULT_HEADER`.
pub const VAULT_DB_KEY: [u8; 32] = [
    68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68,
    68, 68, 68, 68, 68, 68,
];
/// A complete vault header (m=64 KiB, t=1, p=1).
pub const VAULT_HEADER: [u8; 124] = [
    86, 69, 73, 76, 86, 76, 84, 1, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 0, 0, 0,
    64, 0, 0, 0, 1, 0, 0, 0, 1, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 51, 51, 51,
    51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 151, 15, 175, 152,
    169, 223, 247, 34, 145, 91, 14, 204, 99, 13, 94, 160, 93, 196, 246, 87, 39, 39, 109, 199, 91, 47, 179,
    85, 134, 69, 38, 123, 100, 71, 187, 54, 133, 182, 139, 116, 27, 123, 159, 128, 138, 122, 126, 121,
];
pub const ATT_KEY: [u8; 32] = [
    85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
    85, 85, 85, 85, 85, 85,
];
pub const ATT_PREFIX: [u8; 19] = [
    102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
];
pub const ATT_PLAIN_PADDED: &[u8] = &[
    104, 101, 108, 108, 111, 32, 97, 116, 116, 97, 99, 104, 109, 101, 110, 116, 128,
];
pub const ATT_CT: [u8; 33] = [
    226, 43, 207, 196, 128, 45, 37, 243, 65, 127, 173, 31, 220, 62, 187, 165, 243, 4, 235, 167, 233, 20, 206,
    237, 180, 167, 246, 224, 96, 169, 61, 124, 149,
];
