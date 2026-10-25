//! The small files next to the vault that the unlock screen needs before anything is decrypted
//! (ADR-0012). None of them holds a key or content:
//!
//! * `unlock.cfg`: PIN or password, and whether biometric unlock is on (so the right keyboard
//!   and button show while locked);
//! * `attempts`: failed-attempt counter for the retry delay;
//! * `purge.tag`: the Purge PIN tag, or a random tag when none is set, so the file looks the
//!   same either way;
//! * `bio.wrap` / `bio.sealed`: the DB key wrapped under a random secret, and that secret sealed
//!   by the platform keystore behind biometrics.

use std::path::Path;

use serde::{Deserialize, Serialize};
use veil_core::vault::PurgeTag;

use crate::{ClientError, Result};

pub(crate) const CONFIG_FILE: &str = "unlock.cfg";
pub(crate) const ATTEMPTS_FILE: &str = "attempts";
pub(crate) const PURGE_FILE: &str = "purge.tag";
pub(crate) const BIO_WRAP_FILE: &str = "bio.wrap";
pub(crate) const BIO_SEALED_FILE: &str = "bio.sealed";
/// Largest keystore-sealed blob accepted from the platform.
pub const MAX_SEALED: usize = 4096;

/// Failed attempts allowed before delays start.
const FREE_ATTEMPTS: u32 = 5;
const FIRST_DELAY_SECS: u64 = 30;
const MAX_DELAY_SECS: u64 = 3600;

pub const MIN_PIN: usize = 6;
pub const MAX_PIN: usize = 16;
pub const MIN_PASSWORD: usize = 12;

/// How the user unlocks Veil.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SecretKind {
    /// 6 to 16 digits.
    Pin,
    /// At least 12 characters.
    #[default]
    Password,
}

/// Checks a new PIN or password against the rules for its kind.
pub fn validate(kind: SecretKind, secret: &str) -> Result<()> {
    let ok = match kind {
        SecretKind::Pin => {
            (MIN_PIN..=MAX_PIN).contains(&secret.len()) && secret.bytes().all(|b| b.is_ascii_digit())
        }
        SecretKind::Password => secret.chars().count() >= MIN_PASSWORD,
    };
    if ok { Ok(()) } else { Err(ClientError::BadInput) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Config {
    pub kind: SecretKind,
    pub biometric: bool,
}

/// Vaults made before ADR-0012 have no config file: they use a password, no biometrics.
pub fn load_config(dir: &Path) -> Config {
    let Ok(raw) = std::fs::read(dir.join(CONFIG_FILE)) else {
        return Config::default();
    };
    match raw.as_slice() {
        [1, k, b] => Config {
            kind: if *k == 1 {
                SecretKind::Pin
            } else {
                SecretKind::Password
            },
            biometric: *b == 1,
        },
        _ => Config::default(),
    }
}

pub fn store_config(dir: &Path, c: Config) -> Result<()> {
    let k = u8::from(c.kind == SecretKind::Pin);
    crate::write_atomic(dir, CONFIG_FILE, &[1, k, u8::from(c.biometric)])
}

/// (failed attempts, unix time of the last failure)
pub(crate) fn load_attempts(dir: &Path) -> (u32, u64) {
    let Ok(raw) = std::fs::read(dir.join(ATTEMPTS_FILE)) else {
        return (0, 0);
    };
    let (Some(n), Some(t)) = (raw.get(..4), raw.get(4..12)) else {
        return (0, 0);
    };
    (
        u32::from_be_bytes(n.try_into().unwrap_or_default()),
        u64::from_be_bytes(t.try_into().unwrap_or_default()),
    )
}

/// Delay after `failures` failed attempts: five free tries, then 30 s doubling to 1 h.
pub fn delay_for(failures: u32) -> u64 {
    let Some(extra) = failures.checked_sub(FREE_ATTEMPTS) else {
        return 0;
    };
    FIRST_DELAY_SECS
        .checked_shl(extra.min(16))
        .unwrap_or(MAX_DELAY_SECS)
        .min(MAX_DELAY_SECS)
}

/// Seconds until the next attempt is allowed.
pub fn wait_secs(dir: &Path, now: u64) -> u64 {
    let (n, last) = load_attempts(dir);
    remaining(n, last, now)
}

/// The wait never exceeds the delay itself, even if the clock went backwards since the last
/// failure (review U-7). Setting the clock forward skips it: the counter is a speed bump for
/// someone at the lock screen, not protection against a copy of the files.
pub fn remaining(failures: u32, last: u64, now: u64) -> u64 {
    let last = last.min(now);
    last.saturating_add(delay_for(failures)).saturating_sub(now)
}

pub fn record_failure(dir: &Path, now: u64) -> Result<()> {
    let (n, _) = load_attempts(dir);
    let mut b = n.saturating_add(1).to_be_bytes().to_vec();
    b.extend_from_slice(&now.to_be_bytes());
    crate::write_atomic(dir, ATTEMPTS_FILE, &b)
}

pub fn reset_attempts(dir: &Path) {
    let _ = std::fs::remove_file(dir.join(ATTEMPTS_FILE));
}

pub fn load_purge(dir: &Path) -> Option<PurgeTag> {
    std::fs::read(dir.join(PURGE_FILE))
        .ok()
        .and_then(|b| PurgeTag::from_bytes(&b).ok())
}

pub fn store_purge(dir: &Path, tag: &PurgeTag) -> Result<()> {
    crate::write_atomic(dir, PURGE_FILE, &tag.to_bytes())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rules_and_delays() {
        assert!(validate(SecretKind::Pin, "123456").is_ok());
        assert!(validate(SecretKind::Pin, "1234567890123456").is_ok());
        for bad in ["12345", "12345678901234567", "12345a", "１２３４５６", ""] {
            assert!(validate(SecretKind::Pin, bad).is_err(), "{bad}");
        }
        assert!(validate(SecretKind::Password, "twelve chars").is_ok());
        assert!(validate(SecretKind::Password, "eleven char").is_err());
        assert_eq!((1..=4).map(delay_for).max(), Some(0));
        assert_eq!(delay_for(5), 30);
        assert_eq!(delay_for(6), 60);
        assert_eq!(delay_for(11), 1920);
        assert_eq!(delay_for(12), 3600);
        // A failure "in the future" (clock moved back) never means more than the delay.
        assert_eq!(remaining(5, 10_000_000, 100), 30);
        assert_eq!(delay_for(u32::MAX), 3600);
    }

    #[test]
    fn files_round_trip() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(load_config(d.path()), Config::default());
        let c = Config {
            kind: SecretKind::Pin,
            biometric: true,
        };
        store_config(d.path(), c).unwrap();
        assert_eq!(load_config(d.path()), c);
        for _ in 0..5 {
            record_failure(d.path(), 1000).unwrap();
        }
        assert_eq!(wait_secs(d.path(), 1000), 30);
        assert_eq!(wait_secs(d.path(), 1031), 0);
        reset_attempts(d.path());
        assert_eq!(wait_secs(d.path(), 1000), 0);
        // Garbage files fall back safely instead of failing.
        std::fs::write(d.path().join(ATTEMPTS_FILE), b"x").unwrap();
        assert_eq!(wait_secs(d.path(), 5), 0);
    }
}
