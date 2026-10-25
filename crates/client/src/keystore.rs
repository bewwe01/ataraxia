//! The device secret: the second vault factor (INV-REST-2), kept outside the database.
//!
//! * **Windows:** the Windows Credential Manager (DPAPI-protected, per user) via `keyring`.
//! * **Android:** the file `device.secret`, sealed by a hardware-backed Android Keystore key
//!   through a [`DeviceGuard`] the app supplies (ADR-0012, review U-2). The key never leaves the
//!   secure hardware, so a copy of the file is useless off the phone, and deleting the key (Start
//!   over, Purge PIN) makes every old copy unreadable.
//! * **Elsewhere, or without a guard:** the same file holds the secret itself (0600). Not
//!   hardware-backed; INV-REST-2 is partial there.

use std::path::Path;
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::{ClientError, Result};

pub(crate) const FILE: &str = "device.secret";
/// File format with a guard: this byte, then the guard's sealed blob.
#[cfg(not(windows))]
const SEALED_V1: u8 = 2;
#[cfg(not(windows))]
const MAX_SEALED: usize = 1024;

/// Platform key protection for the device secret (the Android Keystore in the app).
pub trait DeviceGuard: Send + Sync {
    /// Seals the secret under a non-exportable platform key, creating the key if needed.
    fn seal(&self, secret: &[u8; 32]) -> Option<Vec<u8>>;
    /// Opens a blob from [`DeviceGuard::seal`].
    fn open(&self, blob: &[u8]) -> Option<Zeroizing<[u8; 32]>>;
    /// Deletes the platform key. Returns false if it may still exist.
    fn destroy(&self) -> bool;
}

pub type Guard = Option<Arc<dyn DeviceGuard>>;

#[cfg(windows)]
fn entry() -> Result<keyring::Entry> {
    keyring::Entry::new("org.veil.app", "device-secret").map_err(|_| ClientError::Storage)
}

/// Stores the device secret, replacing any earlier one. Only setup calls this, and only when
/// no vault header exists, so whatever it replaces belongs to no usable vault (review P4-3).
pub fn store(dir: &Path, secret: &[u8; 32], guard: &Guard) -> Result<()> {
    #[cfg(windows)]
    {
        let _ = (dir, guard);
        entry()?.set_secret(secret).map_err(|_| ClientError::Storage)
    }
    #[cfg(not(windows))]
    {
        let bytes = Zeroizing::new(match guard {
            Some(g) => {
                let sealed = g.seal(secret).ok_or(ClientError::Storage)?;
                // Never 31 bytes, so the file can never be 32 bytes and read as plain.
                if sealed.len() == 31 || sealed.len() > MAX_SEALED {
                    return Err(ClientError::Storage);
                }
                let mut b = vec![SEALED_V1];
                b.extend_from_slice(&sealed);
                b
            }
            None => secret.to_vec(),
        });
        write_private(dir, &bytes)
    }
}

#[cfg(not(windows))]
fn write_private(dir: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let tmp = dir.join(format!("{FILE}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp).map_err(|_| ClientError::Storage)?;
    f.write_all(bytes).map_err(|_| ClientError::Storage)?;
    f.sync_all().map_err(|_| ClientError::Storage)?;
    drop(f);
    std::fs::rename(&tmp, dir.join(FILE)).map_err(|_| ClientError::Storage)
}

/// Deletes the device secret and the platform key, if there are any. Fails if either may
/// still exist (review UR2-6).
pub fn remove(dir: &Path, guard: &Guard) -> Result<()> {
    // The file first, then the platform key, so a failing key delete cannot keep the file
    // around (review UR3-2).
    #[cfg(windows)]
    let file = {
        let _ = dir;
        match entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(ClientError::Storage),
        }
    };
    #[cfg(not(windows))]
    let file = match std::fs::remove_file(dir.join(FILE)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ClientError::Storage),
    };
    let key_gone = guard.as_ref().is_none_or(|g| g.destroy());
    file.and(if key_gone {
        Ok(())
    } else {
        Err(ClientError::Storage)
    })
}

/// Loads the device secret. A plain (pre-guard) file is sealed in place when a guard is present.
pub fn load(dir: &Path, guard: &Guard) -> Result<Zeroizing<[u8; 32]>> {
    #[cfg(windows)]
    let raw = {
        let _ = guard;
        Zeroizing::new(entry()?.get_secret().map_err(|_| ClientError::Storage)?)
    };
    #[cfg(not(windows))]
    let raw = Zeroizing::new(std::fs::read(dir.join(FILE)).map_err(|_| ClientError::Storage)?);
    // Decide by length first: a plain secret is exactly 32 bytes and may start with any
    // byte, a sealed one is never 32 bytes long (review UR2-1).
    #[cfg(not(windows))]
    if raw.len() != 32 {
        let Some((&SEALED_V1, sealed)) = raw.split_first() else {
            return Err(ClientError::Storage);
        };
        if sealed.len() > MAX_SEALED || sealed.len() == 31 {
            return Err(ClientError::Storage);
        }
        let g = guard.as_ref().ok_or(ClientError::Storage)?;
        return g.open(sealed).ok_or(ClientError::Storage);
    }
    let mut out = Zeroizing::new([0u8; 32]);
    if raw.len() != 32 {
        return Err(ClientError::Storage);
    }
    out.copy_from_slice(&raw);
    // Upgrade a plain file from before the guard existed. Best effort: the plain copy is
    // replaced atomically, and on failure the old file still works.
    #[cfg(not(windows))]
    if guard.is_some() {
        let _ = store(dir, &out, guard);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Stand-in for the Android Keystore: XOR with a key that `destroy` forgets.
    struct FakeGuard(Mutex<Option<[u8; 32]>>);

    impl DeviceGuard for FakeGuard {
        fn seal(&self, secret: &[u8; 32]) -> Option<Vec<u8>> {
            let mut k = self.0.lock().unwrap();
            let key = *k.get_or_insert([0x42; 32]);
            Some(secret.iter().zip(key).map(|(a, b)| a ^ b).collect())
        }
        fn open(&self, blob: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
            let key = (*self.0.lock().unwrap())?;
            let v: Vec<u8> = blob.iter().zip(key).map(|(a, b)| a ^ b).collect();
            Some(Zeroizing::new(v.try_into().ok()?))
        }
        fn destroy(&self) -> bool {
            *self.0.lock().unwrap() = None;
            true
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn guard_seals_upgrades_and_destroy_erases() {
        let d = tempfile::tempdir().unwrap();
        let fake = Arc::new(FakeGuard(Mutex::new(None)));
        let guard: Guard = Some(fake.clone());
        let secret = [7u8; 32];

        // A plain file from an older install is upgraded on first load.
        store(d.path(), &secret, &None).unwrap();
        assert_eq!(std::fs::read(d.path().join(FILE)).unwrap(), secret.to_vec());
        assert_eq!(*load(d.path(), &guard).unwrap(), secret);
        let on_disk = std::fs::read(d.path().join(FILE)).unwrap();
        assert_eq!(on_disk.first(), Some(&SEALED_V1));
        assert!(!on_disk.windows(32).any(|w| w == secret));
        assert_eq!(*load(d.path(), &guard).unwrap(), secret);

        // A copy of the file is useless once the platform key is gone.
        let copy = std::fs::read(d.path().join(FILE)).unwrap();
        remove(d.path(), &guard).unwrap();
        assert!(!d.path().join(FILE).exists());
        std::fs::write(d.path().join(FILE), &copy).unwrap();
        assert!(load(d.path(), &guard).is_err());
        // Without a guard a sealed file cannot be read either.
        assert!(load(d.path(), &None).is_err());
    }

    /// A plain secret starting with the sealed-format byte is still plain (review UR2-1).
    #[cfg(not(windows))]
    #[test]
    fn plain_secret_starting_with_format_byte() {
        let mut secret = [9u8; 32];
        secret[0] = SEALED_V1;
        let d = tempfile::tempdir().unwrap();
        store(d.path(), &secret, &None).unwrap();
        assert_eq!(*load(d.path(), &None).unwrap(), secret);
        let guard: Guard = Some(Arc::new(FakeGuard(Mutex::new(None))));
        assert_eq!(*load(d.path(), &guard).unwrap(), secret);
        assert_eq!(*load(d.path(), &guard).unwrap(), secret);
    }
}
