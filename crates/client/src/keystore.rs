//! The device secret: the second vault factor (INV-REST-2), kept outside the database.
//!
//! * **Windows:** the Windows Credential Manager (DPAPI-protected, per user) via `keyring`.
//! * **Android and others (v1):** a file in the app's private data directory, protected by the
//!   OS app sandbox and file-based encryption, and excluded from Android backups and device
//!   transfer (`app/android/harden.py`). **Not** hardware-backed: moving it into the Android
//!   Keystore is a documented follow-up (INV-REST-2 is partial on Android).

use std::path::Path;

use zeroize::Zeroizing;

use crate::{ClientError, Result};

#[cfg(not(windows))]
const FILE: &str = "device.secret";

#[cfg(windows)]
fn entry() -> Result<keyring::Entry> {
    keyring::Entry::new("org.veil.app", "device-secret").map_err(|_| ClientError::Storage)
}

/// Stores the device secret, replacing any earlier one. Only setup calls this, and only when
/// no vault header exists, so whatever it replaces belongs to no usable vault (review P4-3).
pub fn store(dir: &Path, secret: &[u8; 32]) -> Result<()> {
    #[cfg(windows)]
    {
        let _ = dir;
        entry()?.set_secret(secret).map_err(|_| ClientError::Storage)
    }
    #[cfg(not(windows))]
    {
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
        f.write_all(secret).map_err(|_| ClientError::Storage)?;
        f.sync_all().map_err(|_| ClientError::Storage)?;
        drop(f);
        std::fs::rename(&tmp, dir.join(FILE)).map_err(|_| ClientError::Storage)
    }
}

/// Deletes the device secret, if there is one.
pub fn remove(dir: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        let _ = dir;
        match entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(ClientError::Storage),
        }
    }
    #[cfg(not(windows))]
    match std::fs::remove_file(dir.join(FILE)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ClientError::Storage),
    }
}

/// Loads the device secret.
pub fn load(dir: &Path) -> Result<Zeroizing<[u8; 32]>> {
    #[cfg(windows)]
    let raw = {
        let _ = dir;
        Zeroizing::new(entry()?.get_secret().map_err(|_| ClientError::Storage)?)
    };
    #[cfg(not(windows))]
    let raw = Zeroizing::new(std::fs::read(dir.join(FILE)).map_err(|_| ClientError::Storage)?);
    let mut out = Zeroizing::new([0u8; 32]);
    if raw.len() != 32 {
        return Err(ClientError::Storage);
    }
    out.copy_from_slice(&raw);
    Ok(out)
}
