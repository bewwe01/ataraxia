//! The device secret: the second vault factor (INV-REST-2), kept outside the database.
//!
//! * **Windows:** the Windows Credential Manager (DPAPI-protected, per user) via `keyring`.
//! * **Android and others (v1):** a file in the app's private data directory, protected by the
//!   OS app sandbox and file-based encryption. **Not** hardware-backed: moving it into the
//!   Android Keystore is a documented follow-up (INV-REST-2 is partial on Android).

use std::path::Path;

use zeroize::Zeroizing;

use crate::{ClientError, Result};

#[cfg(not(windows))]
const FILE: &str = "device.secret";

#[cfg(windows)]
fn entry() -> Result<keyring::Entry> {
    keyring::Entry::new("org.veil.app", "device-secret").map_err(|_| ClientError::Storage)
}

/// Stores a new device secret. Refuses to overwrite an existing one.
pub fn store(dir: &Path, secret: &[u8; 32]) -> Result<()> {
    #[cfg(windows)]
    {
        let _ = dir;
        let e = entry()?;
        if e.get_secret().is_ok() {
            return Err(ClientError::AlreadySetUp);
        }
        e.set_secret(secret).map_err(|_| ClientError::Storage)
    }
    #[cfg(not(windows))]
    {
        use std::io::Write as _;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts.open(dir.join(FILE)).map_err(|_| ClientError::Storage)?;
        f.write_all(secret).map_err(|_| ClientError::Storage)?;
        f.sync_all().map_err(|_| ClientError::Storage)
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
