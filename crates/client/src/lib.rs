//! Veil client: the async I/O half of the app (ARCHITECTURE §2). It owns the encrypted local
//! store, the pinned relay connection and the protocol account, and exposes a small command API
//! that returns **display data only** (CLAUDE.md non-negotiable 2): no keys, no ciphertext, no
//! file paths ever leave this crate.
//!
//! Scope of v1 (see docs/ARCHITECTURE.md, "Phase 4 scope"): one relay, one mailbox, text
//! messages, invites by link/QR, safety-number verification.
#![forbid(unsafe_code)]

pub mod db;
pub mod keystore;
pub mod qr;
pub mod relay;
pub mod service;

/// Client errors. Display strings are short, user-facing and never contain content, keys or
/// addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    #[error("Invalid input")]
    BadInput,
    #[error("The relay could not be reached")]
    Unreachable,
    #[error("The relay's key does not match the pin. Not connecting.")]
    PinMismatch,
    #[error("The relay sent an invalid response")]
    Relay,
    #[error("The relay refused the request")]
    Rejected(veil_wire::ErrorCode),
    #[error("Wrong passphrase")]
    WrongPassphrase,
    #[error("Local storage failed")]
    Storage,
    #[error("Veil is locked")]
    Locked,
    #[error("Veil is already set up")]
    AlreadySetUp,
    #[error("This invite is invalid, expired or already used")]
    InviteInvalid,
    #[error("This invite is for a different relay; this version supports one relay")]
    OtherRelay,
    #[error("Unknown contact")]
    UnknownContact,
    #[error("Message failed")]
    Protocol,
}

impl From<veil_core::CoreError> for ClientError {
    fn from(e: veil_core::CoreError) -> Self {
        use veil_core::CoreError as E;
        match e {
            E::VaultUnlock => Self::WrongPassphrase,
            E::InviteInvalid => Self::InviteInvalid,
            E::Storage => Self::Storage,
            E::Malformed | E::TooLarge => Self::BadInput,
            _ => Self::Protocol,
        }
    }
}

impl From<rusqlite::Error> for ClientError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}

pub type Result<T> = core::result::Result<T, ClientError>;

/// Current unix time in seconds.
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Current unix time in milliseconds.
pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}
