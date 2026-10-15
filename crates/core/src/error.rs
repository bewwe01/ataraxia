//! Error type for `veil-core`.
//!
//! Display strings are deliberately coarse: they never contain key material,
//! plaintext, addresses, tokens or sizes, so they are safe to log (CLAUDE.md).

use libsignal_protocol::SignalProtocolError;

/// All failures surfaced by `veil-core`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CoreError {
    /// Input could not be parsed (wrong length, bad encoding, non-canonical form).
    #[error("malformed input")]
    Malformed,
    /// Input exceeds a protocol size limit; rejected before parsing.
    #[error("input too large")]
    TooLarge,
    /// Wire or message version is unknown or below the minimum (downgrade).
    #[error("unsupported version")]
    UnsupportedVersion,
    /// A MAC, AEAD tag or signature did not verify.
    #[error("authentication failed")]
    AuthFailed,
    /// The message was already processed (replay).
    #[error("duplicate message")]
    Replay,
    /// The sender is not a known contact and did not redeem one of our invites.
    #[error("unknown sender")]
    UnknownSender,
    /// The peer's identity key differs from the stored one. Never auto-accepted (INV-ID-2).
    #[error("identity key changed")]
    IdentityChanged,
    /// No session exists with this peer.
    #[error("no session")]
    NoSession,
    /// Invite is expired, revoked, already used, or does not match.
    #[error("invite invalid")]
    InviteInvalid,
    /// Wrong passphrase, wrong device secret, or corrupted vault header.
    #[error("vault unlock failed")]
    VaultUnlock,
    /// The storage backend failed.
    #[error("storage error")]
    Storage,
    /// Any other protocol-level failure.
    #[error("protocol error")]
    Protocol,
}

/// Result alias.
pub type Result<T> = core::result::Result<T, CoreError>;

impl From<SignalProtocolError> for CoreError {
    fn from(e: SignalProtocolError) -> Self {
        use SignalProtocolError as E;
        match e {
            E::DuplicatedMessage(..) => Self::Replay,
            E::UntrustedIdentity(_) => Self::IdentityChanged,
            E::SessionNotFound(_) | E::InvalidSessionStructure(_) => Self::NoSession,
            E::InvalidMessage(..)
            | E::InvalidSealedSenderMessage(_)
            | E::SignatureValidationFailed
            | E::InvalidMacKeyLength(_)
            | E::BadKeyType(_)
            | E::BadKeyLength(..)
            | E::InvalidPreKeyId
            | E::InvalidSignedPreKeyId
            | E::InvalidKyberPreKeyId
            | E::SealedSenderSelfSend
            | E::InvalidKeyAgreement
            | E::BadKEMKeyType(_)
            | E::WrongKEMKeyType(..)
            | E::BadKEMKeyLength(..)
            | E::BadKEMCiphertextLength(..)
            | E::NoKeyTypeIdentifier => Self::AuthFailed,
            E::InvalidProtobufEncoding | E::CiphertextMessageTooShort(_) | E::InvalidArgument(_) => {
                Self::Malformed
            }
            E::UnrecognizedMessageVersion(_)
            | E::UnrecognizedCiphertextVersion(_)
            | E::LegacyCiphertextVersion(_)
            | E::UnknownSealedSenderVersion(_) => Self::UnsupportedVersion,
            _ => Self::Protocol,
        }
    }
}
