//! Attachment encryption (PROTOCOL §9). Implemented in a later step; constants are
//! shared with content validation.

/// Largest padded attachment accepted (100 MiB plaintext, Padmé-padded).
pub const MAX_ATTACHMENT_PADDED: u64 = 110 * 1024 * 1024;
