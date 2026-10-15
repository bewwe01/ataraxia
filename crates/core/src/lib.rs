//! # veil-core
//!
//! Pure protocol and crypto logic for Veil: identities, sessions (libsignal PQXDH +
//! Triple Ratchet), sealed envelopes, invites, safety numbers, the vault key hierarchy,
//! attachment encryption and the ICE candidate policy. **No I/O.**
//!
//! Specification: `docs/PROTOCOL.md`. Invariants: `docs/INVARIANTS.md`.
//!
//! Note: libsignal's store traits produce `!Send` futures, so the async APIs here
//! must be driven on a single thread (e.g. a `LocalSet` or `block_on`).
#![forbid(unsafe_code)]
// Tests may use arithmetic and casts freely; product code is held to the workspace lints.
#![cfg_attr(
    test,
    allow(
        clippy::arithmetic_side_effects,
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::many_single_char_names
    )
)]

pub mod account;
pub mod attachment;
pub mod content;
pub mod envelope;
pub mod error;
pub mod ice;
pub mod identity;
pub mod invite;
pub mod padding;
pub mod safety;
pub mod store;
pub mod trust;
pub mod vault;

#[cfg(test)]
mod test_vectors;

pub use error::{CoreError, Result};
