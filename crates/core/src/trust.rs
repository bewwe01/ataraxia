//! Verification state machine for a contact (PROTOCOL §4.4, §5; INV-PAIR-3, INV-ID-2).
//!
//! Pure and exhaustively tested: "Verified" can only be reached by a mutual
//! in-person scan whose scanned key matches the session key, or by explicitly
//! confirming the safety number. Any identity change drops trust and blocks sending.

/// How a contact was first added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddedVia {
    /// Mutual QR scan in person.
    InPerson,
    /// Remote invite link (or one-sided scan).
    InviteLink,
}

/// How a contact became verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedBy {
    InPersonScan,
    SafetyNumber,
}

/// Current trust in a contact's identity key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustState {
    Unverified,
    Verified(VerifiedBy),
    /// The identity key changed and the user has not reviewed it yet.
    /// Incoming messages are held and sending is paused.
    KeyChanged {
        was_verified: bool,
    },
}

/// Events that can change trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustEvent {
    /// Both sides scanned each other in person. `keys_match` is whether the key in the
    /// scanned QR equals the identity key of the established session.
    MutualScan { keys_match: bool },
    /// The user compared safety numbers and confirmed they match.
    SafetyNumberConfirmed,
    /// The user cleared verification.
    Cleared,
    /// A message or bundle arrived under a different identity key.
    IdentityChanged,
    /// The user reviewed and accepted the new identity key.
    ChangeAccepted,
}

impl TrustState {
    /// Initial state for a newly added contact.
    pub fn initial(via: AddedVia, scan_keys_match: bool) -> Self {
        match (via, scan_keys_match) {
            (AddedVia::InPerson, true) => Self::Verified(VerifiedBy::InPersonScan),
            _ => Self::Unverified,
        }
    }

    /// Applies an event. Unlisted combinations leave the state unchanged.
    // Arms are spelled out one per rule so the state machine reads as its specification.
    #[allow(clippy::match_same_arms)]
    #[must_use]
    pub fn apply(self, event: TrustEvent) -> Self {
        use TrustEvent as E;
        match (self, event) {
            (Self::Verified(_), E::IdentityChanged) => Self::KeyChanged { was_verified: true },
            (Self::Unverified, E::IdentityChanged) => Self::KeyChanged { was_verified: false },
            (s @ Self::KeyChanged { .. }, E::IdentityChanged) => s,
            // Accepting a change never restores "verified": the new key must be verified anew.
            (Self::KeyChanged { .. }, E::ChangeAccepted) => Self::Unverified,
            // While a change is pending, nothing else may move the state.
            (s @ Self::KeyChanged { .. }, _) => s,
            (_, E::MutualScan { keys_match: true }) => Self::Verified(VerifiedBy::InPersonScan),
            (s, E::MutualScan { keys_match: false }) => s,
            (_, E::SafetyNumberConfirmed) => Self::Verified(VerifiedBy::SafetyNumber),
            (Self::Verified(_), E::Cleared) => Self::Unverified,
            (s, E::Cleared | E::ChangeAccepted) => s,
        }
    }

    /// Whether we may send to this contact.
    pub fn can_send(self) -> bool {
        !matches!(self, Self::KeyChanged { .. })
    }

    /// Whether the UI may show the verified badge.
    pub fn is_verified(self) -> bool {
        matches!(self, Self::Verified(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_STATES: [TrustState; 5] = [
        TrustState::Unverified,
        TrustState::Verified(VerifiedBy::InPersonScan),
        TrustState::Verified(VerifiedBy::SafetyNumber),
        TrustState::KeyChanged { was_verified: true },
        TrustState::KeyChanged { was_verified: false },
    ];
    const ALL_EVENTS: [TrustEvent; 6] = [
        TrustEvent::MutualScan { keys_match: true },
        TrustEvent::MutualScan { keys_match: false },
        TrustEvent::SafetyNumberConfirmed,
        TrustEvent::Cleared,
        TrustEvent::IdentityChanged,
        TrustEvent::ChangeAccepted,
    ];

    #[test]
    fn initial_states() {
        assert!(TrustState::initial(AddedVia::InPerson, true).is_verified());
        assert!(!TrustState::initial(AddedVia::InPerson, false).is_verified());
        assert!(!TrustState::initial(AddedVia::InviteLink, true).is_verified());
    }

    /// INV-PAIR-3 + INV-ID-2, exhaustively over every (state, event) pair.
    #[test]
    fn exhaustive_transition_properties() {
        for s in ALL_STATES {
            for e in ALL_EVENTS {
                let n = s.apply(e);
                // Only a matching mutual scan or an explicit confirmation can produce "verified"
                // from a non-verified state.
                if n.is_verified() && !s.is_verified() {
                    assert!(
                        matches!(
                            e,
                            TrustEvent::MutualScan { keys_match: true } | TrustEvent::SafetyNumberConfirmed
                        ),
                        "{s:?} --{e:?}--> {n:?}"
                    );
                    assert!(
                        !matches!(s, TrustState::KeyChanged { .. }),
                        "pending change must block verification"
                    );
                }
                // An identity change always blocks sending.
                if e == TrustEvent::IdentityChanged {
                    assert!(!n.can_send());
                    assert!(!n.is_verified());
                }
                // Leaving KeyChanged is only possible by accepting, and lands in Unverified.
                if matches!(s, TrustState::KeyChanged { .. }) && !matches!(n, TrustState::KeyChanged { .. }) {
                    assert_eq!(e, TrustEvent::ChangeAccepted);
                    assert_eq!(n, TrustState::Unverified);
                }
            }
        }
    }

    #[test]
    fn verified_contact_key_change_scenario() {
        let s = TrustState::initial(AddedVia::InPerson, true)
            .apply(TrustEvent::IdentityChanged)
            .apply(TrustEvent::SafetyNumberConfirmed);
        assert_eq!(s, TrustState::KeyChanged { was_verified: true });
        let s = s.apply(TrustEvent::ChangeAccepted);
        assert_eq!(s, TrustState::Unverified);
        assert!(s.can_send());
        assert!(s.apply(TrustEvent::SafetyNumberConfirmed).is_verified());
    }
}
