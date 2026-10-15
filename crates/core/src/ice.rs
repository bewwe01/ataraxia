//! ICE candidate and SDP policy (PROTOCOL §8, INV-NET-1, INV-NET-4).
//!
//! This is the Rust-side enforcement of the transport privacy modes. It runs on every
//! outgoing and incoming SDP and candidate, independently of the WebRTC stack's own
//! `iceTransportPolicy`, because webviews have been observed to gather host candidates
//! (docs/SPIKES.md §C).
//!
//! * **Relay-only:** only `typ relay` candidates pass, and their `raddr`/`rport` are
//!   rewritten to `0.0.0.0 0` because they can reveal our own reflexive/local address.
//! * **Direct:** host/srflx/prflx/relay pass, but private, loopback, link-local, CGNAT,
//!   ULA and mDNS (`.local`) addresses are dropped unless LAN mode is enabled; `raddr` is
//!   always zeroed.
//! * SDP must carry exactly one distinct `sha-256` DTLS fingerprint and a valid `a=setup`
//!   role for its side of the negotiation.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{CoreError, Result};

/// Maximum SDP size accepted.
pub const MAX_SDP: usize = 16 * 1024;
const MAX_CANDIDATE: usize = 512;

/// Transport privacy mode for one contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Default: peers never learn each other's addresses.
    RelayOnly,
    /// Opt-in per contact. `allow_lan` additionally permits private-network candidates.
    Direct { allow_lan: bool },
}

/// Offer or answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdpRole {
    Offer,
    Answer,
}

/// Applies the policy to a single candidate (with or without the `a=` prefix).
/// Returns the (possibly rewritten) candidate to keep, or `None` to drop it.
pub fn filter_candidate(line: &str, mode: Mode) -> Option<String> {
    if line.len() > MAX_CANDIDATE || line.chars().any(char::is_control) {
        return None;
    }
    let (prefix, body) = match line.strip_prefix("a=") {
        Some(b) => ("a=", b),
        None => ("", line),
    };
    let body = body.strip_prefix("candidate:")?;
    let mut tokens: Vec<&str> = body.split(' ').collect();
    // foundation component transport priority address port "typ" type ...
    if tokens.len() < 8 || tokens.get(6) != Some(&"typ") {
        return None;
    }
    let address = *tokens.get(4)?;
    let kind = *tokens.get(7)?;
    let transport = tokens.get(2)?.to_ascii_lowercase();
    if transport != "udp" && transport != "tcp" {
        return None;
    }
    tokens.get(5)?.parse::<u16>().ok()?;
    let allowed = match (mode, kind) {
        (Mode::RelayOnly, "relay") => true,
        (Mode::Direct { allow_lan }, "host" | "srflx" | "prflx" | "relay") => allow_lan || is_public(address),
        _ => false,
    };
    if !allowed {
        return None;
    }
    // Zero related address/port: they can reveal our reflexive or local address.
    let mut i = 8;
    while i < tokens.len() {
        match tokens.get(i).copied() {
            Some("raddr") => {
                if let Some(t) = tokens.get_mut(i.saturating_add(1)) {
                    *t = "0.0.0.0";
                }
                i = i.saturating_add(2);
            }
            Some("rport") => {
                if let Some(t) = tokens.get_mut(i.saturating_add(1)) {
                    *t = "0";
                }
                i = i.saturating_add(2);
            }
            _ => i = i.saturating_add(1),
        }
    }
    Some(format!("{prefix}candidate:{}", tokens.join(" ")))
}

/// Whether an address token is a public unicast IP (mDNS hostnames and unparsable
/// tokens are treated as non-public).
fn is_public(addr: &str) -> bool {
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => is_public_v4(v4),
        Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public_v4(v4),
            None => is_public_v6(v6),
        },
        Err(_) => false,
    }
}

fn is_public_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    let cgnat = o[0] == 100 && (64..128).contains(&o[1]);
    !(a.is_private()
        || a.is_loopback()
        || a.is_link_local()
        || a.is_unspecified()
        || a.is_broadcast()
        || a.is_multicast()
        || a.is_documentation()
        || cgnat
        || o[0] == 0
        || o[0] >= 240)
}

fn is_public_v6(a: Ipv6Addr) -> bool {
    let s = a.segments();
    let ula = (s[0] & 0xfe00) == 0xfc00;
    let link_local = (s[0] & 0xffc0) == 0xfe80;
    let documentation = s[0] == 0x2001 && s[1] == 0x0db8;
    !(a.is_loopback() || a.is_unspecified() || a.is_multicast() || ula || link_local || documentation)
}

/// Filters every candidate line of an SDP and validates its DTLS parameters.
/// Use on outgoing SDP before encryption, and on incoming SDP before handing it to WebRTC.
pub fn filter_sdp(sdp: &str, mode: Mode, role: SdpRole) -> Result<String> {
    if sdp.len() > MAX_SDP {
        return Err(CoreError::TooLarge);
    }
    validate_dtls(sdp, role)?;
    let mut out = String::with_capacity(sdp.len());
    for line in sdp.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        if line.starts_with("a=candidate:") {
            if let Some(kept) = filter_candidate(line, mode) {
                out.push_str(&kept);
                out.push_str("\r\n");
            }
            continue;
        }
        if line.chars().any(char::is_control) {
            return Err(CoreError::Malformed);
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    Ok(out)
}

/// Requires exactly one distinct `sha-256` fingerprint and a role-appropriate `a=setup`.
pub fn validate_dtls(sdp: &str, role: SdpRole) -> Result<()> {
    let mut fingerprint: Option<String> = None;
    let mut setups = 0usize;
    for line in sdp.split("\r\n") {
        if let Some(fp) = line.strip_prefix("a=fingerprint:") {
            let (alg, value) = fp.split_once(' ').ok_or(CoreError::Malformed)?;
            if !alg.eq_ignore_ascii_case("sha-256") || !is_sha256_fingerprint(value) {
                return Err(CoreError::AuthFailed);
            }
            let v = value.to_ascii_uppercase();
            match &fingerprint {
                Some(existing) if existing != &v => return Err(CoreError::AuthFailed),
                _ => fingerprint = Some(v),
            }
        } else if let Some(setup) = line.strip_prefix("a=setup:") {
            let ok = match role {
                SdpRole::Offer => matches!(setup, "actpass" | "active" | "passive"),
                SdpRole::Answer => matches!(setup, "active" | "passive"),
            };
            if !ok {
                return Err(CoreError::AuthFailed);
            }
            setups = setups.saturating_add(1);
        }
    }
    if fingerprint.is_none() || setups == 0 {
        Err(CoreError::AuthFailed)
    } else {
        Ok(())
    }
}

fn is_sha256_fingerprint(v: &str) -> bool {
    let parts: Vec<&str> = v.split(':').collect();
    parts.len() == 32
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const FP: &str =
        "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";

    fn cand(addr: &str, kind: &str) -> String {
        format!(
            "a=candidate:1 1 udp 2122260223 {addr} 54321 typ {kind} raddr 192.168.1.20 rport 40000 generation 0"
        )
    }

    #[test]
    fn relay_only_keeps_only_relay_and_zeroes_raddr() {
        assert_eq!(
            filter_candidate(&cand("192.168.1.20", "host"), Mode::RelayOnly),
            None
        );
        assert_eq!(
            filter_candidate(&cand("203.0.113.9", "srflx"), Mode::RelayOnly),
            None
        );
        assert_eq!(
            filter_candidate(&cand("abcd.local", "host"), Mode::RelayOnly),
            None
        );
        let kept = filter_candidate(&cand("198.51.100.7", "relay"), Mode::RelayOnly).unwrap();
        assert!(kept.contains("typ relay"));
        assert!(kept.contains("raddr 0.0.0.0 rport 0"), "{kept}");
        assert!(!kept.contains("192.168.1.20"));
    }

    #[test]
    fn direct_drops_private_and_mdns() {
        let d = Mode::Direct { allow_lan: false };
        for private in [
            "10.0.0.1",
            "172.16.5.5",
            "192.168.0.2",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "fd00::1",
            "fe80::1",
            "::1",
            "::ffff:10.0.0.1",
            "x.local",
        ] {
            assert_eq!(filter_candidate(&cand(private, "host"), d), None, "{private}");
        }
        assert!(filter_candidate(&cand("8.8.4.4", "srflx"), d).is_some());
        assert!(filter_candidate(&cand("2a00:1450::1", "host"), d).is_some());
        assert!(filter_candidate(&cand("192.168.0.2", "host"), Mode::Direct { allow_lan: true }).is_some());
    }

    #[test]
    fn malformed_candidates_dropped() {
        for bad in [
            "",
            "a=candidate:",
            "candidate:1 1 udp 1 1.2.3.4 99999 typ relay",
            "a=candidate:1 1 sctp 1 1.2.3.4 9 typ relay",
            "a=candidate:1 1 udp 1 1.2.3.4 9 type relay",
            "a=candidate:1 1 udp 1 1.2.3.4 9 typ relay\r\na=evil",
        ] {
            assert_eq!(filter_candidate(bad, Mode::RelayOnly), None, "{bad:?}");
        }
    }

    fn sdp(setup: &str, cands: &[String]) -> String {
        let mut s = format!(
            "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\na=fingerprint:sha-256 {FP}\r\na=setup:{setup}\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
        );
        for c in cands {
            s.push_str(c);
            s.push_str("\r\n");
        }
        s
    }

    #[test]
    fn sdp_filtering_relay_only() {
        let s = sdp(
            "actpass",
            &[
                cand("192.168.1.2", "host"),
                cand("203.0.113.1", "srflx"),
                cand("198.51.100.7", "relay"),
            ],
        );
        let out = filter_sdp(&s, Mode::RelayOnly, SdpRole::Offer).unwrap();
        let kinds: Vec<&str> = out.lines().filter(|l| l.starts_with("a=candidate")).collect();
        assert_eq!(kinds.len(), 1);
        assert!(kinds[0].contains("typ relay"));
        assert!(!out.contains("192.168.1"));
        assert!(!out.contains("203.0.113.1"));
    }

    #[test]
    fn dtls_validation() {
        assert!(validate_dtls(&sdp("actpass", &[]), SdpRole::Offer).is_ok());
        assert!(
            validate_dtls(&sdp("actpass", &[]), SdpRole::Answer).is_err(),
            "answer cannot be actpass"
        );
        assert!(validate_dtls(&sdp("active", &[]), SdpRole::Answer).is_ok());
        let no_fp = sdp("active", &[]).replace(&format!("a=fingerprint:sha-256 {FP}\r\n"), "");
        assert!(validate_dtls(&no_fp, SdpRole::Answer).is_err());
        let sha1 = sdp("active", &[]).replace("sha-256", "sha-1");
        assert!(validate_dtls(&sha1, SdpRole::Answer).is_err());
        let two = sdp("active", &[]) + &format!("a=fingerprint:sha-256 {}\r\n", FP.replace("AB", "AC"));
        assert!(
            validate_dtls(&two, SdpRole::Answer).is_err(),
            "two different fingerprints"
        );
        assert!(filter_sdp(&"x".repeat(MAX_SDP + 1), Mode::RelayOnly, SdpRole::Offer).is_err());
    }

    proptest! {
        /// INV-NET-1 (core part): whatever goes in, nothing but `typ relay` comes out in relay-only mode,
        /// and no related address survives.
        #[test]
        fn relay_only_never_emits_non_relay(
            kind in prop::sample::select(vec!["host", "srflx", "prflx", "relay", "bogus"]),
            a in any::<[u8; 4]>(),
            port in any::<u16>(),
            extra in "[a-z0-9 ]{0,40}",
        ) {
            let addr = format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]);
            let line = format!("a=candidate:9 1 udp 100 {addr} {port} typ {kind} raddr 10.1.2.3 rport 5 {extra}");
            if let Some(out) = filter_candidate(&line, Mode::RelayOnly) {
                prop_assert!(out.contains(" typ relay"));
                prop_assert!(!out.contains("10.1.2.3"));
            }
        }

        #[test]
        fn arbitrary_input_never_panics(s in ".{0,800}") {
            let _ = filter_candidate(&s, Mode::RelayOnly);
            let _ = filter_candidate(&s, Mode::Direct { allow_lan: false });
            let _ = filter_sdp(&s, Mode::RelayOnly, SdpRole::Offer);
        }
    }
}
