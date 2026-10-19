//! ICE candidate and SDP policy (PROTOCOL §8, INV-NET-1, INV-NET-4).
//!
//! This is the Rust-side enforcement of the transport privacy modes. It runs on every
//! outgoing and incoming SDP and candidate, independently of the WebRTC stack's own
//! `iceTransportPolicy`, because webviews have been observed to gather host candidates
//! (docs/SPIKES.md §C).
//!
//! * **Relay-only:** only `typ relay` candidates with a public address pass, and their
//!   `raddr`/`rport` are rewritten to `0.0.0.0 0` because they can reveal our own
//!   reflexive/local address. The rest of the SDP is rebuilt from an allowlist (see
//!   [`filter_sdp`]).
//! * **Direct:** host/srflx/prflx/relay pass, but private, loopback, link-local, CGNAT and
//!   ULA addresses are dropped unless LAN mode is enabled; `raddr` is always zeroed.
//! * Candidates must use IP literals: mDNS (`.local`) and other hostnames are dropped in
//!   every mode, LAN mode included.
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

/// Applies the policy to a single candidate (with or without the `a=` prefix, any case).
/// Returns the candidate re-serialized in canonical form, or `None` to drop it.
///
/// The output is rebuilt from validated fields only: the address must be an IP literal
/// (mDNS and other hostnames are dropped), `raddr`/`rport` become `0.0.0.0 0`, and the only
/// extension attributes kept are `tcptype`, `generation`, `ufrag`, `network-id` and
/// `network-cost`, with validated values. Anything else on the line is discarded.
pub fn filter_candidate(line: &str, mode: Mode) -> Option<String> {
    if line.len() > MAX_CANDIDATE || !line.is_ascii() || line.chars().any(char::is_control) {
        return None;
    }
    let lower = line.to_ascii_lowercase();
    let (prefix, start) = if lower.starts_with("a=candidate:") {
        ("a=", "a=candidate:".len())
    } else if lower.starts_with("candidate:") {
        ("", "candidate:".len())
    } else {
        return None;
    };
    let body = line.get(start..)?;
    let tokens: Vec<&str> = body.split(' ').collect();
    // foundation component transport priority address port "typ" type [ext...]
    let (foundation, component, transport, priority, address, port, typ, kind) = (
        *tokens.first()?,
        *tokens.get(1)?,
        tokens.get(2)?.to_ascii_lowercase(),
        *tokens.get(3)?,
        *tokens.get(4)?,
        *tokens.get(5)?,
        tokens.get(6)?.to_ascii_lowercase(),
        tokens.get(7)?.to_ascii_lowercase(),
    );
    if typ != "typ"
        || !is_ice_token(foundation, 1, 32)
        || !(1..=256).contains(&component.parse::<u16>().ok()?)
        || (transport != "udp" && transport != "tcp")
    {
        return None;
    }
    let priority = priority.parse::<u32>().ok()?;
    let port = port.parse::<u16>().ok()?;
    let ip = address.parse::<IpAddr>().ok()?;
    let allowed = match (mode, kind.as_str()) {
        // A TURN relay is a public server; a "relay" candidate pointing at loopback, a private
        // network, link-local or cloud-metadata addresses is refused (review M1).
        (Mode::RelayOnly, "relay") => is_public_ip(ip),
        (Mode::Direct { allow_lan }, "host" | "srflx" | "prflx" | "relay") => allow_lan || is_public_ip(ip),
        _ => false,
    };
    if !allowed {
        return None;
    }
    let mut out =
        format!("{prefix}candidate:{foundation} {component} {transport} {priority} {ip} {port} typ {kind}");
    if kind != "host" {
        out.push_str(" raddr 0.0.0.0 rport 0");
    }
    let mut ext = tokens.get(8..).unwrap_or_default().iter();
    while let Some(name) = ext.next() {
        let name = name.to_ascii_lowercase();
        let Some(value) = ext.next() else { break };
        let keep = match name.as_str() {
            "tcptype" => {
                transport == "tcp"
                    && matches!(value.to_ascii_lowercase().as_str(), "active" | "passive" | "so")
            }
            "generation" | "network-id" | "network-cost" => value.parse::<u32>().is_ok(),
            "ufrag" => is_ice_token(value, 4, 256),
            _ => false,
        };
        if keep {
            out.push(' ');
            out.push_str(&name);
            out.push(' ');
            // `ufrag` is case-sensitive (RFC 8445); the other values are numbers or keywords.
            if name == "tcptype" {
                out.push_str(&value.to_ascii_lowercase());
            } else {
                out.push_str(value);
            }
        }
    }
    Some(out)
}

/// RFC 8839 `ice-char` token (`ALPHA / DIGIT / "+" / "/"`) with a length range.
fn is_ice_token(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// Whether an address is a public unicast IP.
fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    let cgnat = o[0] == 100 && (64..128).contains(&o[1]);
    let benchmarking = o[0] == 198 && (o[1] == 18 || o[1] == 19);
    let ietf = o[0] == 192 && o[1] == 0 && o[2] == 0;
    !(a.is_private()
        || a.is_loopback()
        || a.is_link_local()
        || a.is_unspecified()
        || a.is_broadcast()
        || a.is_multicast()
        || a.is_documentation()
        || cgnat
        || benchmarking
        || ietf
        || o[0] == 0
        || o[0] >= 240)
}

fn is_public_v6(a: Ipv6Addr) -> bool {
    let s = a.segments();
    let embedded_v4 = |hi: u16, lo: u16| {
        let [o1, o2] = hi.to_be_bytes();
        let [o3, o4] = lo.to_be_bytes();
        Ipv4Addr::new(o1, o2, o3, o4)
    };
    // Forms that carry an IPv4 address are judged by that address (review L2).
    if let Some(v4) = a.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    if s[..6] == [0, 0, 0, 0, 0, 0] {
        // IPv4-compatible `::a.b.c.d` (deprecated), and `::`/`::1`.
        return is_public_v4(embedded_v4(s[6], s[7]));
    }
    if s[..6] == [0, 0, 0, 0, 0xffff, 0] {
        // IPv4-translated `::ffff:0:a.b.c.d` (RFC 2765).
        return is_public_v4(embedded_v4(s[6], s[7]));
    }
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        // NAT64 well-known prefix.
        return is_public_v4(embedded_v4(s[6], s[7]));
    }
    if s[0] == 0x2002 {
        // 6to4.
        return is_public_v4(embedded_v4(s[1], s[2]));
    }
    let teredo = s[0] == 0x2001 && s[1] == 0;
    let nat64_local = s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1;
    let ula = (s[0] & 0xfe00) == 0xfc00;
    let link_local = (s[0] & 0xffc0) == 0xfe80;
    let site_local = (s[0] & 0xffc0) == 0xfec0;
    let documentation = (s[0] == 0x2001 && s[1] == 0x0db8) || s[0] == 0x3fff;
    let discard = s[..4] == [0x100, 0, 0, 0];
    !(a.is_loopback()
        || a.is_unspecified()
        || a.is_multicast()
        || teredo
        || nat64_local
        || ula
        || link_local
        || site_local
        || documentation
        || discard)
}

/// SDP attributes that pass through unchanged. None of them carries a network address.
/// Everything not listed (including `a=rtcp` and `a=remote-candidates`, which do) is dropped.
const KEPT_ATTRIBUTES: &[&str] = &[
    "group",
    "msid-semantic",
    "msid",
    "mid",
    "sendrecv",
    "sendonly",
    "recvonly",
    "inactive",
    "rtcp-mux",
    "rtcp-mux-only",
    "rtcp-rsize",
    "rtpmap",
    "fmtp",
    "rtcp-fb",
    "extmap",
    "extmap-allow-mixed",
    "setup",
    "fingerprint",
    "ice-ufrag",
    "ice-pwd",
    "ice-options",
    "ssrc",
    "ssrc-group",
    "sctp-port",
    "max-message-size",
    "rid",
    "simulcast",
    "bundle-only",
    "end-of-candidates",
    "ptime",
    "maxptime",
];

/// Filters an SDP and validates its DTLS parameters (INV-NET-1, INV-NET-4).
/// Use on outgoing SDP before encryption, and on incoming SDP before handing it to WebRTC.
///
/// This is an allowlist (review H3). Lines are `CRLF`-separated `x=` lines. Then:
/// * `o=` is rewritten to `127.0.0.1`, `c=` to `0.0.0.0`, and every `m=` port to `9`;
/// * `a=` attributes not in [`KEPT_ATTRIBUTES`] are dropped;
/// * candidates (any case) go through [`filter_candidate`];
/// * any passed-through line that could contain an address makes the whole SDP invalid.
///
/// DTLS checks run on the filtered output.
pub fn filter_sdp(sdp: &str, mode: Mode, role: SdpRole) -> Result<String> {
    if sdp.len() > MAX_SDP {
        return Err(CoreError::TooLarge);
    }
    if !sdp.is_ascii() {
        return Err(CoreError::Malformed);
    }
    let mut out = String::with_capacity(sdp.len());
    for line in sdp.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        if line.chars().any(char::is_control) {
            return Err(CoreError::Malformed);
        }
        let (kind, value) = line.split_at_checked(2).ok_or(CoreError::Malformed)?;
        let kept = match kind {
            // Validated, not passed through (review round 2 fuzzing: `v=` carried text).
            "v=" if value == "0" => Some("v=0".to_owned()),
            "t=" if is_timing(value) => Some(line.to_owned()),
            "b=" if is_bandwidth(value) => Some(line.to_owned()),
            "v=" | "t=" | "b=" => return Err(CoreError::Malformed),
            "s=" => Some("s=-".to_owned()),
            "o=" => Some(rewrite_origin(value)?),
            "c=" => Some("c=IN IP4 0.0.0.0".to_owned()),
            "m=" => Some(rewrite_media(value)?),
            "a=" => {
                let name = value.split(':').next().unwrap_or_default().to_ascii_lowercase();
                if name == "candidate" {
                    filter_candidate(line, mode)
                } else if KEPT_ATTRIBUTES.contains(&name.as_str()) {
                    let rest = value.get(name.len()..).unwrap_or_default();
                    Some(format!("a={name}{rest}"))
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(kept) = kept {
            // Fail closed: a passed-through line should never carry an address. (`o=`, `c=`,
            // `m=` and candidates are rebuilt from validated fields above.)
            if matches!(kind, "v=" | "t=" | "b=" | "a=")
                && !kept.starts_with("a=candidate:")
                && contains_ip_literal(&kept)
            {
                return Err(CoreError::Malformed);
            }
            out.push_str(&kept);
            out.push_str("\r\n");
        }
    }
    validate_dtls(&out, role)?;
    Ok(out)
}

/// `t=<start> <stop>`, both decimal.
fn is_timing(value: &str) -> bool {
    let mut t = value.split(' ');
    let num = |v: Option<&str>| {
        v.is_some_and(|v| !v.is_empty() && v.len() <= 20 && v.bytes().all(|b| b.is_ascii_digit()))
    };
    num(t.next()) && num(t.next()) && t.next().is_none()
}

/// `b=<bwtype>:<bandwidth>`, e.g. `b=AS:30` or `b=TIAS:64000`.
fn is_bandwidth(value: &str) -> bool {
    value.split_once(':').is_some_and(|(kind, n)| {
        !kind.is_empty()
            && kind.len() <= 16
            && kind.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !n.is_empty()
            && n.len() <= 20
            && n.bytes().all(|b| b.is_ascii_digit())
    })
}

/// `o=<username> <sess-id> <sess-version> IN IP4 <addr>`; only the numeric ids are kept.
fn rewrite_origin(value: &str) -> Result<String> {
    let mut t = value.split(' ');
    let (_user, id, version) = (t.next(), t.next(), t.next());
    let id = id.filter(|v| !v.is_empty() && v.len() <= 20 && v.bytes().all(|b| b.is_ascii_digit()));
    let version = version.filter(|v| !v.is_empty() && v.len() <= 20 && v.bytes().all(|b| b.is_ascii_digit()));
    match (id, version) {
        (Some(id), Some(version)) => Ok(format!("o=- {id} {version} IN IP4 127.0.0.1")),
        _ => Err(CoreError::Malformed),
    }
}

/// `m=<media> <port> <proto> <fmt...>` with the port forced to 9 (the "discard" port that
/// WebRTC uses when candidates carry the real transport addresses). Every token is validated.
fn rewrite_media(value: &str) -> Result<String> {
    let tokens: Vec<&str> = value.split(' ').collect();
    let (media, proto, fmts) = (
        tokens.first().ok_or(CoreError::Malformed)?,
        tokens.get(2).ok_or(CoreError::Malformed)?,
        tokens.get(3..).unwrap_or_default(),
    );
    let word = |t: &str, extra: &[u8]| {
        !t.is_empty() && t.bytes().all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
    };
    if !word(media, b"") || !word(proto, b"/") || fmts.is_empty() || !fmts.iter().all(|f| word(f, b"-")) {
        return Err(CoreError::Malformed);
    }
    Ok(format!("m={media} 9 {proto} {}", fmts.join(" ")))
}

/// Whether a passed-through line could carry an address: a `hexdigit.digit` sequence (dotted
/// IPv4 such as `05.0.0.2` or `0x7f.1`; it does not catch bare decimal or bare `0x…` integers,
/// which no kept attribute treats as an address), or any
/// substring of a `[0-9A-Fa-f:.]` run that parses as any IP, `::` included (catches IPv6,
/// even glued to other text as in `cname:fe80::1`). Browser SDP attributes in
/// [`KEPT_ATTRIBUTES`] never contain either. Fingerprint lines are exempt: they are 32 hex
/// pairs checked exactly by [`validate_dtls`], and parts of them would read as IPv6.
fn contains_ip_literal(line: &str) -> bool {
    const MAX_IP_LITERAL: usize = 45;
    if line.starts_with("a=fingerprint:") {
        return false;
    }
    let bytes = line.as_bytes();
    let dotted = bytes
        .windows(3)
        .any(|w| matches!(w, [a, b'.', c] if a.is_ascii_hexdigit() && c.is_ascii_digit()));
    dotted
        || line
            .split(|c: char| !(c.is_ascii_hexdigit() || c == ':' || c == '.'))
            .filter(|run| run.len() >= 2)
            .any(|run| {
                (0..run.len()).any(|start| {
                    let end = run.len().min(start.saturating_add(MAX_IP_LITERAL));
                    (start.saturating_add(2)..=end)
                        .any(|stop| run.get(start..stop).is_some_and(|t| t.parse::<IpAddr>().is_ok()))
                })
            })
}

/// Requires exactly one distinct `sha-256` fingerprint, and `a=setup` lines that are all the
/// same and valid for this side of the negotiation (review L3).
pub fn validate_dtls(sdp: &str, role: SdpRole) -> Result<()> {
    let mut fingerprint: Option<String> = None;
    let mut setup: Option<&str> = None;
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
        } else if let Some(s) = line.strip_prefix("a=setup:") {
            let ok = match role {
                SdpRole::Offer => matches!(s, "actpass" | "active" | "passive"),
                SdpRole::Answer => matches!(s, "active" | "passive"),
            };
            if !ok || setup.is_some_and(|prev| prev != s) {
                return Err(CoreError::AuthFailed);
            }
            setup = Some(s);
        }
    }
    if fingerprint.is_none() || setup.is_none() {
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
    /// Public, routable, non-documentation addresses for the tests.
    const RELAY: &str = "8.8.4.4";
    const PUBLIC: &str = "1.1.1.1";

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
        assert_eq!(filter_candidate(&cand(PUBLIC, "srflx"), Mode::RelayOnly), None);
        assert_eq!(
            filter_candidate(&cand("abcd.local", "host"), Mode::RelayOnly),
            None
        );
        let kept = filter_candidate(&cand(RELAY, "relay"), Mode::RelayOnly).unwrap();
        assert_eq!(
            kept,
            "a=candidate:1 1 udp 2122260223 8.8.4.4 54321 typ relay raddr 0.0.0.0 rport 0 generation 0"
        );
    }

    /// Review round 1, H3: case variants and stray extension fields are canonicalised.
    #[test]
    fn candidate_case_and_extensions_canonicalised() {
        assert_eq!(
            filter_candidate("a=Candidate:1 1 UDP 1 192.168.1.2 9 TYP host", Mode::RelayOnly),
            None
        );
        let kept = filter_candidate(
            "A=CANDIDATE:1 1 UDP 1 8.8.4.4 9 TYP RELAY RADDR 192.168.1.2 RPORT 5 x-leak 10.0.0.1 generation 0",
            Mode::RelayOnly,
        )
        .unwrap();
        assert_eq!(
            kept,
            "a=candidate:1 1 udp 1 8.8.4.4 9 typ relay raddr 0.0.0.0 rport 0 generation 0"
        );
    }

    /// Review round 1, M1: a relay candidate must point at a public address.
    #[test]
    fn relay_candidates_must_be_public() {
        for addr in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "x.local",
            "::1",
            "fd00::1",
        ] {
            assert_eq!(
                filter_candidate(&cand(addr, "relay"), Mode::RelayOnly),
                None,
                "{addr}"
            );
        }
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
            // Review round 1, L2: IPv6 forms carrying private IPv4, Teredo, site-local.
            "::10.0.0.1",
            "64:ff9b::a00:1",
            "2002:a00:1::1",
            "2002:c0a8:101::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "fec0::1",
            "::ffff:0:10.0.0.1",
        ] {
            assert_eq!(filter_candidate(&cand(private, "host"), d), None, "{private}");
        }
        assert!(filter_candidate(&cand(RELAY, "srflx"), d).is_some());
        assert!(filter_candidate(&cand("2a00:1450::1", "host"), d).is_some());
        assert!(
            filter_candidate(&cand("2002:808:404::1", "host"), d).is_some(),
            "6to4 of a public v4"
        );
        assert!(filter_candidate(&cand("192.168.0.2", "host"), Mode::Direct { allow_lan: true }).is_some());
    }

    #[test]
    fn malformed_candidates_dropped() {
        for bad in [
            "",
            "a=candidate:",
            "candidate:1 1 udp 1 8.8.4.4 99999 typ relay",
            "a=candidate:1 1 sctp 1 8.8.4.4 9 typ relay",
            "a=candidate:1 1 udp 1 8.8.4.4 9 type relay",
            "a=candidate:1 1 udp 1 8.8.4.4 9 typ relay\r\na=evil",
            "a=candidate:1 0 udp 1 8.8.4.4 9 typ relay",
            "a=candidate:f@o 1 udp 1 8.8.4.4 9 typ relay",
            "a=candidate:1 1 udp 1 turn.example.org 9 typ relay",
        ] {
            assert_eq!(filter_candidate(bad, Mode::RelayOnly), None, "{bad:?}");
        }
    }

    fn sdp(setup: &str, cands: &[String]) -> String {
        let mut s = format!(
            "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=fingerprint:sha-256 {FP}\r\na=setup:{setup}\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\n"
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
                cand(PUBLIC, "srflx"),
                cand(RELAY, "relay"),
            ],
        );
        let out = filter_sdp(&s, Mode::RelayOnly, SdpRole::Offer).unwrap();
        let kinds: Vec<&str> = out.lines().filter(|l| l.starts_with("a=candidate")).collect();
        assert_eq!(kinds.len(), 1);
        assert!(kinds[0].contains("typ relay"));
        assert!(!out.contains("192.168.1"));
        assert!(!out.contains(PUBLIC));
    }

    /// Review round 1, H3: addresses outside `a=candidate:` lines.
    #[test]
    fn addresses_outside_candidates_removed() {
        let leaky = sdp("actpass", &[cand(RELAY, "relay")])
            .replace("o=- 1 2 IN IP4 127.0.0.1", "o=- 1 2 IN IP4 10.0.0.5")
            .replace("c=IN IP4 0.0.0.0", "c=IN IP4 192.168.1.5")
            .replace("m=application 9", "m=application 51234")
            + "a=rtcp:9 IN IP4 192.168.1.5\r\n"
            + "a=remote-candidates:1 192.168.1.5 9\r\n"
            + "a=x-private:10.1.2.3\r\n"
            + "i=lan 172.16.0.9\r\n"
            + "a=Candidate:2 1 udp 9 192.168.1.6 9 typ host\r\n";
        let out = filter_sdp(&leaky, Mode::RelayOnly, SdpRole::Offer).unwrap();
        for bad in [
            "10.0.0.5",
            "192.168.1",
            "10.1.2.3",
            "172.16",
            "51234",
            "rtcp:",
            "remote-candidates",
            "x-private",
        ] {
            assert!(!out.contains(bad), "{bad} in {out}");
        }
        assert!(out.contains("o=- 1 2 IN IP4 127.0.0.1\r\n"));
        assert!(out.contains("c=IN IP4 0.0.0.0\r\n"));
        assert!(out.contains("m=application 9 UDP/DTLS/SCTP"));
        // `v=`, `t=` and `b=` are validated too (found by fuzzing in review round 2).
        for bad in [
            "v=c: te cti d:id::(a",
            "v=1",
            "t=0 0 x",
            "t=::1 0",
            "b=AS:1.2.3.4",
            "b=:30",
        ] {
            let s = sdp("actpass", &[]).replace("v=0\r\n", "") + bad + "\r\n";
            assert!(filter_sdp(&s, Mode::RelayOnly, SdpRole::Offer).is_err(), "{bad}");
        }
        let ok = sdp("actpass", &[]) + "b=AS:30\r\nb=TIAS:64000\r\n";
        assert!(filter_sdp(&ok, Mode::RelayOnly, SdpRole::Offer).is_ok());
        let unspecified = sdp("actpass", &[]) + "a=ssrc:1 cname:::\r\n";
        assert!(filter_sdp(&unspecified, Mode::RelayOnly, SdpRole::Offer).is_err());
        // The `m=` tail is validated, not passed through (found by fuzzing).
        let tail =
            sdp("actpass", &[]) + "m=application 9 UDP/DTLS/SCT typ relay raddr 05.0.0.2 rport 4000\r\n";
        assert!(filter_sdp(&tail, Mode::RelayOnly, SdpRole::Offer).is_err());
        // A kept attribute that smuggles an address invalidates the SDP.
        let smuggled = sdp("actpass", &[]) + "a=ssrc:1 cname:10.0.0.1\r\n";
        assert!(filter_sdp(&smuggled, Mode::RelayOnly, SdpRole::Offer).is_err());
        for glued in [
            "cname:fe80::1",
            "cname:a10.0.0.1",
            "x/192.168.4.4;",
            "c=1.1.1.1",
            "05.0.0.2",
            "0x7f.1",
        ] {
            let smuggled = sdp("actpass", &[]) + &format!("a=ssrc:1 {glued}\r\n");
            assert!(
                filter_sdp(&smuggled, Mode::RelayOnly, SdpRole::Offer).is_err(),
                "{glued}"
            );
        }
        let smuggled6 = sdp("actpass", &[]) + "a=ssrc:1 cname:fe80::1\r\n";
        assert!(filter_sdp(&smuggled6, Mode::RelayOnly, SdpRole::Offer).is_err());
        // Bare LF framing is refused, so lines cannot be hidden inside another.
        assert!(
            filter_sdp(
                &sdp("actpass", &[]).replace("\r\n", "\n"),
                Mode::RelayOnly,
                SdpRole::Offer
            )
            .is_err()
        );
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
        // Review round 1, L3: conflicting roles across media sections.
        let mixed = sdp("active", &[]) + "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=setup:passive\r\n";
        assert!(validate_dtls(&mixed, SdpRole::Answer).is_err());
        // Attribute-name case cannot hide a second fingerprint from the check.
        let hidden = sdp("active", &[]) + &format!("a=Fingerprint:sha-256 {}\r\n", FP.replace("AB", "AC"));
        assert!(filter_sdp(&hidden, Mode::RelayOnly, SdpRole::Answer).is_err());
        assert!(filter_sdp(&"x".repeat(MAX_SDP + 1), Mode::RelayOnly, SdpRole::Offer).is_err());
    }

    /// A typical browser offer (audio + data channel, trickle) survives intact apart from
    /// the dropped host/srflx candidates and `a=rtcp`, so calls keep working.
    #[test]
    fn realistic_offer_passes() {
        let offer = [
            "v=0",
            "o=- 4611731400430051336 2 IN IP4 127.0.0.1",
            "s=-",
            "t=0 0",
            "a=group:BUNDLE 0 1",
            "a=extmap-allow-mixed",
            "a=msid-semantic: WMS 7b2c1d9e-3f4a-4b5c-8d6e-9f0a1b2c3d4e",
            "m=audio 9 UDP/TLS/RTP/SAVPF 111 63 9 0 8 13 110 126",
            "c=IN IP4 0.0.0.0",
            "a=rtcp:9 IN IP4 0.0.0.0",
            "a=candidate:842163049 1 udp 1677729535 1.1.1.1 47810 typ srflx raddr 192.168.1.20 rport 47810 generation 0 network-cost 999",
            "a=candidate:2999745851 1 udp 2122260223 192.168.1.20 47810 typ host generation 0 network-id 1",
            "a=candidate:1052130303 1 udp 41885439 8.8.4.4 3478 typ relay raddr 1.1.1.1 rport 47810 generation 0 ufrag wTb2 network-cost 999",
            "a=ice-ufrag:wTb2",
            "a=ice-pwd:1Kf7oZ/3qR+8tYgH2jL4nM9p",
            "a=ice-options:trickle",
            &format!("a=fingerprint:sha-256 {FP}"),
            "a=setup:actpass",
            "a=mid:0",
            "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level",
            "a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
            "a=sendrecv",
            "a=msid:7b2c1d9e-3f4a-4b5c-8d6e-9f0a1b2c3d4e 0c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f",
            "a=rtcp-mux",
            "a=rtcp-rsize",
            "a=rtpmap:111 opus/48000/2",
            "a=rtcp-fb:111 transport-cc",
            "a=fmtp:111 minptime=10;useinbandfec=1",
            "a=ssrc:1001 cname:Hk3xYz9AbCdEfGhI",
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
            "c=IN IP4 0.0.0.0",
            "a=ice-ufrag:wTb2",
            "a=ice-pwd:1Kf7oZ/3qR+8tYgH2jL4nM9p",
            &format!("a=fingerprint:sha-256 {FP}"),
            "a=setup:actpass",
            "a=mid:1",
            "a=sctp-port:5000",
            "a=max-message-size:262144",
        ]
        .join("\r\n")
            + "\r\n";
        let out = filter_sdp(&offer, Mode::RelayOnly, SdpRole::Offer).unwrap();
        let expected: String = offer
            .split("\r\n")
            .filter(|l| !l.is_empty() && !l.starts_with("a=rtcp:") && !l.contains("typ host") && !l.contains("typ srflx"))
            .map(|l| {
                if l.contains("typ relay") {
                    "a=candidate:1052130303 1 udp 41885439 8.8.4.4 3478 typ relay raddr 0.0.0.0 rport 0 generation 0 ufrag wTb2 network-cost 999".to_owned()
                } else {
                    l.to_owned()
                }
            })
            .map(|l| l + "\r\n")
            .collect();
        assert_eq!(out, expected);
    }

    /// Independent oracle (review round 2, N9): deliberately cruder than the filter's own
    /// `contains_ip_literal`. Any substring that parses as an IP counts, wherever it starts.
    fn any_ip_in(text: &str) -> Option<IpAddr> {
        let n = text.len();
        (0..n).find_map(|i| (i + 2..=n.min(i + 45)).find_map(|j| text.get(i..j)?.parse::<IpAddr>().ok()))
    }

    /// Every IP literal in a filtered relay-only SDP: allowed only as the address of a
    /// public `typ relay` candidate, or as the exact fixed placeholder lines.
    fn assert_relay_only_output(out: &str) {
        for line in out.split("\r\n").filter(|l| !l.is_empty()) {
            if line.starts_with("a=candidate:") || line.starts_with("candidate:") {
                let t: Vec<&str> = line.split(' ').collect();
                assert_eq!(t[6], "typ");
                assert_eq!(t[7], "relay", "{line}");
                assert!(is_public_ip(t[4].parse().unwrap()), "{line}");
                assert_eq!(&t[8..12], ["raddr", "0.0.0.0", "rport", "0"]);
                assert_eq!(any_ip_in(&t[12..].join(" ")), None, "{line}");
            } else if line.starts_with("o=") {
                assert!(line.ends_with(" IN IP4 127.0.0.1"), "{line}");
                let head = line.trim_end_matches(" IN IP4 127.0.0.1");
                assert_eq!(any_ip_in(head), None, "{line}");
            } else if line.starts_with("c=") {
                assert_eq!(line, "c=IN IP4 0.0.0.0");
            } else if !line.starts_with("a=fingerprint:") {
                assert_eq!(any_ip_in(line), None, "{line}");
            }
        }
    }

    fn any_ip() -> impl Strategy<Value = String> {
        prop_oneof![
            any::<[u8; 4]>().prop_map(|a| format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])),
            prop::sample::select(vec![
                "10.1.2.3",
                "192.168.0.7",
                "127.0.0.1",
                "169.254.169.254",
                "8.8.4.4"
            ])
            .prop_map(str::to_owned),
            any::<[u16; 8]>().prop_map(|s| std::net::Ipv6Addr::from(s).to_string()),
            prop::sample::select(vec!["fe80::1", "::ffff:10.0.0.1", "fd12::9", "2a00:1450::1"])
                .prop_map(str::to_owned),
        ]
    }

    fn any_line() -> impl Strategy<Value = String> {
        let kind = prop::sample::select(vec!["host", "srflx", "prflx", "relay", "RELAY", "Host"]);
        let a = prop::sample::select(vec!["a=candidate:", "a=Candidate:", "A=candidate:", "candidate:"]);
        prop_oneof![
            (a, any_ip(), any::<u16>(), kind, any_ip(), "[a-z0-9 ]{0,20}").prop_map(
                |(a, ip, port, k, r, x)| format!("{a}1 1 udp 7 {ip} {port} typ {k} raddr {r} rport 1 {x}")
            ),
            any_ip().prop_map(|ip| format!("c=IN IP4 {ip}")),
            any_ip().prop_map(|ip| format!("o=- 5 6 IN IP4 {ip}")),
            any_ip().prop_map(|ip| format!("a=rtcp:9 IN IP4 {ip}")),
            any_ip().prop_map(|ip| format!("a=remote-candidates:1 {ip} 9")),
            (any::<u16>()).prop_map(|p| format!("m=audio {p} UDP/TLS/RTP/SAVPF 111")),
            any_ip().prop_map(|ip| format!("a=x-{ip}")),
            any_ip().prop_map(|ip| format!("i={ip}")),
            Just("a=rtpmap:111 opus/48000/2".to_owned()),
            Just("a=mid:0".to_owned()),
        ]
    }

    proptest! {
        /// INV-NET-1 (core part), over whole SDPs: in relay-only mode, the output never contains
        /// an address other than public `typ relay` candidates, wherever the input put it.
        #[test]
        fn relay_only_sdp_never_leaks(lines in prop::collection::vec(any_line(), 0..25)) {
            let mut s = sdp("actpass", &[]);
            for l in lines {
                s.push_str(&l);
                s.push_str("\r\n");
            }
            if let Ok(out) = filter_sdp(&s, Mode::RelayOnly, SdpRole::Offer) {
                assert_relay_only_output(&out);
            }
        }

        #[test]
        fn relay_only_never_emits_non_relay(line in any_line()) {
            if let Some(out) = filter_candidate(&line, Mode::RelayOnly) {
                assert_relay_only_output(&out);
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
