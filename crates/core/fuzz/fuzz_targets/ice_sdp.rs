#![no_main]
use core::net::IpAddr;
use veil_core::ice::{Mode, SdpRole, filter_candidate, filter_sdp};

/// Independent re-check (deliberately cruder than the filter's own scan): any substring of the
/// line that parses as an IP at all. Placeholder lines are checked exactly in `check`.
fn leaks(line: &str) -> bool {
    let n = line.len();
    (0..n).any(|i| {
        (i + 2..=n.min(i + 45)).any(|j| {
            line.get(i..j).is_some_and(|t| t.parse::<IpAddr>().is_ok())
        })
    })
}

/// INV-NET-1: in relay-only mode, the only addresses in the output are those of public
/// `typ relay` candidates, whose related address is zeroed.
fn check(out: &str) {
    for line in out.split("\r\n").filter(|l| !l.is_empty()) {
        if line.starts_with("a=candidate:") || line.starts_with("candidate:") {
            let t: Vec<&str> = line.split(' ').collect();
            assert_eq!(t.get(6..8), Some(&["typ", "relay"][..]), "{line}");
            assert_eq!(t.get(8..12), Some(&["raddr", "0.0.0.0", "rport", "0"][..]), "{line}");
            assert!(!t.get(12..).unwrap_or_default().iter().any(|x| leaks(x)), "{line}");
        } else if let Some(head) = line.strip_prefix("o=") {
            // Only the fixed placeholder address may appear (review round 2, N9).
            let head = head.strip_suffix(" IN IP4 127.0.0.1").expect("o= rewritten");
            assert!(!leaks(head), "{line}");
        } else if line.starts_with("c=") {
            assert_eq!(line, "c=IN IP4 0.0.0.0");
        } else if !line.starts_with("a=fingerprint:") {
            assert!(!leaks(line), "{line}");
        }
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Ok(s) = core::str::from_utf8(data) else { return };
    if let Some(out) = filter_candidate(s, Mode::RelayOnly) {
        check(&out);
    }
    let _ = filter_candidate(s, Mode::Direct { allow_lan: false });
    if let Ok(out) = filter_sdp(s, Mode::RelayOnly, SdpRole::Offer) {
        check(&out);
    }
});
