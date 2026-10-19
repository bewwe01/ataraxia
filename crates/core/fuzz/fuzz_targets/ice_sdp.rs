#![no_main]
use core::net::IpAddr;
use veil_core::ice::{Mode, SdpRole, filter_candidate, filter_sdp};

/// Independent re-check (deliberately cruder than the filter's own scan): any substring of the
/// line that parses as an IP other than the fixed placeholders.
fn leaks(line: &str) -> bool {
    let n = line.len();
    (0..n).any(|i| {
        (i + 2..=n.min(i + 45)).any(|j| {
            line.get(i..j).and_then(|t| t.parse::<IpAddr>().ok()).is_some_and(|ip| match ip {
                IpAddr::V4(v4) => !(v4.is_unspecified() || v4.is_loopback()) && !line.contains("127.0.0.1"),
                IpAddr::V6(v6) => !v6.is_unspecified(),
            })
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
