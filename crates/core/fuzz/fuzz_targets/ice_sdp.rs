#![no_main]
use veil_core::ice::{Mode, SdpRole, filter_candidate, filter_sdp};
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Ok(s) = core::str::from_utf8(data) else { return };
    // INV-NET-1: in relay-only mode, no output candidate may be anything but `typ relay`.
    if let Some(out) = filter_candidate(s, Mode::RelayOnly) {
        assert!(out.contains(" typ relay"), "{out}");
    }
    let _ = filter_candidate(s, Mode::Direct { allow_lan: false });
    if let Ok(out) = filter_sdp(s, Mode::RelayOnly, SdpRole::Offer) {
        for line in out.split("\r\n").filter(|l| l.starts_with("a=candidate:")) {
            assert!(line.contains(" typ relay"), "{line}");
        }
    }
});
