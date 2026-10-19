#![no_main]
//! Client↔relay frames (veil-wire): decoding never panics, and anything accepted is canonical
//! (re-encodes to the same bytes) and stays valid. Both directions are hostile input: the
//! relay parses client frames, clients parse relay frames (Phase 3).
use veil_wire::{ClientFrame, ServerFrame};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(f) = ClientFrame::decode_strict(data) {
        assert_eq!(f.encode(), data);
        assert!(f.validate().is_ok());
    }
    if let Ok(f) = ServerFrame::decode_strict(data) {
        assert_eq!(f.encode(), data);
        assert!(f.validate().is_ok());
    }
});
