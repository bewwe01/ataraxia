#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(s) = core::str::from_utf8(data) {
        if let Ok(inv) = veil_core::invite::Invite::from_link(s) {
            assert_eq!(inv.to_link(), s);
        }
    }
});
