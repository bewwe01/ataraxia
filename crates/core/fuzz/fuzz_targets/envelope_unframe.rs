#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(sealed) = veil_core::envelope::unframe(data) {
        // Anything accepted must re-frame to exactly the same bytes (strict, canonical framing).
        assert_eq!(veil_core::envelope::frame(sealed).ok().as_deref(), Some(data));
    }
});
