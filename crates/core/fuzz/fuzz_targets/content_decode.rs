#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(c) = veil_core::content::Content::decode_strict(data) {
        // Canonical: decoded content re-encodes to the identical bytes and still validates.
        assert_eq!(c.encode(), data);
        assert!(c.validate().is_ok());
    }
});
