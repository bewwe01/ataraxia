#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(h) = veil_core::vault::VaultHeader::decode(data) {
        assert_eq!(h.encode(), data);
        // Low-cost params only, so the fuzzer stays fast: unlock must fail cleanly, never panic.
        if h.params.m_kib <= 64 && h.params.t <= 2 {
            let _ = veil_core::vault::unlock(&h, b"pw", &[0u8; 32]);
        }
    }
});
