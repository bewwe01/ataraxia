#![no_main]
//! Feeds arbitrary bytes to a real account's `open()`: must never panic, and (since the
//! input is not a valid envelope from a contact) must never succeed or change state.
use rand::TryRngCore as _;
use rand::rngs::OsRng;
use veil_core::account::Account;
use veil_core::store::MemoryBackend;

thread_local! {
    static ACC: Account<MemoryBackend> = Account::create(MemoryBackend::new(), &mut OsRng.unwrap_err()).expect("account");
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // Frame the input so the fuzzer reaches the sealed-sender and session layers, too.
    let framed = veil_core::envelope::frame(data).unwrap_or_else(|_| data.to_vec());
    ACC.with(|acc| {
        for input in [data, &framed[..]] {
            let r = futures_executor::block_on(acc.open(&mut OsRng.unwrap_err(), input, 1_800_000_000));
            assert!(r.is_err(), "random bytes opened as a message");
        }
    });
});
