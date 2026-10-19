# Veil: Test report

Real command output only. Updated at the end of every phase. Earlier phases' entries are kept for history.

## Phase 2: after review round 1 fixes (2026-10-19)

Review round 1 returned **FAIL** (3 High, 5 Medium, 8 Low; see [`REVIEW_REPORT.md`](REVIEW_REPORT.md)). Every finding was fixed with a regression test, or documented below where it is out of Phase 2's reach. Local: Ubuntu 24.04, rustc 1.97.0.

### Format, lint, tests

```
$ cargo fmt --all --check                                   # no output, exit 0
$ cargo clippy --workspace --all-targets -- -D warnings     # no warnings
$ cargo test --workspace --locked
test result: ok. 72 passed; 0 failed; ...   # unit (src/), was 59
test result: ok. 3 passed; 0 failed; ...    # tests/secrets.rs
test result: ok. 21 passed; 0 failed; ...   # tests/session.rs, was 14
test result: ok. 0 passed; 0 failed; ...    # doctests
```

96 tests, up from 76. Regression tests per finding:

| Finding | Test(s) |
|---|---|
| H1 envelope size leak | `relay_learns_only_the_bucket`; `every_bit_flip_rejected_and_state_unchanged` now also covers the sealed-sender version byte |
| H2 non-atomic commit | `failed_commit_changes_nothing_and_retry_succeeds` (also asserts one backend batch per transaction) |
| H3 / M1 / L2 / L3 ICE filter | `relay_only_sdp_never_leaks` (proptest over whole SDPs; also run with `PROPTEST_CASES=20000`), `addresses_outside_candidates_removed`, `candidate_case_and_extensions_canonicalised`, `relay_candidates_must_be_public`, `direct_drops_private_and_mdns`, `dtls_validation`, `realistic_offer_passes` |
| M2 Debug leaks | `debug_output_never_contains_content_or_secrets` |
| M3 untested downgrade / certificate claims | `downgraded_messages_refused`, `certificate_key_must_match_sealing_key` |
| M4 rollback after decrypt | `account::rollback_tests::*`. **Mutation check:** with `transact` changed to commit on error, both tests fail; restored afterwards |
| M5 fuzzing depth | new fuzz targets `contact_inner`, `contact_plaintext` (below) |
| L1 vault KDF cost | `tampered_cost_parameters_refused_before_kdf` |
| L4 chunk re-encryption | `encrypt_chunk` made private; `every_encryption_uses_a_fresh_key` |
| L5 sealed-sender v2 | exact `0x11` version byte required (bit-flip test) |
| L6 silent invite deletion | `delete_invite` now fails the transaction |
| L7 weak tests | `every_body_variant_roundtrips`, `strangers_and_self_addressed_envelopes_dropped`, `pairing_tests::package_with_swapped_identity_or_signature_refused`, `pairing_tests::one_time_prekeys_deleted`, `safety::tests::known_answer`, `attachment::tests::known_answer_multi_chunk` |
| L8 CI | gitleaks pinned by SHA-256; fuzz lockfile `--locked` check; crash inputs printed on failure; nightly 1 h fuzz workflow |

The new known-answer vectors come from `crates/core/tests/vectors/gen.py`. Its fingerprint code reproduces libsignal's own published vector (`300354477692869396892869876765458257569162576843440918079131`) before emitting Veil's.

### Fuzzing (cargo-fuzz 0.13.2, nightly-2026-10-01, `-O`)

| Target | Duration | Runs | Final coverage (cov / ft) | Crashes |
|---|---|---|---|---|
| contact_inner (new) | 600 s | 172,491 | 8391 / 10661 | 0 |
| contact_plaintext (new) | 600 s | 9,427 | 4325 / 6193 | 0 |
| ice_sdp (new output check) | 300 s | 3,800,321 | — | 0 after the fix below |
| envelope_unframe (framing v2) | 20 s | 9,438,043 | — | 0 |

- **Fuzzing found a real bug.** The strengthened `ice_sdp` check found that the `m=` line tail was passed through unvalidated (`m=application 9 UDP/DTLS/SCT typ relay raddr 05.0.0.2 …`). This is fixed and seeded into the corpus.
- **Coverage.** The old `account_open` target peaked at 794 edges because random input never passes the sealed-sender MAC. The two new targets act as an authenticated contact.
- **Throughput is low.** `contact_plaintext` manages about 16 inputs per second, since every input does real sealing and decryption.
- **No 1-hour runs yet.** The ≥ 1 h runs (`fuzz-nightly.yml`) are scheduled but have not run yet. INV-MSG-5 therefore stays *partial*.

### Miri (pure modules, after the envelope and ICE rewrites)

```
$ PROPTEST_CASES=4 MIRIFLAGS=-Zmiri-disable-isolation cargo +nightly-2026-10-01 miri test -p veil-core --lib -- padding:: envelope:: ice:: trust:: content::
test result: ok. 31 passed; 0 failed; 0 ignored; 0 measured; 41 filtered out; finished in 219.41s
```

### Supply chain

```
$ cargo deny --locked check
advisories ok, bans ok, licenses ok, sources ok
$ cargo audit --deny warnings     # 1338 advisories, 203 crates; exit 0 with the one documented ignore
$ cargo vet --locked
Vetting Succeeded (36 fully audited, 3 partially audited, 158 exempted)
```

`inout 0.2.3` was yanked upstream on 2026-10-16, which turned CI red (run 39252191570). The lockfile now uses 0.2.4. Its delta audit in `supply-chain/audits.toml` was written by the AI agent and is marked as **not yet confirmed by a human**.

### Known limits that remain

- libsignal's `IdentityKeyPair` / `PrivateKey` are `Copy` and are not zeroized.
- A PreKey (first) message never fits the 1 KiB bucket, so the relay can tell a session's first messages by their 4 KiB size.
- 158 crates are only exempted in cargo vet, libsignal among them.
- There has been **no independent audit.** An independent security audit is required before real-world sensitive use.

## Phase 2: crypto core `veil-core` (2026-10-15), before review

Local: Ubuntu 24.04, rustc 1.97.0, libsignal v0.105.0 @ 4beb029d. CI: run [38761908514](https://github.com/bewwe01/ataraxia/actions/runs/38761908514) on commit cfa8d58.

### Format, lint, tests

```
$ cargo fmt --all --check                                   # no output, exit 0
$ cargo clippy --workspace --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.57s
$ cargo test --workspace
test result: ok. 59 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 16.99s   # unit (src/)
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.49s     # tests/secrets.rs
test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 17.76s   # tests/session.rs
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s     # doctests
```

76 tests in total. The test-to-invariant map is in [`INVARIANTS.md`](INVARIANTS.md). The headline tests:
- `pqxdh_and_spqr_are_active`: v4 PQXDH with a 1569-byte ML-KEM ciphertext, then SPQR data on every message.
- `every_bit_flip_rejected_and_state_unchanged`: every bit of an envelope is flipped one at a time; each is rejected and the genuine message still opens.
- `ratchet_properties::shuffled_dropped_duplicated`: proptest of random order, drops and duplicates.
- `keys_and_nonce_prefixes_unique`: 10^6 attachment keys and nonces, no repeats.
- Known-answer vectors for address, fingerprint, vault unlock and attachments, generated by an independent Python oracle (`crates/core/tests/vectors/gen.py`: argon2-cffi plus pyca/cryptography).

### Fuzzing (cargo-fuzz 0.13.2, nightly-2026-10-01, `-O`, 180 s per target)

| Target | Runs | Final coverage (cov / ft) | Crashes |
|---|---|---|---|
| envelope_unframe | 69,015,391 (+34,490,888 after seeding) | 56 / 71 | 0 |
| content_decode | 8,618,420 | 1384 / 4213 | 0 |
| invite_link | 32,396,284 | 302 / 703 | 0 |
| vault_header | 54,466,831 (+3,048,175 after seeding) | 893 / 1545 | 0 |
| ice_sdp | 20,185,863 | 157 / 407 | 0 |
| account_open | 2,381,226 (+3,594,666 after seeding) | 794 / 1649 | 0 |

The minimized corpora are committed under `crates/core/fuzz/corpus/`. CI repeats a 60 s smoke run per target. This is short: the planned ≥ 1 h nightly runs (INV-MSG-5) are not set up yet.

### Miri (pure modules)

```
$ PROPTEST_CASES=4 MIRIFLAGS=-Zmiri-disable-isolation cargo +nightly-2026-10-01 miri test -p veil-core --lib -- padding:: envelope:: ice:: trust:: content::
test result: ok. 26 passed; 0 failed; 0 ignored; 0 measured; 33 filtered out; finished in 554.63s
```

Miri does not run modules that call into libsignal or Argon2; they are too slow under the interpreter.

### Supply chain

```
$ cargo deny --locked check
advisories ok, bans ok, licenses ok, sources ok
$ cargo audit --deny warnings          # 1329 advisories, 203 crates; exit 0 with one documented ignore (RUSTSEC-2026-0173)
$ cargo vet --locked
Vetting Succeeded (36 fully audited, 2 partially audited, 159 exempted)
```

The 159 exemptions are unreviewed by us (see [`supply-chain/README.md`](../supply-chain/README.md)).

### Known limits after Phase 2

- libsignal's `IdentityKeyPair` / `PrivateKey` are `Copy` and are not zeroized on drop. Veil cannot fix this without patching libsignal.
- Two claims are argument-only, not tested:
  - INV-MSG-6, because there is no API to forge a certificate under a foreign key. The check was confirmed in libsignal `sealed_sender.rs` (constant-time comparison of the certificate key with the message key).
  - The INV-CRY-3 v3-message rejection, because libsignal cannot produce a v3 message.
- Only the core part of each invariant is covered. The relay, UI, calls and OS-keystore parts are tested in later phases (see [`INVARIANTS.md`](INVARIANTS.md)).
- There has been no independent audit.

## Phase 1: spikes (2026-10-15)

### Spike A: libsignal (local, Ubuntu 24.04, rustc 1.97.0)

`cd spikes/libsignal && cargo run --release`

```
# cargo run --release  (2026-10-15, rustc 1.97.0, libsignal v0.105.0 @ 4beb029d)
PASS PQXDH: Alice processes Bob's bundle (EC + signed Kyber1024 prekey) (Ok(()))
PASS first message is PreKeySignalMessage v4+ with ML-KEM ciphertext (version 4, KEM ciphertext 1569 bytes)
PASS Bob decrypts first message
PASS 40 alternating messages decrypt (Double Ratchet steps)
PASS SPQR triple ratchet active: post-quantum ratchet data present in messages (40/40 messages carried SPQR data)
PASS bit-flip at every byte of a SignalMessage is rejected (105/105 rejected)
PASS genuine message still decrypts after tamper attempts
PASS replayed message is rejected (Err(DuplicatedMessage(2, 1)))
PASS out-of-order delivery (reverse order) decrypts
PASS changed identity key is refused (UntrustedIdentity) (Err(UntrustedIdentity(ProtocolAddress { name: "bob", device_id: DeviceId(1) })))
PASS bundle with forged Kyber prekey signature is rejected (Err(SignatureValidationFailed))
ALL CHECKS PASSED

# crypto-relevant dependencies (cargo tree -e normal)
aes v0.9.3
aes-gcm-siv v0.12.1
curve25519-dalek v5.0.0
curve25519-dalek-derive v0.1.1 (proc-macro)
hkdf v0.13.0
hmac v0.13.0
libcrux-hacl-rs v0.0.5
libcrux-hmac v0.0.8
libcrux-intrinsics v0.0.8
libcrux-macros v0.0.3 (proc-macro)
libcrux-ml-kem v0.0.10
libcrux-platform v0.0.3
libcrux-secrets v0.0.6
libcrux-sha2 v0.0.8
libcrux-sha3 v0.0.10
libcrux-traits v0.0.8
libsignal-core v0.1.0 (https://github.com/signalapp/libsignal?tag=v0.105.0#4beb029d)
libsignal-debug v0.105.0 (https://github.com/signalapp/libsignal?tag=v0.105.0#4beb029d)
libsignal-protocol v0.1.0 (https://github.com/signalapp/libsignal?tag=v0.105.0#4beb029d)
sha2 v0.11.1
signal-crypto v0.1.0 (https://github.com/signalapp/libsignal?tag=v0.105.0#4beb029d)
spqr v1.6.0 (https://github.com/signalapp/SparsePostQuantumRatchet.git?tag=v1.6.0#06959b47)
subtle v2.6.1
veil-spike-libsignal v0.0.0 (/home/user/ataraxia/spikes/libsignal)
x25519-dalek v3.0.0
zeroize v1.9.1
zeroize_derive v1.5.0 (proc-macro)
total unique crates: 117
```

### Spike B: WebRTC in Tauri/WebKitGTK (local, Xvfb)

`VEIL_PROBE_EXIT=1 xvfb-run -a spikes/webrtc-probe/src-tauri/target/release/veil-webrtc-probe` (and with `VEIL_ENABLE_WEBRTC=1`)

```
# mode: default
VEIL_PROBE_INFO webkit enable-webrtc default=false media-stream default=true
VEIL_PROBE_RESULT {"userAgent":"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/60.5 Safari/605.1.15","origin":"tauri://localhost","secureContext":true,"RTCPeerConnection":"undefined","RTCDataChannel":"undefined","getUserMedia":true,"RTCRtpScriptTransform":"undefined","mediaDeviceKinds":[]}
# mode: enabled
VEIL_PROBE_INFO webkit enable-webrtc default=false media-stream default=true
VEIL_PROBE_INFO set enable-webrtc=true enable-media-stream=true
VEIL_PROBE_RESULT {"userAgent":"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/60.5 Safari/605.1.15","origin":"tauri://localhost","secureContext":true,"RTCPeerConnection":"undefined","RTCDataChannel":"undefined","getUserMedia":true,"RTCRtpScriptTransform":"undefined","mediaDeviceKinds":[]}
```

This is a negative result: WebRTC is unavailable in the Linux webview. See `docs/SPIKES.md` §B and ADR-0003.

### Spike C: Tauri 2 on Android (GitHub Actions, emulator)

GitHub Actions `spike-android`, run 38746889576 (conclusion: **success**). Excerpt of the job log:

```
android_version=14
abi=x86_64
webview_versionName=113.0.5672.136
Performing Streamed Install
Success
Status: ok
LaunchState: COLD
TotalTime: 3613
I VeilProbe: veil_webrtc_probe_lib: VEIL_PROBE_RESULT {"userAgent":"Mozilla/5.0 (Linux; Android 14; sdk_gphone64_x86_64 Build/UE1A.230829.050; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/113.0.5672.136 Mobile Safari/537.36","origin":"http://tauri.localhost","secureContext":true,"RTCPeerConnection":"function","RTCDataChannel":"function","getUserMedia":true,"RTCRtpScriptTransform":"undefined","loopbackAll":{"ok":true,"ms":1431,"candidates":{"a":["host/udp","host/udp"],"b":["host/udp","host/udp"]},"fingerprintInSdp":true},"relayPolicyAccepted":true,"generateCertificate":true,"mediaDeviceKinds":["audioinput","videoinput","audiooutput"]}
=== libsignal spike on device
PASS PQXDH: Alice processes Bob's bundle (EC + signed Kyber1024 prekey) (Ok(()))
PASS first message is PreKeySignalMessage v4+ with ML-KEM ciphertext (version 4, KEM ciphertext 1569 bytes)
PASS Bob decrypts first message
PASS 40 alternating messages decrypt (Double Ratchet steps)
PASS SPQR triple ratchet active: post-quantum ratchet data present in messages (40/40 messages carried SPQR data)
PASS bit-flip at every byte of a SignalMessage is rejected (105/105 rejected)
PASS genuine message still decrypts after tamper attempts
PASS replayed message is rejected (Err(DuplicatedMessage(2, 1)))
PASS out-of-order delivery (reverse order) decrypts
PASS changed identity key is refused (UntrustedIdentity) (Err(UntrustedIdentity(ProtocolAddress { name: "bob", device_id: DeviceId(1) })))
PASS bundle with forged Kyber prekey signature is rejected (Err(SignatureValidationFailed))
ALL CHECKS PASSED
```

Also from that run: `target/aarch64-linux-android/release/veil-spike-libsignal: ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /system/bin/linker64`.

Earlier runs, kept for honesty:
- 38741826807 failed: Android rejects app version `0.0.0`.
- 38742060429 failed: APK and libsignal Android builds succeeded, then "No space left on device" while fetching the emulator image.
- 38744023740 failed: the probe page never reported, because the eval-navigation was lost on Android. libsignal passed 11/11 on the device in that run.

## Phase 0: design checks (2026-10-15)

`cd design/tools && node capture.mjs && node check.mjs`

- `capture.mjs`: `OK: 280 screenshots, 0 console errors, 0 CSP violations, 0 network requests`
- `check.mjs`: `PASS`. The full report is in [`design/CHECKS.md`](../design/CHECKS.md):
  - 2,304 contrast pairs ≥ 4.5:1;
  - axe: 0 violations across 244 renders;
  - all targets ≥ 44 px;
  - motion uses transform/opacity only, and nothing runs under reduced motion;
  - 0 network requests;
  - 7/7 keyboard interactions pass.
