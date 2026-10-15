# Veil: Test report

Real command output only. Updated at the end of every phase. Earlier phases' entries are kept for history.

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

_Filled in from CI; see `docs/SPIKES.md` §C._

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
