# Phase 1 spikes: findings

Spikes are throwaway code in `spikes/` that answers "will this work?" with real output before we build on it. Raw outputs are committed next to each spike.

| Spike | Question | Answer | Evidence |
|---|---|---|---|
| A | Can we use libsignal (PQXDH + Triple Ratchet) from our own workspace, and does it give the properties the brief requires? | **Yes, 11/11 checks pass** | [`spikes/libsignal/RESULT.txt`](../spikes/libsignal/RESULT.txt) |
| B | Does the Linux webview (WebKitGTK) support WebRTC for calls? | **No.** Ubuntu 24.04 WebKitGTK 2.52.6 has no WebRTC backend, even with `enable-webrtc` | [`spikes/webrtc-probe/RESULT-linux.md`](../spikes/webrtc-probe/RESULT-linux.md) |
| C | Can Tauri 2 build and run on Android, with WebRTC in the Android WebView, and does libsignal build and pass on Android? | _see §C_ | CI workflow `spike-android` |

---

## A. libsignal from our workspace

**Setup.** `libsignal-protocol` pinned to git tag `v0.105.0` (commit `4beb029d`), Rust 1.97.0, Ubuntu 24.04, release build. Two in-memory parties; Bob publishes a full PQXDH bundle (EC one-time prekey, signed EC prekey, signed Kyber1024 prekey).

| Check | Result |
|---|---|
| PQXDH bundle processing | PASS |
| First message is a v4 `PreKeySignalMessage` with an ML-KEM ciphertext | PASS (1569-byte KEM ciphertext) |
| 40 alternating messages | PASS |
| **SPQR (post-quantum ratchet) data present in messages** | PASS (40/40) |
| **Bit flip at every byte position** of a `SignalMessage` rejected | PASS (105/105) |
| Genuine message still decrypts after all tamper attempts (no state corruption) | PASS |
| Replay rejected | PASS (`DuplicatedMessage`) |
| Out-of-order (reverse) delivery | PASS |
| Changed identity key refused | PASS (`UntrustedIdentity`) |
| Forged Kyber-prekey signature rejected | PASS (`SignatureValidationFailed`) |

**Supply chain.**
- 117 unique crates; **no BoringSSL/OpenSSL**.
- curve25519-dalek 5.0 and x25519-dalek 3.0 come from crates.io (not forks).
- RustCrypto `aes`, `hkdf`, `hmac`, `sha2`.
- **libcrux** (ML-KEM, SHA-3; formally verified, pre-1.0) is the one exception to the "RustCrypto/ring only" rule (ADR-0001).
- Git dependencies: libsignal (tag v0.105.0) and `spqr` (tag v1.6.0).

**Also verified in the libsignal source** (for ADR-0006): sealed sender v1 rejects a certificate whose key differs from the ECDH-authenticated static key (`ct_eq`, "sender certificate key does not match message key"). That makes self-issued sender certificates sound for Veil.

**Toolchain notes.** libsignal's own repo pins Rust 1.98.1, but the protocol crate declares `rust-version = 1.85` and built fine with 1.97.0. The `protoc` binary is required (prost build script).

## B. WebRTC in WebKitGTK (Linux)

A Tauri 2.12.4 probe app creates its window on a blank page, optionally sets WebKit's `enable-webrtc` and `enable-media-stream` *before* loading the probe, then tests `RTCPeerConnection`, a loopback data channel and ICE candidate types. Run under Xvfb:

| Setting | `RTCPeerConnection` | `RTCDataChannel` | `getUserMedia` |
|---|---|---|---|
| default (`enable-webrtc=false`) | `undefined` | `undefined` | present |
| `enable-webrtc=true` | **`undefined`** | **`undefined`** | present |

`ldd libwebkit2gtk-4.1.so.0` shows no GStreamer-WebRTC, libnice or librice linkage. The distro build has **no WebRTC backend compiled in**. Upstream: GstWebRTC off by default; LibWebRTC planned as default around 2.56 (~March 2027).

**Decision → ADR-0003.**
- Messaging is unaffected.
- Linux calls use **webrtc-rs 0.20** (TURN client included) with native audio I/O. **Audio first, video later.**
- Track webrtc-rs TURN issues #890 (srflx gathering when STUN and TURN share an address; affects Direct mode only) and #894 (TURN allocation not released on ICE restart).

## C. Tauri 2 on Android

_Pending: filled in from the CI run of `.github/workflows/spike-android.yml`._
