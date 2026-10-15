# Phase 1 spikes: findings

Spikes are throwaway code in `spikes/` that answers "will this work?" with real output before we build on it. Raw outputs are committed next to each spike.

| Spike | Question | Answer | Evidence |
|---|---|---|---|
| A | Can we use libsignal (PQXDH + Triple Ratchet) from our own workspace, and does it give the properties the brief requires? | **Yes, 11/11 checks pass** | [`spikes/libsignal/RESULT.txt`](../spikes/libsignal/RESULT.txt) |
| B | Does the Linux webview (WebKitGTK) support WebRTC for calls? | **No.** Ubuntu 24.04 WebKitGTK 2.52.6 has no WebRTC backend, even with `enable-webrtc` | [`spikes/webrtc-probe/RESULT-linux.md`](../spikes/webrtc-probe/RESULT-linux.md) |
| C | Can Tauri 2 build and run on Android, with WebRTC in the Android WebView, and does libsignal build and pass on Android? | **Yes.** APK runs on Android 14; WebView data channel works; libsignal 11/11 on-device | [CI run 38746889576](https://github.com/bewwe01/ataraxia/actions/runs/38746889576), §C |

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

## C. Tauri 2 on Android (GitHub Actions, emulator)

**Setup.** Workflow `.github/workflows/spike-android.yml`, [run 38746889576](https://github.com/bewwe01/ataraxia/actions/runs/38746889576) (success, 2026-10-15):
- Tauri CLI 2.12.3 / tauri 2.12.4;
- NDK 30.0.16248370, Rust 1.97.0;
- universal debug APK, about 38 MB;
- installed on an **Android 14 (API 34) x86_64 emulator** with system WebView **113.0.5672.136**.

| Check | Result |
|---|---|
| `tauri android init` + `android build --apk` | PASS |
| APK installs and cold-starts | PASS (`am start -W`: 3.6 s cold start on the emulator) |
| `RTCPeerConnection` / `RTCDataChannel` in the WebView | PASS: both `function` |
| **Loopback data channel** (two peer connections, message round-trip) | **PASS** in 1431 ms |
| `iceTransportPolicy: "relay"` accepted | PASS |
| `RTCPeerConnection.generateCertificate` + `a=fingerprint:sha-256` in SDP | PASS |
| Media devices enumerated | PASS: audioinput, videoinput, audiooutput |
| **libsignal spike, run natively on the device** | **PASS, 11/11** (identical to Spike A) |
| libsignal cross-compiles for **aarch64-linux-android** (real phones) | PASS: `ELF 64-bit LSB pie executable, ARM aarch64 … /system/bin/linker64` |

Raw probe report (from logcat, tag `VeilProbe`):

```
VEIL_PROBE_RESULT {"userAgent":"Mozilla/5.0 (Linux; Android 14; sdk_gphone64_x86_64 Build/UE1A.230829.050; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/113.0.5672.136 Mobile Safari/537.36","origin":"http://tauri.localhost","secureContext":true,"RTCPeerConnection":"function","RTCDataChannel":"function","getUserMedia":true,"RTCRtpScriptTransform":"undefined","loopbackAll":{"ok":true,"ms":1431,"candidates":{"a":["host/udp","host/udp"],"b":["host/udp","host/udp"]},"fingerprintInSdp":true},"relayPolicyAccepted":true,"generateCertificate":true,"mediaDeviceKinds":["audioinput","videoinput","audiooutput"]}
```

**Findings.**
1. **Tauri 2 is viable for Android** for Veil's needs → ADR-0002 can be accepted.
2. **The Android WebView gathers `host` ICE candidates** even with no STUN/TURN configured. The probe did not record the address values, so whether they were raw local IPs or mDNS-obfuscated is **not established**; the Phase 6 test must capture it. Either way, the Rust-side candidate filter (PROTOCOL §8, INV-NET-1) is **mandatory**. Never rely on the webview to hide addresses.
3. The page origin on Android is `http://tauri.localhost` (still a secure context). The CSP and IPC allowlist must cover both `tauri://localhost` (desktop) and `http://tauri.localhost` (Android).
4. Not yet proven, scheduled for Phase 6:
   - `getUserMedia` with a real permission grant needs the Kotlin `onPermissionRequest` shim plus manifest permissions (tauri-apps #12041, discussion #12732);
   - real-device calls through TURN.
5. Emulator system images ship an old WebView (113). Real devices update it through Google Play, so set a minimum supported WebView version and show a clear message below it.

**CI lessons:**
- the runner ran out of disk while fetching the system image: free about 10 GB first;
- Android rejects app version `0.0.0`;
- navigating with `eval()` immediately after window creation is unreliable on Android.
