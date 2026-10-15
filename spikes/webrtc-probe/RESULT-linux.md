# Spike B result: WebRTC in the Tauri webview on Linux (WebKitGTK)

Environment: Ubuntu 24.04.5, `libwebkit2gtk-4.1-0` **2.52.6-0ubuntu0.24.04.1**, Tauri **2.12.4**, run under Xvfb.
Command: `VEIL_PROBE_EXIT=1 xvfb-run -a src-tauri/target/release/veil-webrtc-probe` (and again with `VEIL_ENABLE_WEBRTC=1`).

```
=== WebKit settings untouched
VEIL_PROBE_INFO webkit enable-webrtc default=false media-stream default=true
VEIL_PROBE_RESULT {"userAgent":"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/60.5 Safari/605.1.15","origin":"tauri://localhost","secureContext":true,"RTCPeerConnection":"undefined","RTCDataChannel":"undefined","getUserMedia":true,"RTCRtpScriptTransform":"undefined","mediaDeviceKinds":[]}

=== enable-webrtc=true and enable-media-stream=true set before the probe page loads
VEIL_PROBE_INFO set enable-webrtc=true enable-media-stream=true
VEIL_PROBE_RESULT {... "RTCPeerConnection":"undefined","RTCDataChannel":"undefined","getUserMedia":true ...}
```

Library inspection: `ldd libwebkit2gtk-4.1.so.0` shows **no** GStreamer-WebRTC, libnice or librice linkage, so the Ubuntu package is built **without a WebRTC backend**. Upstream says the GstWebRTC backend is off by default and LibWebRTC becomes the default around WebKitGTK 2.56 (expected about March 2027).

**Conclusion:** WebRTC is not available in the Linux webview on a mainstream distro today, and turning the setting on does not help. `getUserMedia` exists, but there is no peer connection to send the media over.
Consequences (see `docs/ARCHITECTURE.md`, ADR-0003):
- Messaging, attachments and signaling are unaffected; they never use WebRTC (relay WebSocket + mailbox).
- Calls on Linux need the Rust-native fallback your plan foresaw: **webrtc-rs 0.20** (has a TURN client; open TURN bugs #890/#894 to track) with native audio I/O. Video on Linux comes later.
