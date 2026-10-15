# Veil: Architecture

Status: **Phase 1 draft, awaiting approval.** Companion documents: [`THREAT_MODEL.md`](THREAT_MODEL.md), [`PROTOCOL.md`](PROTOCOL.md), [`INVARIANTS.md`](INVARIANTS.md), [`SPIKES.md`](SPIKES.md). Design: [`../design/DESIGN.md`](../design/DESIGN.md).

Veil is a 1:1 end-to-end encrypted messenger with voice/video calls. There are no accounts, phone numbers or directory. Peers meet through an **untrusted relay** they choose (and can self-host), and through WebRTC for calls.

---

## 1. Components and trust boundaries

```
 ┌──────────────────────────── Device (trusted while unlocked) ────────────────────────────┐
 │                                                                                         │
 │  React + TS UI (webview)            Tauri 2 shell (Rust)                                │
 │  ───────────────────────            ─────────────────────                               │
 │  • renders plain text only    IPC   • narrow, allowlisted commands                      │
 │  • never sees key material  ◄─────► • input validation at the boundary                  │
 │  • strict CSP, no remote            • owns windows, notifications, OS keystore          │
 │    origins                                    │                                         │
 │                                               ▼                                         │
 │                              crates/client (Rust, async I/O)                            │
 │                              • relay connection (WebSocket over TLS 1.3, pinned key)    │
 │                              • encrypted store (SQLCipher) + attachment blob store      │
 │                              • call engine: webview WebRTC, or webrtc-rs on Linux       │
 │                              • enforces relay-only ICE policy                           │
 │                                               │                                         │
 │                                               ▼                                         │
 │                              crates/core (pure Rust, #![forbid(unsafe_code)], no I/O)   │
 │                              • identity, sessions (libsignal: PQXDH + Triple Ratchet)   │
 │                              • sealed envelopes, padding, attachment crypto             │
 │                              • safety numbers, invites, vault key hierarchy             │
 └───────────────────────────────────────────────┬─────────────────────────────────────────┘
                                                 │ TLS 1.3 (rustls), relay key pinned
                         ════════════════ untrusted network ═════════════════
                                                 │
 ┌───────────────────────────── Relay (assumed hostile) ───────────────────────────────────┐
 │  crates/relay (axum + tokio + rustls)          coturn (TURN/STUN)                       │
 │  • mailboxes: store-and-forward ciphertext     • relays call media for relay-only mode  │
 │  • invite & prekey-bundle storage (opaque)     • ephemeral HMAC credentials minted by   │
 │  • attachment blob store (opaque, padded)        the relay                              │
 │  • signaling fan-out (ciphertext only)                                                  │
 │  • rate limits per mailbox/token; no IP logs                                            │
 └─────────────────────────────────────────────────────────────────────────────────────────┘
```

Trust boundaries, outermost first. Each is an input-validation point with fuzz targets ([`INVARIANTS.md`](INVARIANTS.md) §I):

1. **Network → relay.** Everything a client sends is untrusted. Size limits and timeouts apply before parsing.
2. **Relay → client.** Everything the relay returns is untrusted: envelopes, bundles, blobs and timestamps are verified cryptographically, never believed.
3. **Webview → Rust (IPC).** The UI is treated as potentially compromised by XSS. IPC commands take small, typed, validated inputs and return display data only. No command exposes keys, raw ciphertext stores or file-system access.
4. **Peer → client.** A contact's messages are authenticated but may still be malicious. The parser is fuzzed, and sizes and counts are bounded.

## 2. Repository layout

```
crates/
  core/       pure protocol & crypto logic; compiled natively (and WASM only if feasible, see ADR-0007)
  wire/       versioned client↔relay message types (no crypto); shared by client and relay; fuzzed
  client/     async I/O: relay transport (trait-based, Tor-ready), storage, call engine, keystore glue
  relay/      the untrusted server
app/
  src/        React + TypeScript (strict) + Vite UI, ported from design/
  src-tauri/  Tauri 2 shell: IPC command surface, capabilities, platform glue (Android Kotlin bits)
deploy/       Dockerfile(s), docker-compose.yml (relay + coturn), setup README (Raspberry Pi / VPS)
design/       Phase 0 design system and prototypes (approved)
docs/         this documentation, TEST_REPORT.md, REVIEW_REPORT.md
spikes/       Phase 1 throwaway spikes (evidence only; not built into the product)
```

Rust workspace + pnpm workspace at the root. A single `Cargo.lock` and a single `pnpm-lock.yaml`, both committed.

## 3. Data flow summaries

**Send a message.** UI → `send_message(conversation_id, text)` IPC → client loads the session → core: pad → libsignal encrypt (Triple Ratchet) → sealed-sender seal → padded envelope → client posts to the recipient's mailbox with a delivery token → relay stores the ciphertext under the mailbox ID, with a TTL.

**Receive.** Client authenticates to its own mailbox (mailbox key, challenge-response) → fetches envelopes → core: unseal → identify the sender by identity key → decrypt → unpad → store (encrypted at rest) → UI gets display data via an event → client acknowledges, and the relay deletes.

**Call.** UI asks to call → client obtains TURN credentials from the relay → creates a peer connection with `iceTransportPolicy: "relay"` (default) → SDP/ICE are sent **as E2E-encrypted messages** through the mailbox path, after a Rust-side candidate filter → DTLS fingerprints are bound to the authenticated session. Details in [`PROTOCOL.md`](PROTOCOL.md) §8.

## 4. Platform matrix (from the Phase 1 spikes, see [`SPIKES.md`](SPIKES.md))

| Platform | Shell | Messaging | Calls (media) | Status |
|---|---|---|---|---|
| Linux (x86_64) | Tauri 2 + WebKitGTK | ✅ | ❌ in webview (no WebRTC in distro WebKitGTK 2.52) → **webrtc-rs** in Rust; audio first | Built and probed here |
| Android 10+ (arm64, x86_64) | Tauri 2 + Android System WebView (Chromium) | ✅ | ✅ webview WebRTC: data channel proven; mic/camera need the Kotlin permission shim | Spike C passed in CI (API 34 emulator) |
| Windows | Tauri 2 + WebView2 (Chromium) | ✅ | ✅ webview WebRTC expected | Not buildable here; CI workflow later |
| macOS | Tauri 2 + WKWebView | ✅ | ✅ expected (with known permission-prompt quirks) | Not buildable here; CI workflow later |
| iOS | out of scope for v1 | | | |
| Web/PWA fallback | WASM core | ⚠️ see ADR-0007 | | Not committed |

## 5. Key technology choices

| Concern | Choice | Why |
|---|---|---|
| 1:1 protocol | **libsignal** `libsignal-protocol` (git tag, AGPL-3.0) | PQXDH + SPQR Triple Ratchet + sealed sender; deployed at scale; verified in Spike A |
| Groups (later) | **OpenMLS** (MIT), RFC 9420 | standard group protocol; data model leaves room (no v1 code) |
| Symmetric crypto outside libsignal | RustCrypto `chacha20poly1305` (XChaCha20-Poly1305), `hkdf`, `sha2`, `argon2`; `ed25519-dalek`, `x25519-dalek` | audited, maintained, no custom constructions |
| Secrets in memory | `zeroize`, `secrecy`; best-effort `mlock` (see THREAT_MODEL §6) | |
| At-rest DB | SQLCipher via `rusqlite` (`bundled-sqlcipher-vendored-openssl`) | full-DB encryption incl. indices; see ADR-0005 |
| Relay | `axum` + `tokio` + `rustls` (TLS 1.3 only) | memory-safe, `forbid(unsafe_code)` in our code |
| TURN | coturn, `use-auth-secret` (REST API credentials) | standard; credentials are ephemeral HMACs |
| Desktop/mobile shell | **Tauri 2.12.x** (stable; Tauri 3 is alpha) | small attack surface, capability-based IPC ACL |
| Calls on Linux | **webrtc-rs 0.20** (+ `cpal`/Opus for audio) | the only maintained Rust WebRTC with a TURN client; see ADR-0003 |
| UI | React 18 + TypeScript strict + Vite; design tokens from `design/tokens.css` | approved Phase 0 design |

## 6. Architecture decision records (ADRs)

### ADR-0001: libsignal for 1:1 messaging; Veil is AGPL-3.0 and public. **Accepted (owner, Phase 1).**
- **Context.** The brief prefers an audited implementation with post-quantum hybrid agreement. Verified status (Oct 2026):
  - vodozemac has no PQ support; its PQXDH draft has been on hold since 2024.
  - OpenMLS has only an experimental, non-IANA X-Wing suite.
  - libsignal ships PQXDH plus SPQR (Triple Ratchet, Oct 2025) and sealed sender.
- **Decision.** Use `libsignal-protocol` pinned to an exact git tag (currently `v0.105.0`, commit `4beb029d`). Veil is licensed **AGPL-3.0-only** and developed in public.
- **Consequences.**
  - (+) Strongest available guarantees: forward secrecy, post-compromise security, PQ for the initial agreement and the ratchet, authenticated key exchange, replay/reorder handling, tamper rejection. All checked in Spike A.
  - (−) Signal states use outside its apps is **unsupported** and APIs change without notice. Mitigation: wrap all libsignal use behind `crates/core` interfaces, upgrade deliberately, and keep a wire-version field.
  - (−) Not on crates.io: git dependency pinned by tag and lockfile commit. `cargo vet` needs manual audits for these crates.
  - (−) Uses **libcrux** (formally verified, pre-1.0) for ML-KEM and SHA-3, an accepted exception to the "RustCrypto/ring only" rule, recorded in `deny.toml`/`supply-chain/`.
  - (−) App-store redistribution under AGPL is legally unclear (signalapp/libsignal#684, #691 still unanswered). **v1 distribution is GitHub Releases** (owner request), where AGPL is unproblematic: every release links the exact source.
  - Build needs `protoc`, `clang`, `cmake` (documented in CLAUDE.md and CI).

### ADR-0002: Tauri 2 for desktop and Android. **Proposed. Spike C passed (SPIKES.md §C).**
- Tauri 2.12 stable; Tauri 3 is alpha and not used.
- Android needs a small Kotlin shim for WebView `onPermissionRequest` (mic/camera) and Android Keystore access. This is known community territory: tauri-apps discussion #12732, issue #12041.
- Spike C: the APK builds and runs on Android 14; the WebView data channel works; libsignal passes 11/11 natively.
- The WebView gathers **host ICE candidates** (whether raw or mDNS-obfuscated is still to be captured), so the Rust candidate filter is mandatory.
- Origins differ: `tauri://localhost` (desktop) vs `http://tauri.localhost` (Android).
- Minimum: Android 10 (the WebView's own `minSdkVersion=29`).
- Fallback if Android is unworkable: a PWA with the WASM core is **not** a drop-in (see ADR-0007). The realistic fallback would be a native Kotlin UI over the same Rust core via UniFFI. Not needed if Spike C passes.

### ADR-0003: Calls on Linux use webrtc-rs in Rust; elsewhere the webview's WebRTC. **Proposed.**
- Spike B: Ubuntu 24.04's WebKitGTK 2.52.6 exposes **no `RTCPeerConnection`**, even with `enable-webrtc=true`. The package is built without a WebRTC backend; upstream plans LibWebRTC around 2.56 (~March 2027).
- Messaging, attachments and signaling never use WebRTC, so Linux loses nothing there.
- Linux calls: webrtc-rs 0.20 (has a TURN client; open TURN bugs webrtc-rs#890/#894 to track) + `cpal` + Opus. **Audio first; Linux video in a later phase.**
- Security upside: on Linux the relay-only candidate policy and DTLS fingerprint binding are enforced entirely in Rust.
- Alternative rejected for now: bundling our own WebKitGTK build (huge maintenance and supply-chain cost).

### ADR-0004: Relay-only is the default transport; Direct is a per-contact opt-in. **Accepted (brief).**
- Relay-only uses `iceTransportPolicy: "relay"`, *and* a Rust-side filter that drops any non-`typ relay` candidate before it is encrypted and sent (defence in depth; INV-NET-1).
- Direct mode shows "IP visible to {name}" wherever it is active (design §1).

### ADR-0005: SQLCipher for the local database. **Proposed.**
- `rusqlite` with `bundled-sqlcipher-vendored-openssl`: one build path for Linux, Windows, macOS and Android, with no system OpenSSL dependency.
- Cost: vendored OpenSSL (via `openssl-src`) in the supply chain, used only by SQLCipher's page crypto.
- Alternative: plain SQLite with per-row XChaCha20-Poly1305 (leaks row counts/sizes and complicates indices). Rejected unless you prefer zero OpenSSL.

### ADR-0006: Sealed sender with self-issued sender certificates. **Proposed.**
- Signal's sealed sender assumes a server-issued certificate. Veil has no authority. Each client self-issues its sender certificate under its own identity key.
- This is sound because libsignal's v1 unseal **checks, in constant time, that the certificate key equals the static key authenticated by the outer ECDH** (verified in source: `sealed_sender.rs`, "sender certificate key does not match message key").
- The recipient then looks up the contact by identity key and rejects unknown senders. Details in PROTOCOL.md §6. A Phase 2 test suite must confirm it (INV-MSG-6/7).

### ADR-0007: No WASM/PWA build in v1. **Proposed.**
- `libsignal-protocol` depends on `rayon` (threads) and was not designed for `wasm32`. With Tauri covering desktop and Android, a PWA fallback isn't needed. Revisit only if a platform fails.

### ADR-0008: Supply-chain policy. **Accepted (brief).**
- Exact-pinned dependencies, committed lockfiles, `cargo deny` (licenses: AGPL-compatible allowlist; advisories; bans; sources: crates.io plus the two pinned Signal git repos), `cargo audit`, `cargo vet` (Mozilla/Google/Bytecode Alliance imports plus our own audits), `pnpm audit`, `gitleaks`, lockfile integrity check.
- GitHub Actions pinned by full commit SHA, `permissions: contents: read` by default, `persist-credentials: false`.

## 7. Distribution (recorded owner request)

The final step, after all phases pass the code-reviewer gate, is a GitHub Actions workflow that builds the Android **APK** and publishes it to this repository's **GitHub Releases**. Details:
- Signing keystore lives only in encrypted GitHub secrets.
- A SHA-256 checksum file and the exact source tag are attached to each release, which also satisfies AGPL.
- Desktop artifacts (Linux AppImage/deb) are built the same way. Windows/macOS jobs are added if the owner wants them.
