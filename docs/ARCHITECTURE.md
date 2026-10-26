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
 │  crates/relay (tokio + tungstenite + rustls)   coturn (TURN/STUN)                       │
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
| Relay | `tokio` + `tokio-tungstenite` + `tokio-rustls`/`rustls` with *ring* (TLS 1.3 only), `redb` storage | memory-safe, `forbid(unsafe_code)` in our code; see ADR-0010 |
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
- The recipient then looks up the contact by identity key and rejects unknown senders. Details in PROTOCOL.md §6. Confirmed by Phase 2 tests with hand-built hostile envelopes: `certificate_key_must_match_sealing_key`, `strangers_and_self_addressed_envelopes_dropped` (INV-MSG-6/7).

### ADR-0007: No WASM/PWA build in v1. **Proposed.**
- `libsignal-protocol` depends on `rayon` (threads) and was not designed for `wasm32`. With Tauri covering desktop and Android, a PWA fallback isn't needed. Revisit only if a platform fails.

### ADR-0008: Supply-chain policy. **Accepted (brief).**
- Exact-pinned dependencies, committed lockfiles, `cargo deny` (licenses: AGPL-compatible allowlist; advisories; bans; sources: crates.io plus the two pinned Signal git repos), `cargo audit`, `cargo vet` (Mozilla/Google/Bytecode Alliance imports plus our own audits), `pnpm audit`, `gitleaks`, lockfile integrity check.
- GitHub Actions pinned by full commit SHA, `permissions: contents: read` by default, `persist-credentials: false`.

### ADR-0009: Envelopes fill their bucket from inside the sealed-sender encryption. **Accepted (owner, 2026-10-19). Implemented after review round 1, H1; recorded after review round 2, N4.**
- **Problem.** Framing v1 (`len || sealed || zero padding`) showed the relay the exact sealed size and the message type, so it learned more than the bucket that THREAT_MODEL §5 promises.
- **Composition.** This is libsignal's own `sealed_sender_encrypt` composition, with one change:
  - `message_encrypt` produces the inner message;
  - `UnidentifiedSenderMessageContent::new(type, cert, inner, hint, group_id)` wraps it;
  - `sealed_sender_encrypt_from_usmc` seals it;
  - the change: the unused `groupId` field carries zero bytes, and `contentHint` is toggled (+2 bytes) where a protobuf varint boundary would skip a size.
  - The filler length is searched for so that `1 + sealed` equals the bucket exactly. Framing v2 is just `version (2) || sealed`.
- **No new primitive.**
  - Both fields sit inside the sealed-sender ciphertext, which is encrypted and MAC'd by libsignal.
  - Their content is not secret, and the recipient ignores both.
  - The only property used is "the encrypted part has a length we choose".
- **Receiver.**
  - Requires the exact sealed-sender v1 version byte `0x11`. libsignal reads only the high nibble; this also refuses sealed-sender v2.
  - Ignores `groupId` and `contentHint`.
- **Cost.** A few extra X25519 operations per seal for the size search: worst case 6.4 ms, measured by reviewer round 2.
- **Evidence.**
  - `relay_learns_only_the_bucket`;
  - reviewer round 2's exhaustive scan of inner lengths 0–65 600, which found no size gap;
  - `largest_valid_content_always_seals`.

### ADR-0010: Relay stack: plain WebSocket over rustls with *ring*, redb storage. **Proposed (Phase 3).**
- **WebSocket without a web framework.**
  - The relay has a single endpoint, a binary WebSocket carrying protobuf frames, so `tokio-tungstenite` on a `tokio-rustls` stream replaces the `axum` planned in Phase 1. There is no HTTP routing, no middleware, and fewer dependencies to vet.
  - Frame and message size caps are set in the WebSocket config, so oversize input is refused before it is buffered.
- **rustls with the *ring* provider, TLS 1.3 only.**
  - This avoids `aws-lc-rs`, which needs CMake and a C toolchain for every target, the Pi build included, and brings a large C and assembly crypto library into the audit surface.
  - **Cost:** *ring* has no ML-KEM, so the relay TLS key exchange is classical (X25519). Message content is post-quantum protected end to end (PQXDH + SPQR) regardless. What a harvest-now-decrypt-later attacker could later recover is only what the relay itself sees: mailbox ids, tokens, sizes and timing (THREAT_MODEL §5).
  - Revisit when rustls ships a pure-Rust ML-KEM provider, or switch the relay and client together to `aws-lc-rs` with `X25519MLKEM768`.
- **Trust by pin, not CA.**
  - `veil-relay gen-cert` creates a self-signed ECDSA P-256 certificate.
  - Clients pin the SHA-256 of its SPKI, delivered in invites or by manual entry. No domain or CA is needed, and a CA cannot mint a substitute.
  - At load time the relay checks that the certificate carries the key's SPKI, so the pin it prints is the key it serves.
- **redb for storage.**
  - Pure Rust, transactional (ACID, copy-on-write), single file, no `unsafe` in our code paths.
  - Every multi-record change (deposit + counters, take-invite + delete, blob chunk + quota) is one write transaction.
  - Records are fixed-layout byte strings with checked decoding, so a corrupt record yields `Corrupt`, never a panic.
- **No IP records.** Abuse control is by token, mailbox, connection, source key (below) and relay-wide limits, plus storage caps. Nothing IP-derived is written to disk or logs. The trade-off, that anyone can create mailboxes up to the caps, is documented in `deploy/README.md` and THREAT_MODEL §5.
- **The one use of the peer address (reviews P3-4, P3R2-1/2/3):** a truncated source key (IPv4 address or IPv6 /64), held in memory only and never logged or stored. It caps what one host can take of relay-wide resources:
  - concurrent connections (32, configurable);
  - its share of the response budget (8 MiB of 64);
  - mailbox creations and upload tokens (rate buckets in a bounded, evicting map).

  Connection counts and budget shares are dropped at zero, and rate buckets once they refill (the sweep prunes them; review P3R3-4). Without the key, one host could exhaust each of these.
- **Bounded memory (review P3-1).**
  - redb's page cache is set explicitly (64 MiB by default, `VEIL_DB_CACHE_MB`); redb's own default of 1 GiB let the process outgrow its container limit.
  - Expiry uses an index table (`kind ‖ due ‖ id`), so a sweep reads only due entries, in batches of 256, each its own write transaction.
  - Writes to clients time out, and large responses share a relay-wide byte budget.
  - Measured in a 512 MiB container: 71 MB peak while filling 630 MB of envelopes; a sweep with nothing due takes 1.5 ms; expiring 9 600 envelopes takes 0.77 s at 36 MB.
  - The cost: redb's file reached an apparent size of 3.4× the stored payload in that test (it grows in large steps), with about 2× actually allocated. Disk is sized from the caps, including the token-row and upload-token caps (`deploy/README.md`).
- **Schema version (P3R2-9).** The store records its layout version and refuses a database of another version, or an unversioned one that holds data. An older layout would otherwise open with no expiry entries, and its records would never expire.

### ADR-0011: Phase 4 scope cut (owner request, 2026-10-19). **Accepted.**
The owner asked to finish the mandatory parts and ship installers within a limited budget. Phase 4 therefore ships:
- `crates/client`: SQLCipher store (vendored OpenSSL, the only OpenSSL in the tree, enforced by `deny.toml`), pinned TLS 1.3 relay link, a single-threaded actor around `Account` (which is `!Send`).
- `app/`: onboarding with the vault, unlock, auto-lock after 5 minutes without user input (incoming messages do not postpone it; a lock pre-empts relay I/O), start over (reset), invites by link (QR shows the link; there is no camera scanner), 1:1 text chat over one relay, safety numbers with verify/clear, rename, the two themes.
- Device secret: Windows Credential Manager; Android/Linux a 0600 file in the app's private directory (INV-REST-2 is partial there). The APK excludes all app data from backup and device transfer and sets FLAG_SECURE.
- Release builds: signing happens only for a version tag, in a separate job in the `release` environment that runs no project code.

Cut, and listed as future work: mailbox rotation and unlinkable deposits (so in v1 the relay can link sender and recipient mailboxes; THREAT_MODEL updated), attachments, voice notes, disappearing messages, calls (Phase 6), backup, panic wipe, notifications, camera QR scanning, multi-relay, Android Keystore, a key-change warning UI, Linux/macOS packages. Unused invites keep their delivery token registered at the relay until the mailbox is gone (fixed in ADR-0013).

### ADR-0012: PIN or password, biometric unlock, Purge PIN. **Accepted (owner request, 2026-10-25).**
**Context.** The owner asked for a choice between a PIN and a password, biometric unlock with a settings toggle, and an optional duress code (the "Purge PIN") that wipes Veil when it is entered at the unlock screen.

**Decision.** No new primitive; two HKDF/XChaCha20-Poly1305 compositions in `crates/core/src/vault.rs`, beside the existing KEK:
- *Purge tag* = HKDF-SHA-256(`Argon2id(input) || device_secret`, salt = vault id, info `veil/v1/purge-tag`). The client stores it in `purge.tag` (a random tag when no Purge PIN is set, so the file exists either way). Unlock runs Argon2id once and derives both the KEK and the tag: passphrase → open; tag match (constant time) → purge; otherwise wrong. The tag needs the device secret, so offline it is the same guessing oracle as the header, no weaker. A Purge PIN equal to the passphrase is refused. Changing the PIN/password re-salts the header, so the Purge PIN is cleared and must be set again.
- *Secret wrap* = XChaCha20-Poly1305 of the DB key under HKDF(`secret || device_secret`, salt = vault id, info `veil/v1/secret-kek`), AAD `veil/v1/secret-wrap || vault id`. `secret` is 32 random bytes that only the Android Keystore releases, after a BiometricPrompt, from a key created with user authentication required (BIOMETRIC_STRONG, every use) and invalidated by new enrolments. The webview never sees it: the Rust side calls the Kotlin code directly, and Tauri 2.12 rejects every `plugin:` IPC call that has no capability entry (`tauri/src/webview/mod.rs`, ACL check); our capability grants none for this plugin.
- PIN: 6 to 16 digits. Password: at least 12 characters. A PIN has far less entropy, so it relies on the device secret (hardware-bound on Android) and on failed-attempt delays. Someone holding a copy of the files and the device secret bypasses the delays: the UI says a PIN is weaker.
- Device secret on Android (review U-2): the file holds the secret sealed by a non-exportable Android Keystore key (`veil.device.v1`, StrongBox if the phone has it, else the TEE; no user authentication, it only binds the file to this phone's hardware). Plain files from 0.1 previews are sealed on first unlock; the old plain copy may survive in flash blocks, so crypto-erasure only holds for vaults created (or reset) with this version (UR2-7).
- Purge: on a match the client deletes the device secret and its Keystore key and the header first (retried), then every other file in `crates/client` `DATA_FILES` (only Veil's own files, in Veil's own `vault/` folder; files from 0.1 previews are moved there once). The app deletes the biometric Keystore key and clears the webview's storage. On Android, deleting the Keystore keys destroys the only way to open the leftover file blocks (crypto-erasure, as far as the phone's keystore hardware erases keys). On Windows the Credential Manager entry is deleted, but a forensic copy of the disk taken with the user's Windows password could still recover it; the UI says so. Not covered: ciphertext already at the relay (it expires there), and copies taken while Veil was unlocked.
- The Purge PIN is checked even during a retry delay (U-3, UR2-3): the lock screen still submits while it shows the wait; the passphrase is not checked then.
- The Android Keystore calls run on a helper thread with a 10 s timeout, so a lost platform response cannot hang the client (UR2-8). Base64 copies of the secrets in the JVM and in serde_json buffers cannot be wiped (U-10, INV-REST-4).
- After a purge, until Veil restarts, the lock screen keeps the same keyboard, fingerprint button and retry delays as before (U-4); the fingerprint prompt then ends as if the fingerprint set had changed. The next start shows the welcome screen. The purge path takes a little longer than a wrong attempt (file deletion, Keystore calls).
- Fingerprint unlock and the Purge PIN pull in opposite directions: the lock screen offers the fingerprint first, so someone can force a finger without meeting the Purge PIN. Settings says so (U-12).
- Five wrong attempts are free; then each waits 30 s, doubling to 1 h. The counter uses the wall clock: changing the clock forward skips it, and a clock moved backwards never makes the wait longer than the delay (U-7).
- Screenshots (owner request after the preview, U-11): FLAG_SECURE is on by default; Settings can lift it, only while unlocked. That also lets the recent-apps screen show Veil.

**Not done.** Windows Hello (biometrics are Android-only for now). A Purge PIN does not tell contacts anything.

### ADR-0013: Contact management and conversation privacy (milestone 1). **Accepted (owner request, 2026-10-26).**
**Context.** The owner asked for a key-change warning, deleting and blocking contacts, disappearing messages, read receipts and typing indicators (off by default), and cleanup of unused invite tokens at the relay. No new primitive or composition: everything is ordinary `Content` inside the existing sessions, and relay token changes the protocol already had.

**Decision.**
- *Key-change warning.* An address is the hash of the identity key, so a changed key always arrives as a new contact, through a new invite (INV-MSG-7). When its introduction carries the name of an existing contact (case and spacing ignored), the new contact gets `key_warning`: the chat and the contact page show "Is this really …?" with a link to the safety number. It is never merged with the old contact or given its history. Verifying the safety number or dismissing clears it. This is a heuristic: an impostor can pick another name or lookalike letters, and the side that *accepts* an invite names the new contact "Contact XXXX", so it gets no warning there; verifying safety numbers stays the real check (INV-ID-2, review M1-10).
- *Delete.* The contact row and its messages are deleted (with `PRAGMA secure_delete`), the core forgets the peer identity and the session (`Account::forget_contact`), and the delivery token we gave them is queued for removal at the relay. Only a new invite brings them back, with a new session.
- *Block.* The delivery token we gave them is withdrawn at the relay, so the relay refuses their deposits; anything already queued from them is dropped on arrival, and nothing is sent to them, including messages queued before the block (review M1-2). They are not told, but their messages fail, which they can notice. Re-pairing with a blocked contact keeps them blocked (M1-9). *Unblock* needs the relay to register a fresh token; it is sent to them in an encrypted `MailboxUpdate` that is stored and retried like a message until it gets through (M1-3). Blocking or unblocking again drops any older update still waiting, and the receiver applies only a newer one (by the sender's clock), so a stale update can never point them at a withdrawn token (M1R2-1). The contact page says when an unblock has not reached them yet. A `MailboxUpdate` that names another relay is ignored (one relay per install). Any contact can point our future deposits at another mailbox with a `MailboxUpdate`; confidentiality is unaffected and they could deposit there themselves, so this is accepted (M1-14).
- *Retries.* While connected, failed messages, timer notices and mailbox updates are retried every minute, not only on reconnect, up to 20 attempts each (M1R2-4).
- *Token removals* are kept in the encrypted database until the relay confirms them, so going offline only delays them. Expired invites are cleaned up on each tick: their prekeys are deleted from the core store and their tokens queued for removal (this closes the gap noted in ADR-0011). A token whose invite could not be published is withdrawn too (M1-12).
- *Disappearing messages.* A per-contact timer (off, 5 min, 1 h, 1 day, 1 week, 4 weeks) is set with a `TimerUpdate`, which is stored and retried like a message and shown as a notice on both sides. Text messages carry the sender's timer; each side deletes its copy that long after sending or receiving it (no "after reading" start). A text that carries no timer (from a version before this one) gets our own timer for the conversation, but such a version keeps its own copies (M1-15). Only a timer change newer than the last one either side made is applied, and setting a new timer drops any older change still waiting to be sent, so a retry cannot undo a later change (M1-7) and of two simultaneous changes the later one wins on both sides (M1R2-2). "Later" compares the two phones' clocks, so a phone whose clock is far off can lose such a race. Unread counts shrink with the messages that expire (M1-11). Expired rows are deleted every tick and on unlock, with `secure_delete` overwriting their content in the database file; the message list hides them on time in the UI in between (M1R2-5). An unsent message that expires is deleted unsent. The relay never sees the timer.
- *Read receipts and typing indicators* are one setting each, both off. Receipts are reciprocal: with them off, Veil sends none and ignores incoming ones. Turning receipts on sends no receipt, delivery or read, for any older message (M1-4). A conversation counts as read only while the window is visible and focused (M1-5). A receipt the other side's relay refuses for good (they blocked or deleted us) counts as sent, so it is not sealed again on every sync (M1-6). Delivery receipts go out after each sync, read receipts when the conversation is shown; each is one envelope per contact with up to 64 ids. Typing is sent at most every 4 s while typing, plus "stopped"; typing messages older than 15 s (by the sender's clock) are not shown. Receipts and typing are best effort, never stored or retried, never sent to a blocked contact or ahead of our introduction, and need the relay to be reachable (so the session is not advanced for a message that cannot go out).

**Costs.** Receipts and typing add envelopes the relay can count and time (THREAT_MODEL §4). Database schema migrations now exist (`PRAGMA user_version`, `crates/client/src/db.rs`).

### ADR-0014: Everyday messaging (milestone 2). **Accepted (owner request, 2026-10-26).**
**Context.** The owner asked for replies, reactions, editing and deleting messages, message search, scanning QR codes with the camera, and verifying a contact in person by scanning. No new primitive: replies, reactions, edits and deletes use the `Text.reply_to`, `Reaction`, `Edit` and `Delete` content the core already validates, inside the existing sessions.

**Decision.**
- *Replies* carry the quoted message's 16-byte id; the quote is resolved locally in the same conversation, and shows "not available" when that message is gone or was deleted. Only texts that have an id (sent or received with preview.4 or later) can be quoted or reacted to.
- *Reactions*: one per person per message, changeable and removable, on either side's texts in that conversation. The core limits an emoji to 8 characters and 32 bytes without control characters; the UI renders it as a text node.
- *Edit and delete for everyone*: only our own messages, for 24 h after sending. A received edit or delete applies only to that contact's **own** messages received in the last 48 h (the query matches `mine = 0` and the conversation), so a contact can never change or remove what we wrote, or a message in another conversation. Deleting for everyone overwrites the text (`secure_delete`), drops reactions, and cancels the message if it was still waiting to be sent. It is best effort: they may have seen or copied it, and a version before preview.5 ignores it (THREAT_MODEL §3.7). *Delete for me* removes the row on this device only.
- Reactions, edits and deletes are stored as hidden outgoing rows and delivered and retried like messages (so they are not lost offline), never sent to a blocked contact.
- *Search* runs a `LIKE` query inside the encrypted database (wildcards escaped, 2–100 characters, at most 100 results, deleted and expired messages excluded). Nothing is indexed outside SQLCipher and nothing leaves the device.
- *QR scanning* uses the webview's camera (`getUserMedia`) and decodes frames locally with jsQR 1.4.0 (Apache-2.0, no dependencies, no network). Frames are not stored; the stream stops as soon as a code is read. Android asks for the camera permission at first use; the APK declares CAMERA as optional hardware. Invite codes go to the normal invite path.
- *Verify by scanning*: each side shows the libsignal `ScannableFingerprint` of the pair as a QR code (`veil-verify:` + hex); the other scans it and libsignal compares both identity keys in it with ours. Only a match marks the contact verified; a mismatch is shown as a warning and changes nothing. The code is public (it commits to both public keys) and is only drawn by the webview.

## 7. Distribution (recorded owner request)

The final step, after all phases pass the code-reviewer gate, is a GitHub Actions workflow that builds the Android **APK** and publishes it to this repository's **GitHub Releases**. Details:
- Signing keystore lives only in encrypted GitHub secrets.
- A SHA-256 checksum file and the exact source tag are attached to each release, which also satisfies AGPL.
- Implemented in `.github/workflows/release.yml`: an arm64 APK and a Windows NSIS installer, published as a pre-release on a `v*` tag with `SHA256SUMS.txt`. The owner asked for Windows; Linux/macOS packages are not built yet.
- Without the keystore secrets the APK is signed with a throwaway key made in that run, and the release notes say so. The Windows installer is not code-signed.
- **Repository settings the workflow relies on (review P4R2-3; not visible in the repo, must be set by the owner before the first `v*` tag with a real key):**
  - Settings → Environments → `release`: deployment branches and tags restricted to the `v*` tag pattern; required reviewer = the owner; the `ANDROID_KEYSTORE_*` secrets stored here only.
  - No repository-level `ANDROID_KEYSTORE_*` secrets.
  - Settings → Rules → a tag ruleset for `v*` so only the owner can create these tags.
  Without these, anyone with push access could reach the signing job. With no keystore secrets at all, releases are signed with a throwaway key and the notes say so.
