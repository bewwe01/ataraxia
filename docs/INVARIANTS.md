# Veil: Security invariants

The canonical list of testable promises. [`THREAT_MODEL.md`](THREAT_MODEL.md) and [`PROTOCOL.md`](PROTOCOL.md) cite these IDs, and the code-reviewer gate checks each one against real evidence in [`TEST_REPORT.md`](TEST_REPORT.md).

**Status key:**
- **planned**: test to be written in the listed phase.
- **spike-evidence**: demonstrated in a Phase 1 spike, to be re-proven by product tests.
- **argument**: cannot be fully tested automatically; the written argument must be reviewed.

| ID | Invariant | How it is proven | Phase | Status |
|---|---|---|---|---|
| **Cryptography** |||||
| INV-CRY-1 | Every session starts with PQXDH including an ML-KEM (Kyber1024) encapsulation | unit test inspects first message (`kyber_ciphertext` present, version ≥ 4) | 2 | spike-evidence (Spike A: 1569-byte KEM ct, v4) |
| INV-CRY-2 | The SPQR post-quantum ratchet is active in every established session | test: every `SignalMessage` carries non-empty `pq_ratchet` data after setup | 2 | spike-evidence (40/40) |
| INV-CRY-3 | No downgrade: bundles without a signed Kyber prekey, message versions < 4, and unknown/older wire versions are rejected | negative tests with crafted inputs | 2 | planned |
| INV-CRY-4 | One-time prekeys are deleted after use, locally and on the relay | store test + relay integration test | 2–3 | planned |
| INV-CRY-5 | Only reviewed constructions: no custom crypto; nonces are random 192-bit (XChaCha) or libsignal-managed; nonce uniqueness property-tested | `proptest` over 1e6 nonces; `cargo deny` bans; code review | 2 | planned |
| **Messages** |||||
| INV-MSG-1 | Round-trip: every `Content` type survives encrypt → seal → pad → unseal → decrypt → unpad unchanged | `proptest` round-trips | 2 | planned |
| INV-MSG-2 | **Any single bit flip** in any envelope, header, sealed layer or ciphertext is rejected, and session state is unaffected afterwards | exhaustive bit-flip test per byte position | 2 | spike-evidence (105/105 positions) |
| INV-MSG-3 | Replayed envelopes are rejected and never shown twice | test: decrypt twice → `DuplicatedMessage`; app-level `id` dedupe | 2 | spike-evidence |
| INV-MSG-4 | Out-of-order delivery within libsignal's window decrypts; beyond it fails cleanly (no panic, no state corruption) | `proptest` with random permutations and drops | 2 | spike-evidence (reverse order of 6) |
| INV-MSG-5 | Decoders never panic on arbitrary input | `cargo fuzz` targets: envelope, content, invite, wire frames (≥ 1 h each in CI nightly, corpus committed) | 2–3 | planned |
| INV-MSG-6 | Sealed sender: certificate key ≠ outer static key → rejected | test with a mismatched self-issued certificate | 2 | planned (verified in libsignal source) |
| INV-MSG-7 | Envelopes from unknown identity keys are dropped unless they redeem a live invite of ours | test | 2 | planned |
| **Identity & pairing** |||||
| INV-ID-1 | The address is derived from the identity key; no user-chosen identifiers reach the relay | unit test + relay DB inspection test | 2–3 | planned |
| INV-ID-2 | A changed identity key is **never auto-accepted**: messages held, sending paused, warning shown; verified status drops to unverified | core test (`UntrustedIdentity`) + E2E UI test | 2, 4 | spike-evidence (core part) |
| INV-ID-3 | Safety numbers are symmetric (both sides see the same 60 digits) and change when either key changes | unit tests + known-answer vectors | 2 | planned |
| INV-PAIR-1 | A redeemed invite's bundle must carry the identity key embedded in the QR/link; any mismatch aborts | test with swapped bundle | 2 | planned |
| INV-PAIR-2 | Invites are single-use and expire; the relay deletes them on first fetch | relay integration test | 3 | planned |
| INV-PAIR-3 | "Verified" is set only by mutual in-person scan or explicit safety-number confirmation | state-machine tests + E2E | 2, 4 | planned |
| **Metadata** |||||
| INV-META-1 | The relay never receives an identity key, address, display name or contact list in any request | integration test captures every relay request and asserts absence (byte search for all identity keys/addresses) | 3 | planned |
| INV-META-2 | Relay DB, logs and metrics contain **no IPs, User-Agents, mailbox IDs in logs, or message sizes in logs** | integration test greps DB dump and log output after a scripted session | 3 | planned |
| INV-META-3 | Every envelope on the wire is exactly one bucket size; attachments are Padmé-padded | wire-capture test | 3 | planned |
| **Network & calls** |||||
| INV-NET-1 | **In relay-only mode, no SDP/ICE candidate other than `typ relay` is ever sent** (and incoming ones are dropped) | property test of the Rust filter with fuzzed SDP + E2E test capturing all signaling plaintexts from two real clients | 2, 6 | planned |
| INV-NET-2 | The relay TLS key is pinned; mismatch is a hard failure with no user override | integration test with a wrong cert | 3 | planned |
| INV-NET-3 | Call signaling only travels as E2EE `Content::Call` | wire-capture test | 6 | planned |
| INV-NET-4 | SDP without exactly one `sha-256` fingerprint, or with an inconsistent `a=setup`, is rejected; DTLS peer must match | unit tests + E2E with a MITM TURN | 6 | planned |
| INV-NET-5 | No network request from the app goes anywhere except the configured relay and TURN hosts | Playwright/WebView request interception + Rust connector allowlist test | 4 | planned |
| **Attachments** |||||
| INV-ATT-1 | Truncation, chunk reordering, chunk swapping between files, and bit flips in any chunk are detected | tests per case | 5 | planned |
| INV-ATT-2 | Ciphertext hash is verified before decryption | test | 5 | planned |
| INV-ATT-3 | Resumed uploads/downloads produce byte-identical results | test with interruption at random offsets | 5 | planned |
| **Data at rest** |||||
| INV-REST-1 | No plaintext message, key or contact data is written outside SQLCipher / the encrypted attachment store | test scans the data dir, temp dir and logs for known plaintext canaries after a scripted session | 2, 4 | planned |
| INV-REST-2 | Opening the vault needs **both** the passphrase-derived key and the OS-keystore secret | unit tests (each alone fails) | 2 | planned |
| INV-REST-3 | Panic wipe leaves nothing decryptable: keystore entry gone, header gone, DB and attachments gone | test + manual Android check | 7 | planned |
| INV-REST-4 | Secrets are zeroized on drop/lock; no secret type implements `Debug`/`Display` revealing bytes | `zeroize` drop tests + compile-time checks + clippy lint | 2 | planned |
| INV-REST-5 | Notifications never contain sender or content | unit test on the notification builder + Android check | 7 | planned |
| **UI / IPC** |||||
| INV-UI-1 | Message text is rendered as text (no `dangerouslySetInnerHTML`, no `innerHTML`) | ESLint rule + XSS payload E2E test | 4 | planned |
| INV-UI-2 | CSP: no inline script, no `eval`, no remote origins; Trusted Types where supported | config test + CSP violation monitor in E2E | 4 | planned |
| INV-UI-3 | No IPC command returns key material or raw ciphertext; every input validated with size limits | IPC surface inventory test + fuzzing of command args | 4 | planned |
| INV-UI-4 | Link previews are off by default | settings test | 4 | planned |
| INV-UI-5 | Tauri capabilities grant no shell, fs or http plugin to the webview | capability file test | 4 | planned |
| **Robustness, logging, supply chain** |||||
| INV-ROB-1 | Relay and client never panic on untrusted input; bounded queues, timeouts, rate limits | fuzzing + load tests | 3 | planned |
| INV-LOG-1 | Logs never contain plaintext, keys, tokens, mailbox IDs or sizes | log-capture test with canaries | 2–3 | planned |
| INV-SUP-1 | All deps exact-pinned with committed lockfiles; CI fails on lockfile drift | CI job | 2 | planned |
| INV-SUP-2 | `cargo deny` (licenses/advisories/bans/sources), `cargo audit`, `pnpm audit`, secret scan pass | CI job | 2 | planned |
| INV-SUP-3 | `cargo vet` passes, with documented audits for the libsignal/spqr git crates and libcrux | CI job + `supply-chain/` | 2 | planned |
| INV-SUP-4 | Releases ship SHA-256 checksums and link the exact source tag; signing keys never in repo | release workflow check | 8 | planned |
