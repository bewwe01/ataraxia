# Veil: Security invariants

The canonical list of testable promises. [`THREAT_MODEL.md`](THREAT_MODEL.md) and [`PROTOCOL.md`](PROTOCOL.md) cite these IDs, and the code-reviewer gate checks each one against real evidence in [`TEST_REPORT.md`](TEST_REPORT.md).

**Status key:**
- **planned**: test to be written in the listed phase.
- **spike-evidence**: demonstrated in a Phase 1 spike, to be re-proven by product tests.
- **argument**: cannot be fully tested automatically; the written argument must be reviewed.
- **tested**: the named tests pass (see [`TEST_REPORT.md`](TEST_REPORT.md)); "(core)" means the Rust core part only.
- **partial**: part of the invariant is tested; the rest is listed with its phase.

| ID | Invariant | How it is proven | Phase | Status |
|---|---|---|---|---|
| **Cryptography** |||||
| INV-CRY-1 | Every session starts with PQXDH including an ML-KEM (Kyber1024) encapsulation | unit test inspects first message (`kyber_ciphertext` present, version ≥ 4) | 2 | **tested** (core): `account::pq_tests::pqxdh_and_spqr_are_active` (v4, 1569-byte KEM ct) |
| INV-CRY-2 | The SPQR post-quantum ratchet is active in every established session | test: every `SignalMessage` carries non-empty `pq_ratchet` data after setup | 2 | **tested** (core): `pqxdh_and_spqr_are_active` checks SPQR data on every later message |
| INV-CRY-3 | No downgrade: bundles without a signed Kyber prekey, message versions < 4, and unknown/older wire versions are rejected | negative tests with crafted inputs | 2 | **partial**: wire version → `envelope::tests::strict_parsing`; `open` rejects message version < 4 or a PreKey message without a Kyber prekey id (`account.rs`, *argument only*: libsignal's API cannot produce a v3 message to test with); the invite package has no field layout without a signed Kyber prekey |
| INV-CRY-4 | One-time prekeys are deleted after use, locally and on the relay | store test + relay integration test | 2–3 | **partial**: local deletion after first use → `invite_is_single_use`, `expired_and_revoked_invites_refused`; relay side is Phase 3 |
| INV-CRY-5 | Only reviewed constructions: no custom crypto; nonces are random 192-bit (XChaCha) or libsignal-managed; nonce uniqueness property-tested | `proptest` over 1e6 nonces; `cargo deny` bans; code review | 2 | **tested** (core): `attachment::tests::keys_and_nonce_prefixes_unique` (1e6), `invite::tests::package_nonces_unique`; `cargo deny` bans in `deny.toml`; libsignal manages its own nonces |
| **Messages** |||||
| INV-MSG-1 | Round-trip: every `Content` type survives encrypt → seal → pad → unseal → decrypt → unpad unchanged | `proptest` round-trips | 2 | **tested** (core): `content::tests::roundtrip_text`, `text_roundtrip`, `attachment::tests::prop_roundtrip`, `pairing_and_conversation` |
| INV-MSG-2 | **Any single bit flip** in any envelope, header, sealed layer or ciphertext is rejected, and session state is unaffected afterwards | exhaustive bit-flip test per byte position | 2 | **tested** (core): `every_bit_flip_rejected_and_state_unchanged`, `invite::tests::package_seal_open_and_every_bit_flip_rejected`, `vault::tests::every_header_bit_flip_rejected` |
| INV-MSG-3 | Replayed envelopes are rejected and never shown twice | test: decrypt twice → `DuplicatedMessage`; app-level `id` dedupe | 2 | **tested** (core): `replay_rejected`, `ratchet_properties::shuffled_dropped_duplicated`; app-level `id` dedupe is Phase 4 |
| INV-MSG-4 | Out-of-order delivery within libsignal's window decrypts; beyond it fails cleanly (no panic, no state corruption) | `proptest` with random permutations and drops | 2 | **tested** (core): `out_of_order_delivery`, `ratchet_properties::shuffled_dropped_duplicated` |
| INV-MSG-5 | Decoders never panic on arbitrary input | `cargo fuzz` targets: envelope, content, invite, wire frames (≥ 1 h each in CI nightly, corpus committed) | 2–3 | **tested** (core decoders): 6 `cargo fuzz` targets, 3 min each locally, 0 crashes; corpora committed; CI smoke 60 s each; `*_never_panic` proptests. Wire frames for the relay: Phase 3 |
| INV-MSG-6 | Sealed sender: certificate key ≠ outer static key → rejected | test with a mismatched self-issued certificate | 2 | *argument only*: sealed-sender v1 decrypt checks certificate key = outer static key (libsignal `sealed_sender_decrypt_to_usmc`, read at tag v0.105.0); no public API to forge a mismatched certificate |
| INV-MSG-7 | Envelopes from unknown identity keys are dropped unless they redeem a live invite of ours | test | 2 | **tested** (core): `unknown_and_self_senders_refused`, `invite_is_single_use` |
| **Identity & pairing** |||||
| INV-ID-1 | The address is derived from the identity key; no user-chosen identifiers reach the relay | unit test + relay DB inspection test | 2–3 | **partial**: `identity::tests::address_*` (KAT, canonical form); `envelopes_are_bucket_sized_and_relay_sees_no_identity`. Relay DB test: Phase 3 |
| INV-ID-2 | A changed identity key is **never auto-accepted**: messages held, sending paused, warning shown; verified status drops to unverified | core test (`UntrustedIdentity`) + E2E UI test | 2, 4 | **partial**: `store::tests::identity_policy_is_exact_match_only`, `trust::tests::verified_contact_key_change_scenario`; addresses are key hashes so a key change is a new contact. UI part: Phase 4 |
| INV-ID-3 | Safety numbers are symmetric (both sides see the same 60 digits) and change when either key changes | unit tests + known-answer vectors | 2 | **tested**: `safety::tests::symmetric_digits_and_cross_scan`, `changes_when_either_key_changes`, `safety_numbers_agree_across_the_pair` |
| INV-PAIR-1 | A redeemed invite's bundle must carry the identity key embedded in the QR/link; any mismatch aborts | test with swapped bundle | 2 | **tested** (core): `bundle_must_match_invite_identity`, `invite::tests::package_bound_to_invite_identity_and_id` |
| INV-PAIR-2 | Invites are single-use and expire; the relay deletes them on first fetch | relay integration test | 3 | **partial**: client-side single use and expiry → `invite_is_single_use`, `expired_and_revoked_invites_refused`; relay deletion: Phase 3 |
| INV-PAIR-4 | An invite can only be redeemed by someone holding the invite secret: the redeem proof is an HMAC bound to the invite id and the redeemer's identity key; the relay alone cannot redeem | unit test + relay-forgery test | 2 | **tested** (core): `invite::tests::proof_binds_secret_id_and_redeemer` |
| INV-PAIR-3 | "Verified" is set only by mutual in-person scan or explicit safety-number confirmation | state-machine tests + E2E | 2, 4 | **partial**: `trust::tests::exhaustive_transition_properties`, `in_person_mode_is_reported`; E2E: Phase 4 |
| **Metadata** |||||
| INV-META-1 | The relay never receives an identity key, address, display name or contact list in any request | integration test captures every relay request and asserts absence (byte search for all identity keys/addresses) | 3 | planned |
| INV-META-2 | Relay DB, logs and metrics contain **no IPs, User-Agents, mailbox IDs in logs, or message sizes in logs** | integration test greps DB dump and log output after a scripted session | 3 | planned |
| INV-META-3 | Every envelope on the wire is exactly one bucket size; attachments are Padmé-padded | wire-capture test | 3 | **partial**: `envelope::tests::sizes_are_buckets`, `padding::tests::*`; wire capture: Phase 3 |
| **Network & calls** |||||
| INV-NET-1 | **In relay-only mode, no SDP/ICE candidate other than `typ relay` is ever sent** (and incoming ones are dropped) | property test of the Rust filter with fuzzed SDP + E2E test capturing all signaling plaintexts from two real clients | 2, 6 | **partial**: Rust filter → `ice::tests::relay_only_never_emits_non_relay` (proptest), `sdp_filtering_relay_only`, `relay_only_keeps_only_relay_and_zeroes_raddr`, fuzz target `ice_sdp`; E2E: Phase 6 |
| INV-NET-2 | The relay TLS key is pinned; mismatch is a hard failure with no user override | integration test with a wrong cert | 3 | planned |
| INV-NET-3 | Call signaling only travels as E2EE `Content::Call` | wire-capture test | 6 | planned |
| INV-NET-4 | SDP without exactly one `sha-256` fingerprint, or with an inconsistent `a=setup`, is rejected; DTLS peer must match | unit tests + E2E with a MITM TURN | 6 | **partial**: `ice::tests::dtls_validation`; E2E with MITM TURN: Phase 6 |
| INV-NET-5 | No network request from the app goes anywhere except the configured relay and TURN hosts | Playwright/WebView request interception + Rust connector allowlist test | 4 | planned |
| **Attachments** |||||
| INV-ATT-1 | Truncation, chunk reordering, chunk swapping between files, and bit flips in any chunk are detected | tests per case | 5 | **tested** (crypto layer): `attachment::tests::tamper_reorder_truncate_extend_swap_all_rejected` |
| INV-ATT-2 | Ciphertext hash is verified before decryption | test | 5 | **tested** (crypto layer): `attachment::tests::tamper_reorder_truncate_extend_swap_all_rejected` (hash checked first) |
| INV-ATT-3 | Resumed uploads/downloads produce byte-identical results | test with interruption at random offsets | 5 | **partial**: `attachment::tests::resumable_chunks_match_whole_file`; network resume: Phase 5 |
| **Data at rest** |||||
| INV-REST-1 | No plaintext message, key or contact data is written outside SQLCipher / the encrypted attachment store | test scans the data dir, temp dir and logs for known plaintext canaries after a scripted session | 2, 4 | planned |
| INV-REST-2 | Opening the vault needs **both** the passphrase-derived key and the OS-keystore secret | unit tests (each alone fails) | 2 | **tested** (key hierarchy): `vault::tests::create_unlock_and_both_factors_required`, `known_answer_unlock`, `rewrap_keeps_key_and_retires_old_passphrase`; OS keystore: Phase 4 |
| INV-REST-3 | Panic wipe leaves nothing decryptable: keystore entry gone, header gone, DB and attachments gone | test + manual Android check | 7 | planned |
| INV-REST-4 | Secrets are zeroized on drop/lock; no secret type implements `Debug`/`Display` revealing bytes | `zeroize` drop tests + compile-time checks + clippy lint | 2 | **partial**: `tests/secrets.rs` (3 tests), redaction tests per module. Known gap: libsignal's `IdentityKeyPair`/`PrivateKey` are `Copy` and not zeroized |
| INV-REST-5 | Notifications never contain sender or content | unit test on the notification builder + Android check | 7 | planned |
| **UI / IPC** |||||
| INV-UI-1 | Message text is rendered as text (no `dangerouslySetInnerHTML`, no `innerHTML`) | ESLint rule + XSS payload E2E test | 4 | planned |
| INV-UI-2 | CSP: no inline script, no `eval`, no remote origins; Trusted Types where supported | config test + CSP violation monitor in E2E | 4 | planned |
| INV-UI-3 | No IPC command returns key material or raw ciphertext; every input validated with size limits | IPC surface inventory test + fuzzing of command args | 4 | planned |
| INV-UI-4 | Link previews are off by default | settings test | 4 | planned |
| INV-UI-5 | Tauri capabilities grant no shell, fs or http plugin to the webview | capability file test | 4 | planned |
| **Robustness, logging, supply chain** |||||
| INV-ROB-1 | Relay and client never panic on untrusted input; bounded queues, timeouts, rate limits | fuzzing + load tests | 3 | planned |
| INV-STATE-1 | Rejected input never changes stored state: all store writes go through a transactional overlay committed only on success | store test + every negative session test re-checks the genuine message afterwards | 2 | **tested**: `store::tests::rollback_discards_and_commit_persists`, `every_bit_flip_rejected_and_state_unchanged` |
| INV-LOG-1 | Logs never contain plaintext, keys, tokens, mailbox IDs or sizes | log-capture test with canaries | 2–3 | planned |
| INV-SUP-1 | All deps exact-pinned with committed lockfiles; CI fails on lockfile drift | CI job | 2 | **tested**: CI `cargo metadata --locked` + `--locked` builds; all workspace deps `=`-pinned |
| INV-SUP-2 | `cargo deny` (licenses/advisories/bans/sources), `cargo audit`, `pnpm audit`, secret scan pass | CI job | 2 | **partial**: `cargo deny check` passes; `cargo audit` and gitleaks in CI; `pnpm audit` from Phase 4 |
| INV-SUP-3 | `cargo vet` passes, with documented audits for the libsignal/spqr git crates and libcrux | CI job + `supply-chain/` | 2 | planned |
| INV-SUP-4 | Releases ship SHA-256 checksums and link the exact source tag; signing keys never in repo | release workflow check | 8 | planned |
