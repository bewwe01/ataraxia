# Veil: code-reviewer gate reports

Saved verbatim, per CLAUDE.md "Process".

## Phase 2 review, round 1 (2026-10-16)

**Reviewer:** independent code-reviewer agent (adversarial gate)
**Scope:** `git diff 03bc316..HEAD -- crates/ Cargo.toml deny.toml .cargo supply-chain .github docs` (HEAD = `8d6bdf9`). All of `crates/core/src/*.rs`, `crates/core/tests/*`, `crates/core/fuzz/fuzz_targets/*`, `tests/vectors/gen.py`, `deny.toml`, `.cargo/audit.toml`, `.github/workflows/ci.yml`, and the Phase 2 parts of `PROTOCOL.md`, `THREAT_MODEL.md`, `INVARIANTS.md`, `TEST_REPORT.md` and `ARCHITECTURE.md` (ADR-0006). Binary corpus files were skipped.
**libsignal consulted:** `~/.cargo/git/checkouts/libsignal-2a193a9867decbc4/4beb029` (tag v0.105.0): `sealed_sender.rs`, `protocol.rs`, `ratchet.rs`, `fingerprint.rs`.

**Verdict: FAIL.** 3 High, 5 Medium, 8 Low. Nothing is Critical: no confidentiality or authentication break of the E2EE core was found. The High findings are a metadata leak that contradicts the threat model, a violated state invariant that the docs mark as tested, and a bypass of the relay-only filter.

---

### 1. Evidence re-run (real output)

All commands ran locally on 2026-10-16 in `/home/user/ataraxia`.

| Command | Result |
|---|---|
| `cargo fmt --all --check` | no output, exit 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | `Finished 'dev' profile [unoptimized + debuginfo] target(s) in 10.46s`, no warnings |
| `cargo test --workspace` | unit `59 passed; 0 failed`; `tests/secrets.rs` `3 passed`; `tests/session.rs` `14 passed`; doctests `0`. Total 76. **Matches TEST_REPORT.** |
| `cargo deny --locked check` | `advisories ok, bans ok, licenses ok, sources ok`, exit 0. Warnings: 8 × `duplicate` (getrandom, hashbrown, r-efi, rand, rand_core, shlex, syn, itertools ×3) and 3 × `license-not-encountered`. |
| `cargo audit --deny warnings` | `Loaded 1329 security advisories`, `Scanning Cargo.lock for vulnerabilities (203 crate dependencies)`, exit 0. One documented ignore (RUSTSEC-2026-0173). |
| `cargo vet --locked` | `Vetting Succeeded (36 fully audited, 2 partially audited, 159 exempted)` |
| `cargo +nightly-2026-10-01 fuzz run -O ice_sdp … -max_total_time=30` | `Done 1590883 runs in 31 second(s)`, cov 466 / ft 2059, 0 crashes |
| `… fuzz run -O account_open … -max_total_time=30` | `Done 1016823 runs in 31 second(s)`, cov 764 / ft 1631, 0 crashes |
| `… fuzz run -O content_decode … -max_total_time=30` | `Done 2132276 runs in 31 second(s)`, cov 1385 / ft 4293, 0 crashes |

Disclosure: the first `ice_sdp` run wrote about 475 new corpus files into `crates/core/fuzz/corpus/ice_sdp/`. I removed them with `git clean` (they were untracked) and confirmed `git status` was clean. The later runs used a corpus copy in the scratchpad.

`tests/vectors/gen.py` could not be re-run because `argon2-cffi` is not installed, so the KAT values were not independently regenerated.

**Probe tests.** I wrote a separate scratch crate outside the repo with a path dependency on `veil-core`, using only its public API plus public libsignal APIs. It confirmed findings H1, H2, H3, M1, M2, M3 and L1. Relevant output:

```
body    0 B -> envelope 4096 B, cleartext len field = 2397, trailing zero run = 1694
body  300 B -> envelope 4096 B, cleartext len field = 2653, trailing zero run = 1438
body  600 B -> envelope 4096 B, cleartext len field = 2909, trailing zero run = 1182

first open -> Some(Storage); backend ops applied before failure: ["del inv/", "del kpk/", "put peer/", "del pk/…"]
peer recorded after failed open: true
retry of the same envelope -> Err(AuthFailed)
alice's next message -> Some(AuthFailed)

filter_sdp(RelayOnly) output still contains:
  o=- 1 2 IN IP4 192.168.1.20
  c=IN IP4 192.168.1.20
  a=rtcp:54322 IN IP4 192.168.1.20
  a=Candidate:1 1 udp 2122260223 192.168.1.20 54321 typ host
  a=candidate:2 1 udp 1 198.51.100.7 3478 typ relay RADDR 192.168.1.20 RPORT 40000
filter_candidate(RelayOnly) keeps "typ relay" at 127.0.0.1, 192.168.1.1, 10.0.0.5, 169.254.169.254

Message { …, content: Content { …, body: Some(Text(Text { body: "TOP-SECRET-CANARY", … })) } }   // format!("{opened:?}")

v3 open -> Some(UnsupportedVersion)          // v3 SignalMessage built with the public SignalMessage::new(3, …)
mismatched cert -> Some(AuthFailed)          // cert for Alice, outer static key = Mallory, via sealed_sender_encrypt_from_usmc
tampered header accepted by decode: KdfParams { m_kib: 4194304, t: 64, p: 8 }
0 keys left with prefix "pk/" / "spk/" / "kpk/" / "inv/"   // after a redemption (deletion works; no repo test asserts it)
all 12 Content variants round-trip through decode_strict   // code is fine; INV-MSG-1 evidence is not
```

---

### 2. Findings

| # | Sev | Area | Location | Summary |
|---|---|---|---|---|
| H1 | **High** | Metadata | `crates/core/src/envelope.rs:3,18-30,33-54`; PROTOCOL §6.1 step 4 | The envelope's `len` field is in **cleartext**, so the relay learns the exact sealed size (256-byte content granularity plus message type), not just the bucket |
| H2 | **High** | State (INV-STATE-1) | `store.rs:29-35,151-160`; `account.rs:196-213` | `commit` is not atomic: a backend error part-way through leaves a torn state, so input that was rejected still changed storage. Shown: the invite is consumed, the peer recorded, no session exists, and the contact is permanently broken |
| H3 | **High** | ICE (INV-NET-1) | `ice.rs:131-155,46-50,72-89` | `filter_sdp` sanitises only lines that start exactly `a=candidate:`. `c=`, `o=` and `a=rtcp:` lines, `a=Candidate:`, and `RADDR`/`RPORT` pass verbatim with private IPs in relay-only mode |
| M1 | Medium | ICE (incoming) | `ice.rs:63-66` | In relay-only mode, any candidate labelled `typ relay` is accepted whatever its address: loopback, RFC 1918, 169.254.169.254, `.local` |
| M2 | Medium | Secret hygiene | `content.rs:34-232` (prost derives), `account.rs:65,80`, `invite.rs:91` | `prost::Message` derives `Debug`, so `Opened`/`Content` print plaintext, attachment keys, delivery tokens, invite proofs and re-key links (which hold invite secrets). `InviteRecordPb.proof_key` is printable and not zeroized |
| M3 | Medium | Claims vs tests | INVARIANTS INV-CRY-3, INV-MSG-6; TEST_REPORT "Known limits"; ADR-0006 | Both are marked "argument only" because "libsignal cannot produce" the inputs. That is false: both inputs were built with public APIs in about 20 lines each. ADR-0006 requires a test |
| M4 | Medium | Claims vs tests | `tests/session.rs:155-180`; INVARIANTS INV-STATE-1, INV-MSG-2 | The bit-flip test never reaches a state-mutating path: every flip dies at unframe or the sealed-sender MAC before any write. Rollback after a *successful* decrypt (bad proof, wrong invite id, expired re-key invite, invalid content) is untested |
| M5 | Medium | Fuzzing claims | `fuzz/fuzz_targets/account_open.rs`; INVARIANTS INV-MSG-5 | `account_open` cannot get past the sealed-sender HMAC, so libsignal/SPQR parsing of authenticated-but-hostile input from a contact is never fuzzed. The ≥ 1 h requirement is unmet, yet the status is "tested" |
| L1 | Low | Vault / DoS | `vault.rs:78-85` | `validate_for_open` accepts m = 4 GiB, t = 64, p = 8 before authentication, which means OOM, an abort, a 32-bit capacity-overflow panic, or hours of CPU |
| L2 | Low | ICE (Direct) | `ice.rs:95-127` | `is_public` treats IPv4-compatible `::a.b.c.d`, NAT64 `64:ff9b::/96`, 6to4 `2002::/16` (embedding private v4), and site-local `fec0::/10` as public |
| L3 | Low | DTLS (INV-NET-4) | `ice.rs:172-181` | Conflicting `a=setup` values across m-sections are accepted, but INV-NET-4 says "inconsistent `a=setup` is rejected" |
| L4 | Low | Nonce discipline | `attachment.rs:156-175`; INV-CRY-5 | The public `encrypt_chunk(key, index, …)` lets a resumed upload re-encrypt *changed* plaintext under the same (key, prefix, index), which is XChaCha nonce reuse. The 1e6 test only shows OsRng doesn't repeat |
| L5 | Low | Sealed sender version | `account.rs:460` | `sealed_sender_decrypt_to_usmc` also accepts **v2** (multi-recipient), while the spec and ADR-0006 say v1 only |
| L6 | Low | Fragile error path | `account.rs:622-632` | `delete_invite` silently skips deletion if the `RefCell` borrow fails, and the transaction would still commit, so the invite would not be consumed |
| L7 | Low | Weak tests / overclaims | several, see details | INV-MSG-1 (only `Text` tested), INV-MSG-7 (no self-send or receiver-side test), INV-PAIR-1, INV-CRY-4, INV-ID-3 KAT, attachment KAT, fuzz/proptest oracles |
| L8 | Low | CI | `.github/workflows/ci.yml:62-67,85-88` | The fuzz job builds without `--locked`; the gitleaks checksum comes from the same release (no pinned hash); fuzz crash artifacts are not uploaded |

---

### 3. Details

#### H1. Cleartext length field defeats the size buckets. [HIGH confidence]

- **Where:** `envelope.rs:25-26` writes `len (u32 BE)` before the sealed bytes, unencrypted. The relay receives `Deposit { envelope }` as is (PROTOCOL §6.3).
- **What the relay learns:** bytes 1..5 of every envelope give the exact sealed-sender length. Even without them, the run of trailing `0x00` padding gives the length to within a byte or two.
  - Content is padded to 256-byte blocks only, so the relay learns the plaintext length to 256 B.
  - It can tell `PreKey` from `Whisper` messages: about 1.6 KB of ML-KEM ciphertext, so every first message sits around 2.4 KB.
  - Probe: bodies of 0, 300 and 600 bytes all produce 4096-byte envelopes, but the header reads 2397, 2653 and 2909.
- **Contradicts:** THREAT_MODEL §5 table, "Relay learns message sizes: **Bucket only (1/4/16/64 KiB)**", and the purpose of INV-META-3. `sizes_are_buckets` checks only the outer length, so it cannot see this.
- **Fix:**
  - Make the sealed payload *exactly* fill the bucket. Compute the sealed-sender overhead for this message type and certificate, pad the plaintext `Content` (inside the encryption) to `bucket − HEADER − overhead`, then assert `sealed.len() == bucket − HEADER`. Then drop `len` and the zero padding entirely, or keep `len` as a constant per bucket.
  - Add a test that the first 5 bytes and the length of the zero tail are identical across different message sizes in the same bucket, for both `PreKey` and `Whisper` messages.

#### H2. Non-atomic commit breaks INV-STATE-1. [HIGH confidence, reproduced]

- **Where:** `VeilStore::commit` (`store.rs:151-160`) does `core::mem::take(&mut self.overlay)`, then applies `put`/`delete` one key at a time to the backend. The first error returns with earlier writes already applied and the overlay gone; `transact`'s `rollback()` (`account.rs:204`) then clears an empty overlay.
  - `KvBackend` (`store.rs:29-35`) has no batch or transaction primitive, so the coming SQLCipher backend inherits this. `SQLITE_BUSY`, `SQLITE_FULL` and I/O errors are ordinary events on mobile.
- **Reproduced:** a backend that fails `put("sess/…")`, used during invite redemption. The keys are applied in BTreeMap order: `del inv/`, `del kpk/`, `put peer/`, `del pk/`, then failure.
  - `open` returns `Err(Storage)`, but the invite and its one-time keys are consumed and the peer identity is recorded with no session.
  - A retry of the same envelope now fails (`AuthFailed`), as does every later message from the redeemer. The app never received `NewContact`.
  - So input that was rejected changed stored state, which is exactly what INV-STATE-1 forbids. INVARIANTS marks it **tested**.
- **Fix:**
  - Add `fn apply_batch(&mut self, ops: &[(Vec<u8>, Option<&[u8]>)]) -> Result<()>` to `KvBackend`, with a documented all-or-nothing contract (one SQL transaction).
  - Make `commit` call it once and restore the overlay on error, so `rollback` actually discards it.
  - Add a failing-backend test (like the probe) asserting the backend is byte-identical after a failed commit, and that the envelope can be retried.

#### H3. Relay-only SDP filter passes address-bearing lines. [HIGH confidence for the filter behaviour; MEDIUM that a given webview fills these lines with host IPs]

- **Where:**
  - `filter_sdp` (`ice.rs:141-152`) treats only lines that `starts_with("a=candidate:")` (case-sensitive) as candidates. Every other line is copied verbatim, with only a control-character check.
  - `filter_candidate` zeroes only lowercase `raddr`/`rport` tokens (`ice.rs:75-86`).
- **Bypass (probe output above).** In `Mode::RelayOnly`, these all reach the peer unchanged:
  - `c=IN IP4 <ip>` (libwebrtc writes the default candidate's address here);
  - `a=rtcp:<port> IN IP4 <ip>`;
  - `o=… IN IP4 <ip>`;
  - `a=Candidate:… typ host` (a literal non-relay candidate);
  - `typ relay … RADDR <ip> RPORT <port>`.
- **Why it matters:** the attacker is the *peer*, a contact running a modified client. They read the SDP text, so their own stack doesn't need to parse these lines.
  - The filter exists precisely because "the Android WebView gathers host candidates … Never rely on the webview to hide addresses" (SPIKES §C.2). In exactly that case, `c=` and `a=rtcp:` carry the host or srflx address.
  - CLAUDE.md non-negotiable 4 and INV-NET-1 are therefore not enforced by the Rust filter as claimed.
  - The fuzz oracle (`ice_sdp.rs`) and the proptest check only lowercase `a=candidate:` lines, so they could not find this.
- **Note for Phase 6:** no SDP filter can stop the webview from sending STUN checks from host candidates. Only the transport policy can. PROTOCOL §8's "Independently, Rust filters…" overstates the independence; say so.
- **Fix:**
  - In relay-only mode, rebuild the SDP from an allowlist:
    - drop every `a=candidate`/`candidate` line, case-insensitively, whose parsed type ≠ `relay`;
    - rebuild kept candidates from parsed fields, with no pass-through of extension tokens other than an allowlist (`generation`, `ufrag`, `network-id`, `network-cost`, `tcptype`), and with `raddr 0.0.0.0 rport 0`;
    - rewrite `c=` to `IN IP4 0.0.0.0`, `a=rtcp:` to `9 IN IP4 0.0.0.0` and `o=` to `127.0.0.1`;
    - reject any other line containing an IP literal.
  - Change the property test and fuzz oracle to: "no IPv4/IPv6 literal other than kept relay addresses and `0.0.0.0`/`127.0.0.1` appears anywhere in the output".

#### M1. Incoming relay-labelled candidates are not address-checked. [HIGH]

- `(Mode::RelayOnly, "relay") => true` (`ice.rs:64`) ignores the address. A malicious peer can label any address `typ relay`: `127.0.0.1:<port>`, `192.168.1.1`, `169.254.169.254`, or `x.local`, which triggers mDNS on the victim's LAN.
- The victim's stack then probes those addresses. That is LAN/localhost probing and, if the webview ignores the relay policy (see H3), a direct IP disclosure to an attacker-chosen host.
- INV-NET-1 says "incoming ones are dropped"; a peer bypasses that with one word.
- **Fix:** in relay-only mode, also require `is_public(address)` for relay candidates (a TURN allocation is never loopback, link-local or mDNS). Ideally, also require the address to be one of the peer's known TURN server addresses. Add these cases to the tests.

#### M2. `Debug` on content types leaks plaintext and secrets. [HIGH, reproduced]

- `#[derive(prost::Message)]` generates `impl Debug` unless `#[prost(skip_debug)]` is set (prost-derive 0.14.4, lib.rs:211-236). As a result:
  - `Opened` (`account.rs:65`, `#[derive(Debug)]`) prints message text. Probe: `format!("{opened:?}")` printed `"TOP-SECRET-CANARY"`.
  - `Attachment.key`, `ContactIntro.delivery_token` and `invite_proof`, `RekeyInvite.link` (a full invite including its secret), `MailboxUpdate.new_delivery_token`, `PackagePb.delivery_token` and `InviteRecordPb.proof_key` are all printable.
- One `tracing::debug!(?opened)` in Phase 3/4 would violate non-negotiable 6 and the "no `Debug` on secret types" rule.
- `InviteRecordPb.proof_key` (`account.rs:91`) and the `Vec`s in decoded `Content` are also not zeroized on drop.
- **Fix:**
  - Add `#[prost(skip_debug)]` to every content and record message, with a manual redacting `Debug` (type and lengths only), and remove `Debug` from `Opened` or redact it.
  - Wrap `proof_key` and the attachment key in `Zeroizing`, or convert them to fixed arrays inside a zeroizing newtype right after decoding.
  - Extend `tests/secrets.rs` with a canary-in-`Debug` test for `Opened`, `Content`, `ContactIntro` and `Attachment`.

#### M3. "Argument only" claims rest on a false premise. [HIGH, reproduced]

- **What the docs say:** INVARIANTS (INV-CRY-3, INV-MSG-6) and TEST_REPORT ("libsignal cannot produce a v3 message", "no API to forge a certificate under a foreign key").
- **What the API allows:** `SignalMessage::new(3, …)` and `PreKeySignalMessage::new(3, …, None, …)` are public (`protocol.rs:79,341`). So are `UnidentifiedSenderMessageContent::new` and `sealed_sender_encrypt_from_usmc` (`sealed_sender.rs:558,973`). With a custom `IdentityKeyStore`, the outer static key can be any key while the certificate names another.
- **Probe results:**
  - A sealed v3 `Whisper` from a real contact gives `UnsupportedVersion`.
  - A certificate for Alice under Mallory's outer key gives `AuthFailed`.
  - So the code is correct, but the evidence the ADR requires (ADR-0006: "A Phase 2 test suite must confirm it (INV-MSG-6/7)") was not delivered, and the stated reason is wrong.
- **Fix:**
  - Add these tests to `tests/session.rs`, and also: a v3 `PreKey` message without a Kyber payload; a PreKey message from an unknown sender with a valid certificate but no invite; and a certificate whose `sender_uuid` or device does not match.
  - Move INV-CRY-3 and INV-MSG-6 to **tested** and correct TEST_REPORT.

#### M4. INV-STATE-1 / INV-MSG-2 evidence never exercises rollback. [HIGH]

- **The test:** `every_bit_flip_rejected_and_state_unchanged` flips bits in an envelope from an existing contact.
  - Each flip is rejected by `unframe` (padding or length checks) or by the sealed-sender v1 HMACs. Both run before `transact` or any store write.
  - The snapshot comparison is therefore trivially true; it would pass even if `rollback()` were a no-op.
- **What is untested:** the paths where state *is* written and must then be discarded. These are a failed `verify_proof` (`account.rs:531`), a mismatched `invite_id` (`:527`), a non-`ContactIntro` first message (`:524-526`), `consume_invite_if_proven` failing for a known contact (`:501`, `:614-617`), and `Content::decode_strict` failing after a successful `message_decrypt`. INV-PAIR-4's "relay-forgery test" is also missing at account level.
- **Fix:**
  - Build these envelopes from inside the crate (a `#[cfg(test)]` helper that seals arbitrary `Content` or a tampered proof) and assert, for each: backend unchanged, no pending overlay, and the genuine next message still opens.
  - Add the failing-backend test from H2.

#### M5. Fuzzing does not reach the hostile-contact surface. [HIGH]

- **What the target reaches:** `account_open` fuzzes an account with no contacts and no invites. Random bytes cannot pass the sealed-sender ephemeral HMAC, so coverage stops there; the fuzz run gave cov 764 against 1385 for `content_decode`.
- **What is not fuzzed:** the threat model's "Malformed message from a contact" row. A contact holds valid session keys, so they can send MAC-valid `SignalMessage`s and `PreKeySignalMessage`s with arbitrary `pq_ratchet` (SPQR) bytes, counters and Kyber ciphertexts. libsignal and spqr parse those bytes, and that code contains `expect`/`unreachable!`. Nothing fuzzes it.
- **Runtime:** the ≥ 1 h runs in INV-MSG-5's "How it is proven" don't exist (3 min locally, 60 s in CI), yet the status is **tested**.
- **Fix:**
  - Add a structure-aware target: a fixed paired account with a known session, where the fuzzer mutates the *inner* `SignalMessage`/`PreKeySignalMessage` fields, re-MACs with the sender's session, and re-seals.
  - Set the status to **partial** until the nightly ≥ 1 h job exists.

#### L1. Vault-header KDF bounds allow resource exhaustion. [HIGH for the behaviour, LOW exploitability]

- `validate_for_open` allows `m_kib ≤ 4 GiB`, `t ≤ 64`, `p ≤ 8`. Probe: a tampered header with `4194304/64/8` decodes fine.
- `unlock` then runs Argon2 *before* the AEAD can reject the header. Results: a 4 GiB allocation (an OOM kill on Android; a `capacity overflow` panic on 32-bit `armv7`, which breaks non-negotiable 7), or hours of CPU. This needs local write access to the header.
- **Fix:** bound open-time parameters to what Veil ever creates, e.g. `m ≤ 1 GiB`, `t ≤ 10`, `p ≤ 4`. Better, also check them against the device class's configured maximum, and test both bounds.

#### L2. Direct-mode address classification gaps.

- `is_public_v6` lacks IPv4-compatible `::/96`, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`, Teredo `2001::/32` and deprecated site-local `fec0::/10`. 6to4 and NAT64 embed an IPv4 address that should be classified with `is_public_v4`.
- **Fix:** extract embedded IPv4 for those prefixes and classify it, reject `fec0::/10`, and add the cases to `direct_drops_private_and_mdns`.

#### L3. `a=setup` consistency not enforced.

- `validate_dtls` checks each `a=setup` against the role, but accepts `active` in one m-section and `passive` in another. INV-NET-4's wording ("inconsistent `a=setup` … rejected") is stronger than the code.
- **Fix:** require all `a=setup` values to be equal, and add a test.

#### L4. Chunk API invites nonce reuse.

- `encrypt_chunk` is `pub` and takes `(key, index)` freely. A resumable upload that re-reads a file changed on disk and re-encrypts chunk *i* reuses the XChaCha20-Poly1305 nonce under the same key, which breaks confidentiality of that chunk and allows Poly1305 forgery.
- `keys_and_nonce_prefixes_unique` (1e6 draws from OsRng) does not test this risk.
- **Fix:** expose an `Encryptor` that owns the key and yields each index once, or document and enforce (by API shape) that resume re-sends stored *ciphertext* and never re-encrypts.

#### L5. Sealed-sender v2 is accepted.

- `sealed_sender_decrypt_to_usmc` handles both V1 and V2 (`sealed_sender.rs:1860-1960`). Its V2 binding via the authentication tag is sound, but it widens the parser surface and contradicts "sealed sender v1" in PROTOCOL §6 and ADR-0006.
- **Fix:** before calling it, reject a sealed payload whose first byte is not the v1 version byte (`0x11`), and add a test.

#### L6. `delete_invite` swallows a failure.

- `if let Ok(mut s) = self.store.try_borrow_mut()` (`account.rs:623`): on a borrow failure the invite and its prekeys are silently kept, while the surrounding transaction commits and returns `NewContact`. That breaks single use. It is unreachable today but fragile.
- **Fix:** return `Result<()>` and propagate the error.

#### L7. Weak tests and claim mismatches. [HIGH]

- **INV-MSG-1** ("every `Content` type") is **tested**, but only `Text` (plus `ContactIntro` implicitly) is round-tripped. My probe shows all 12 variants round-trip, so add a proptest over every variant.
- **INV-MSG-7:** `unknown_and_self_senders_refused` asserts a *sender-side* `NoSession` and an undecryptable envelope. It tests neither self-send rejection (`account.rs:473`) nor receiver-side `UnknownSender` for a valid but uninvited sender. The `revoke_invite` path covers part of this.
- **INV-PAIR-1:** `bundle_must_match_invite_identity` fails because Mallory's package is under a different *key*, so it would pass even without the AAD binding. The explicit `ik != invite.identity` check (`account.rs:334`) is never exercised.
- **INV-CRY-4:** `invite_is_single_use` never asserts that `pk/`, `spk/` and `kpk/` are deleted. The probe shows they are, so add the assertion.
- **INV-ID-3** lists "known-answer vectors"; there is no safety-number KAT.
- The attachment KAT is a single chunk with counter 0 and `last = 1`. It never tests the BE32 counter or the non-last flag.
- KATs live in `src/test_vectors.rs`, not under `tests/vectors/` (CLAUDE.md), and `gen.py` is not run in CI.
- The ICE proptest and fuzz oracles check only `contains(" typ relay")` on lowercase lines (see H3).

#### L8. CI details.

- **Fuzz job:** `cargo fuzz run` without `--locked`, so `fuzz/Cargo.lock` can drift silently. Crash artifacts are not uploaded (`actions/upload-artifact`, pinned).
- **gitleaks:** the checksum file comes from the same GitHub release as the tarball, so it guards against corruption but not a compromised release. Pin the expected SHA-256 in the workflow.
- **What is in order:** all actions are pinned by full SHA, `permissions: contents: read` is set, and `persist-credentials: false` is used on every checkout. I found nothing that lets the main jobs pass with checks skipped.

---

### 4. Invariant status corrections required

| ID | Claimed | Should be | Reason |
|---|---|---|---|
| INV-STATE-1 | tested | **failing** | H2 (reproduced), M4 |
| INV-NET-1 (core) | partial (filter tested) | **failing** | H3, M1 |
| INV-META-3 | partial | **failing** (core part) | H1: the length leaks in cleartext |
| INV-MSG-5 | tested (core decoders) | partial | M5 |
| INV-MSG-1 | tested | partial | L7 |
| INV-CRY-3, INV-MSG-6 | partial / argument only | tests are feasible; add them | M3 |
| INV-REST-4 | partial | partial; add the content-type `Debug` gap | M2 |
| INV-NET-4 | partial | partial; the `a=setup` consistency claim is not enforced | L3 |

---

### 5. What is done well

- **Identity policy:**
  - `is_trusted_identity` is exact-match only, and `save_identity` refuses to record or overwrite (`store.rs:222-248`). New contacts are recorded only tentatively inside a transaction, after the invite gate.
  - The certificate checks in `open` (`account.rs:467-475`) bind `sender_uuid` to `Address::of(key)` and device 1, use the sender's key as trust root, and reject self-sends.
  - I confirmed in libsignal that v1 unseal compares the certificate key with the static key using `ct_eq`, and that SPQR is mandatory (`min_version: V1`, `ratchet.rs:87`).
- **Downgrade checks:** `message_version < 4` and Kyber-less PreKey messages are rejected before decrypt. The probe confirmed v3 is rejected.
- **Invite cryptography:**
  - HKDF uses separate `info` labels for package key and proof key.
  - The AEAD AAD binds the id and the inviter's identity key.
  - The package has a fixed size of 4136 B and is checked for canonical form.
  - `verify_slice` checks the full length and compares in constant time (digest 0.11.3, `mac.rs:139-146`).
  - Only `k_proof` is stored, not the secret.
- **Strict decoding:** size limits come before parsing, `Content`/`PackagePb` must re-encode canonically, the invite link has an exact layout, and the vault header has an exact length and authenticated Argon2 parameters.
- **Attachments:** the ciphertext hash is checked in constant time before AEAD, STREAM uses the last-chunk flag, and size and padded size are cross-checked. The Padmé implementation matches the paper's formula; I checked it by hand.
- **Lints and tooling:** `unwrap`/`expect`/indexing/`as`/arithmetic are denied in non-test code and clippy is clean. All TEST_REPORT numbers reproduce exactly. Supply-chain tooling is wired into CI with documented, review-dated ignores.

---

### 6. Required for round 2

1. Fix H1, H2 and H3, each with a test that fails on the current code:
   - H1: a header/tail-length invariance test;
   - H2: a failing-backend test;
   - H3: an "IP literal anywhere" oracle in both the proptest and the `ice_sdp` fuzz target.
2. Fix M1 and M2, and add the tests from M3, M4 and M5. Update INVARIANTS and TEST_REPORT per §4.
3. Address or explicitly defer (with a phase) L1 to L8.

VERDICT: FAIL
