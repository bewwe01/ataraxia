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

---

## Phase 2 review, round 2 (2026-10-19)

**Reviewer:** independent code-reviewer agent (adversarial gate), round 2.
**Scope:** `git diff 32f8b16..HEAD` (HEAD = `09a2963`, 8 commits: `3e95085` H1/L5, `4c47566` H2/L6, `86bf928` H3/M1/L2/L3, `32c907c` M2/M3, `6975947` M4, `f4521a4` M5/L1/L4/L7/L8, `2c72705` inout bump, `09a2963` docs). I also re-read all of `crates/core/` (src, tests, fuzz targets, vectors), `Cargo.toml`, `deny.toml`, `.cargo/audit.toml`, `supply-chain/`, `.github/workflows/`, and the Phase 2 parts of the docs. Binary corpus files were skipped.
**libsignal consulted:** `~/.cargo/git/checkouts/libsignal-2a193a9867decbc4/4beb029`: `sealed_sender.rs` (`UnidentifiedSenderMessageContent::new`, `sealed_sender_encrypt_from_usmc`), `protocol.rs`, `consts.rs`, `triple_ratchet.rs`, and `rust/crypto/src/aes_cbc.rs`.

**Verdict: PASS WITH CONDITIONS.** All 3 High findings from round 1 are fixed, and I re-verified each with my own probes. No new Critical or High was found. One new Medium is open (N1: the `contact_plaintext` fuzz target cannot reach the code it claims to fuzz). M2, M4, M5 and L7 are only partially fixed. There are 7 new Low findings.

### 1. Evidence re-run (real output, 2026-10-19)

| Command | Result |
|---|---|
| `cargo fmt --all --check` | no output, exit 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | `Finished 'dev' profile … in 4.41s`, exit 0, no warnings |
| `cargo test --workspace --locked` | unit `72 passed`; `tests/secrets.rs` `3 passed`; `tests/session.rs` `21 passed`; doctests `0`. **96 in total, which matches TEST_REPORT.** |
| `cargo deny --locked check` | `advisories ok, bans ok, licenses ok, sources ok`, exit 0. Warnings: 8 × `duplicate` and the `license-not-encountered` notes (CC0-1.0, CDLA-Permissive-2.0, …). |
| `cargo audit --deny warnings` | `Loaded 1338 security advisories`, `Scanning Cargo.lock for vulnerabilities (203 crate dependencies)`, exit 0. One documented ignore (RUSTSEC-2026-0173). |
| `cargo vet --locked` | `Vetting Succeeded (36 fully audited, 3 partially audited, 158 exempted)`, exit 0 |
| `RUSTFLAGS="--cfg fuzzing" cargo clippy -p veil-core --locked -- -D warnings` (scratch copy, scratch target) | clean. CI never lints the fuzz-only hooks, so I checked them here. |

**Fuzzing.** `cargo +nightly-2026-10-01 fuzz run -O <t> <scratch copy of corpus/t> -- -max_total_time=60 -max_len=70000 -rss_limit_mb=2048`, with corpora copied to the scratchpad and the artifact prefix pointed there:

| Target | Runs / 61 s | Final cov / ft | `lim` | Crashes |
|---|---|---|---|---|
| ice_sdp | 1,537,215 | 962 / 4694 | 3918 | 0 |
| contact_inner | 18,320 | 8391 / 10729 | 427 | 0 |
| contact_plaintext | 2,961 | 4302 / 6147 | **40** | 0 |
| envelope_unframe | 28,085,913 | 33 / 34 | 70000 | 0 |

`git status` was clean after every run.

**Oracle and vectors.** I ran `pyenv/bin/python3 -I crates/core/tests/vectors/gen.py` with argon2-cffi. Its output differs from the committed `tests/vectors/vectors.rs` only in line wrapping; after `rustfmt --edition 2024` the two are **byte-identical**. Its built-in self-tests passed: libsignal's published fingerprint `300354…079131` and the HChaCha20 draft vector.

**Supply chain checks.**
- gitleaks: the SHA-256 pinned in `ci.yml`, `551f6fc8…70eb`, equals the entry in the release's `gitleaks_8.30.1_checksums.txt`, which I fetched.
- inout: I diffed the `inout` 0.2.3 → 0.2.4 sources myself; see N6.

**Probe crate.** I wrote a scratch crate outside the repo with a path dependency on an unmodified copy of HEAD, built with `--cfg fuzzing` so it can reach `fuzz_seal_inner`, plus mutation runs on a second scratch copy:

```
# H1: seal_to_bucket over every inner Whisper length 0..65600 (one call each)
len 0 -> bucket 1024 | len 653 -> 4096 | len 3725 -> 16384 | len 16013 -> 65536 | len >= 65163 -> ERR TooLarge
done: errors only at len >= 65163 (437 = 65600-65163), mean 846 us, worst 6.4 ms per seal

# Max-size valid content
validate(Text 63488 = MAX_BODY_LEN) = true
alice (PreKey phase) seal: Err(TooLarge)      bob (Whisper) seal: Ok(65536)

# Mutation: transact() commits instead of rolling back on error
rollback_tests::* -> 2 FAILED            tests/session.rs -> 21 passed (no other test notices)
# Mutation: remove `if ik != invite.identity` (account.rs:546)
pairing_tests::package_with_swapped_identity_or_signature_refused -> ok ; bundle_must_match_invite_identity -> ok
# Mutation: accept sealed-sender byte by high nibble only (libsignal's own rule)
every_bit_flip_rejected_and_state_unchanged -> FAILED
# Mutation: (RelayOnly, "relay") => true
relay_candidates_must_be_public, relay_only_never_emits_non_relay, relay_only_sdp_never_leaks -> FAILED

# H3: real browser SDPs, relay-only offer
Firefox audio+video offer (68 lines) -> OK, 67 kept (host candidate dropped)
Chrome video offer with VP8/VP9/AV1/H265/H264, rid, simulcast (45 lines) -> OK, 45 kept
"a=ssrc:1 cname:3232235796" / "cname:0xC0A80114" / "cname:abcd1234.local" -> passed through (no dot or colon)
"candidate:1 +1 udp 1 8.8.4.4 9 typ relay generation +7" -> "... 1 +1 udp ... generation +7" (not canonical)
"a=candidate:1 1 udp 1 ::ffff:0:10.0.0.1 9 typ relay" -> kept as public
"a=candidate:1 1 udp 1 abc.local 9 typ host", Direct { allow_lan: true } -> None
```

Not re-run: Miri (TEST_REPORT: 31 passed), and fuzz targets `account_open`, `content_decode`, `invite_link` and `vault_header`.

### 2. Status of the round-1 findings

| # | Status | Evidence |
|---|---|---|
| **H1** cleartext length | **FIXED** | Framing v2 is `0x02 ‖ sealed`, with no length field and no outer padding (`envelope.rs`). `unframe` is strict: exact bucket and version 2. `seal_to_bucket` (`account.rs:471`) always terminates, with at most 1 + 4 × 2 × 8 seals. **My exhaustive scan of every inner length found no gap below the 64 KiB cap.** The filler sits inside the sealed-sender AES-CTR/HMAC layer, which is deterministic in length. The relay-visible outer protobuf lengths are therefore constant per bucket, which `relay_learns_only_the_bucket` checks across PreKey and Whisper messages. On receipt, `groupId` and `contentHint` are ignored, so a contact gains nothing they could not already send as content. Residuals: the PreKey→4 KiB leak is documented; the missing ADR is under N4; the capacity mismatch is N7. |
| **H2** non-atomic commit | **FIXED** | `KvBackend` now has only `get`, `keys_with_prefix` and `apply(batch)`. **No write path bypasses the batch:** `VeilStore::put`/`delete` write to the overlay, `commit` makes one `apply` call and keeps the overlay on error, and `Account::create` writes through `apply`. `failed_commit_changes_nothing_and_retry_succeeds` checks a byte-identical backend, a successful retry and one batch per transaction. Note: atomicity now depends entirely on each backend's `apply`. Ship a reusable backend-conformance test with the SQLCipher backend in Phase 4. |
| **H3** SDP leaks | **FIXED** | `filter_sdp` is now an allowlist:<br>• `o=`, `c=` and `m=` are rebuilt;<br>• unknown `a=`, `i=`, `u=`, `e=` and other lines are dropped;<br>• candidates are re-serialised from parsed fields;<br>• bare LF and CR are refused as control characters;<br>• non-ASCII is refused;<br>• attribute names are case-folded before both the allowlist and the DTLS checks.<br>None of my bypass attempts got through: CRLF/LF, odd casing, whitespace in attribute names, zone ids, brackets, hostnames, leading-zero/octal and `0x` dotted IPv4, IPs glued to text, the `m=` tail, `a=rtcp`, `a=remote-candidates` and `RADDR`. Real Firefox and Chrome SDPs pass, so I found no false positive that breaks a normal call. Residuals (docs, nits): N4 and §4. |
| **M1** relay candidates unchecked | **FIXED** | `(RelayOnly, "relay") => is_public_ip(ip)`. Mutation-verified: three tests fail when the check is removed. |
| **M2** Debug leaks | **PARTIALLY FIXED** | Every prost type has `skip_debug` plus `redacted_debug!`, `Opened`'s Debug is redacted through `Content`, and `InviteRecordPb` zeroizes `proof_key` on drop. Not done (N5): the attachment key, delivery tokens, invite proofs and re-key links in decoded `Content` are plain `Vec`s that are never zeroized, and INV-REST-4 does not list this as a known gap. |
| **M3** argument-only claims | **FIXED** | `downgraded_messages_refused` (a v3 Whisper from a real contact gives `UnsupportedVersion`; a PreKey without Kyber is built and refused), `certificate_key_must_match_sealing_key` (foreign sealing key, wrong root, wrong name) and `strangers_and_self_addressed_envelopes_dropped`. Still missing, but minor: a v3 *PreKey* message and a certificate with a device id other than 1. |
| **M4** rollback untested | **PARTIALLY FIXED** | `rollback_tests::*` cover decrypt-then-refuse for new-contact intros and for undecodable content from a known contact. **I reproduced the author's mutation check: both tests fail when `transact` commits on error.** Still untested (N3): the known-contact `consume_invite_if_proven` path (`account.rs:739`), which round 1 named explicitly. |
| **M5** fuzz depth | **PARTIALLY FIXED** | `contact_inner` really does act as an authenticated contact: cov 8391 against 794 for `account_open`, reaching libsignal parsing and SPQR before the MAC check. `contact_plaintext` **cannot** reach content handling (N1). The `cfg(fuzzing)` hooks cannot enter a normal build: the cfg is set only by `cargo fuzz` (`RUSTFLAGS`), and dependents cannot set it. I found no dependency whose behaviour changes under `cfg(fuzzing)`; libsignal, spqr and the RustCrypto crates have no such code. The INV-MSG-5 status of **partial** is honest about the missing 1 h runs. |
| **L1** KDF cost | **FIXED** | `CEILING` (512 MiB, t = 8, p = 4) is checked in `decode` before Argon2 runs; tested, including timing. Residual: a tampered header can still ask a phone running the 64 MiB preset for 512 MiB × 8 passes, about 8× its normal unlock cost. That is acceptable; a per-device cap is optional. |
| **L2** IPv6 classes | **FIXED** | v4-compatible, NAT64, 6to4, Teredo and `fec0::/10` are now covered. Nit: the IPv4-translated `::ffff:0:a.b.c.d` form is still treated as public; it is not exploitable. |
| **L3** `a=setup` consistency | **FIXED** | `dtls_validation` now includes mixed `a=setup` roles. |
| **L4** chunk nonce reuse | **FIXED** | `encrypt_chunk` is private, and `encrypt` draws a fresh key and prefix on every call. |
| **L5** sealed sender v2 | **FIXED** | The first sealed byte must be exactly `0x11` (`account.rs` `open`). Mutation-verified: the bit-flip test fails at byte 1 (0x13) when only the high nibble is checked. |
| **L6** silent delete | **FIXED** | `delete_invite` propagates the borrow error. |
| **L7** weak tests | **PARTIALLY FIXED** | Now covered:<br>• all 12 `Body` and 5 `CallKind` variants round-trip;<br>• strangers and self-sends are refused on the receiver side;<br>• one-time prekeys are deleted;<br>• safety-number KAT, reproduced by me;<br>• multi-chunk attachment KAT, reproduced by me;<br>• vectors moved to `tests/vectors/`.<br>Not fixed:<br>• the INV-PAIR-1 test still does not isolate the identity check (N2; mutation-verified);<br>• `gen.py` is not run in CI;<br>• the ICE proptest oracle reuses the code under test (N9). |
| **L8** CI | **FIXED** | gitleaks hash pinned and checked by me; fuzz lockfile checked with `cargo metadata --locked`; crash inputs printed as hex; nightly 1 h workflow added. Both workflows pin actions by SHA, set `permissions: contents: read`, and use `persist-credentials: false`. The nightly has no recorded run yet, which the docs disclose. |

### 3. New findings

| # | Sev | Area | Location | Summary |
|---|---|---|---|---|
| N1 | **Medium** | Fuzzing claims (INV-MSG-5) | `fuzz/fuzz_targets/contact_plaintext.rs`; `account.rs:838`; INVARIANTS INV-MSG-5; TEST_REPORT | `contact_plaintext` passes raw fuzz bytes as already-padded plaintext. `unpad_block` rejects any length that is not a multiple of 256, and the committed corpus maxes out at 40 bytes, so **no input ever reaches content decoding, validation, invite-proof handling or the post-decrypt transaction logic it claims to fuzz** |
| N2 | Low | Weak test (INV-PAIR-1) | `account.rs` `pairing_tests`, `tests/session.rs:423`; INVARIANTS INV-PAIR-1 | With `if ik != invite.identity` (`account.rs:546`) **removed**, both INV-PAIR-1 tests still pass: libsignal's signature check under the swapped key rejects the bundle first |
| N3 | Low | Untested rollback path (M4 residual) | `account.rs:739` `consume_invite_if_proven` | No test of a known contact redeeming a re-key invite: neither success (invite and prekeys consumed) nor refusal (bad proof or expired → state unchanged) |
| N4 | Low | Docs vs code | PROTOCOL §8 (`:205-213`), `ice.rs:8-12`, ARCHITECTURE ADR-0006 | §8 still describes the old line filter and the "Independently, Rust filters…" claim that round 1 asked to qualify. It and the `ice.rs` header promise mDNS in LAN mode, but the code drops `.local` in every mode. The new USMC `groupId`-filler composition has no ADR entry (CLAUDE.md non-negotiable 1) |
| N5 | Low | Secret hygiene (M2 residual) | `content.rs` (`Attachment.key`, `ContactIntro.delivery_token`/`invite_proof`, `RekeyInvite.link`, `MailboxUpdate.new_delivery_token`); `account.rs:83` | Decoded secrets live in plain `Vec`/`String` and are never zeroized. `InviteRecordPb`, which holds the proof key, derives `Clone` and a non-constant-time `PartialEq`. `Opened::NewContact`'s derived Debug prints the full identity public key, which CLAUDE.md's logging rule forbids |
| N6 | Low | Supply chain | `supply-chain/audits.toml:3-8`, `supply-chain/config.toml:309` | The AI-written `safe-to-deploy` delta audit for `inout` 0.2.3→0.2.4 counts as a real audit in `cargo vet`. Its rationale "Veil's AEAD paths do not use block padding" is misleading: libsignal's Triple Ratchet encrypts **every message** with AES-256-CBC/PKCS7 (`aes_cbc.rs:34` → `cipher::encrypt_padded` → `inout::into_padded_blocks`), the function this release changed. I checked the delta itself and it is accurate. The stale 0.2.3 exemption remains |
| N7 | Low | Correctness (likely pre-existing) | `content.rs:13,15`; `account.rs:471` | `Content` at `MAX_BODY_LEN` validates, but `seal` returns `TooLarge` for it while the session is in its PreKey phase (probe above): the 1569-byte Kyber ciphertext plus SPQR overhead does not fit the 65,163-byte inner cap |
| N8 | Low | Fuzz efficiency | `contact_inner.rs`; `account.rs:828-832` | Half of all inputs are wasted: types 2 and 3 are refused at once. No corpus seed is a genuine PreKey/Whisper message (max 403 B against ~1.7 KB for a PreKey with Kyber), so the PreKey-from-contact path with a Kyber ciphertext is barely explored (`lim` 427 after 60 s) |
| N9 | Low | Oracle quality / claims | `ice.rs:708` (`assert_relay_only_output`); `fuzz_targets/ice_sdp.rs:12`; INVARIANTS INV-MSG-5 and INV-SUP-3 | Weak oracles and stale numbers (details below) |

#### N1. `contact_plaintext` never gets past unpadding. [HIGH confidence]

- **Why nothing gets through:**
  - `fuzz_seal_plaintext` hands `data` unchanged to `seal_bytes_in_tx` ("already padded plaintext"). On receipt, `decrypt_in_tx` calls `unpad_block`, which returns `Malformed` unless `len % 256 == 0`, the marker is `0x80`, and the rest is zeros (`padding.rs:34-44`).
  - All 84 committed corpus files are 4–40 bytes, and none is a multiple of 256.
  - With `-len_control`, the length limit grows slowly: `lim: 40` after my 61 s run (2,961 runs). At about 16 execs/s, even an hour of fuzzing is unlikely to produce a 256-multiple with a valid marker *and* a canonical protobuf.
- **What is therefore never fuzzed:**
  - `Content::decode_strict` and `validate` on authenticated input;
  - the known-contact `ContactIntro` → `consume_invite_if_proven` path;
  - every post-decrypt rollback branch.
- **What the docs claim instead:** the target's doc comment, INVARIANTS INV-MSG-5 ("reach libsignal, SPQR and content handling") and TEST_REPORT all say otherwise. Its cov 4302 is libsignal encrypt/decrypt, not content handling. This is the claims-vs-evidence gap round 1 flagged as M5.
- **Long-run concern (MEDIUM confidence):** every refused input leaves Bob's receive chain behind Alice's. More than 25,000 consecutive refusals (libsignal `MAX_FORWARD_JUMPS`) would wedge the target into "too far in the future" errors for the rest of the run.
- **Fix:**
  - Pad in the hook: `seal_bytes_in_tx(rng, &remote, &pad_block(plaintext), now)`. Keep a raw-bytes mode behind a selector byte, so unpadding is still fuzzed.
  - Seed `corpus/contact_plaintext` with `encode()` of every `Body` variant, including a `ContactIntro` carrying `invite_id`/`invite_proof` for an invite that exists in the paired fixture.
  - Re-run, record the coverage, and correct INV-MSG-5 and TEST_REPORT until then.
  - Optionally, have Bob reply every N inputs so the chains never drift.

#### N2. INV-PAIR-1 tests don't isolate the identity check. [HIGH, mutation-verified]

- I removed `if ik != invite.identity { return Err(AuthFailed) }`. Both `package_with_swapped_identity_or_signature_refused` and `bundle_must_match_invite_identity` still pass.
- The reason: the swapped package keeps Bob's prekey signatures, so libsignal's `SignatureValidationFailed` (also mapped to `AuthFailed`) rejects it anyway.
- The comment "so the identity and signature checks themselves are exercised" overclaims.
- **Fix:** in the swapped case, also replace `signed_prekey_pub/sig` and `kyber_prekey_pub/sig` with prekeys generated and signed by Mallory, so the bundle is internally consistent for Mallory. Then only the explicit identity check can reject it. Assert `AuthFailed`, and that no peer or session was recorded.

#### N3. Known-contact re-key consumption is untested. [HIGH]

- `consume_invite_if_proven` runs after a *successful* decrypt from a known contact, and can fail with `InviteInvalid` (expired) or `AuthFailed` (bad proof). Both are state-mutating rollback paths, and M4 listed them.
- No test exercises the path at all, not even the success case. `grep -i rekey tests/` shows only Debug tests.
- **Fix:**
  - Add to `rollback_tests` a known contact sending a `ContactIntro { invite_id: <live invite>, invite_proof: <wrong> }` and the same with an expired invite. Assert a byte-identical backend, that the invite is still redeemable, and that the next genuine message opens.
  - Add a success case asserting that `invite/`, `pk/`, `spk/` and `kpk/` are gone.

#### N4. Docs out of step with the fixes.

- **PROTOCOL §8** (`:205-213`):
  - It still says only that non-relay `candidate` lines are removed. It does not say that `o=`, `c=` and `m=` are rebuilt, that unknown attributes are dropped, that relay addresses must be public, or that address-like content invalidates the SDP.
  - Round 1 asked §8 to state that an SDP filter cannot stop the webview's own STUN checks from host candidates; only `iceTransportPolicy` can. That was not done.
- **mDNS in LAN mode:** §8 says "LAN pairing mode is the only exception" for mDNS, and so does `ice.rs:10-12`. The code drops every `.local` candidate in every mode. That is fail-safe, but Chromium-based webviews obfuscate host candidates with mDNS by default, so LAN-mode direct calls will rarely get host candidates. Either document this or design it.
- **Missing ADR:** the H1 fix changes how sealed sender is composed: `sealed_sender_encrypt_from_usmc` with a zero-filled `groupId` and a toggled `contentHint`, instead of `sealed_sender_encrypt`. CLAUDE.md non-negotiable 1 asks for an ADR for a new composition, so add a short note to ADR-0006.

#### N5. Content secrets not zeroized; `InviteRecordPb` is `Clone`.

- Round 1 M2 asked to "wrap `proof_key` and the attachment key in `Zeroizing` … or convert … right after decoding". Only `proof_key` was handled.
- **Fix:**
  - Implement `Drop` with `zeroize` for `Attachment`, `ContactIntro`, `RekeyInvite` and `MailboxUpdate`, as was done for `InviteRecordPb`. Alternatively, document the gap under INV-REST-4.
  - Drop `Clone`/`PartialEq` from `InviteRecordPb`; nothing clones it.
  - Make `Opened`'s Debug print the `Address` only, not the `IdentityKey` bytes.

#### N6. cargo-vet audit rationale is wrong.

- The delta content is fine. I confirmed it: a length check, `assert_eq!` → `debug_assert_eq!` after that check, and a test, with no new `unsafe` and no new dependencies.
- **Fix:**
  - Rewrite the `notes` to state that the changed function *is* on Veil's message path (libsignal AES-256-CBC/PKCS7).
  - Until a human signs, record 0.2.4 as an `exemptions` entry rather than an `audits` entry, so `cargo vet` does not count an unconfirmed AI audit.
  - Run `cargo vet prune` to remove the stale `inout 0.2.3` exemption.

#### N7. Max-size content cannot be sealed as a first message.

- **Fix:** set `MAX_CONTENT_LEN` so that `pad_block(MAX_CONTENT_LEN)` plus the worst-case PreKey overhead fits the 65,163-byte inner cap. That overhead is about 1569 (Kyber ciphertext) + ~33 base key + SPQR chunk + ~60 headers + 16 CBC; measure it.
- Add a test that seals and opens maximum-size `Text` in both the PreKey and the Whisper phase.

#### N8. `contact_inner` wastes inputs and lacks seeds.

- **Fix:** map `ty` to Whisper/PreKey only (keep one rare value for the other types), and seed the corpus with genuine serialized PreKey and Whisper messages captured from the paired fixture.

#### N9. Oracle quality and stale numbers.

- **ICE proptest:** it checks its output with the filter's own `contains_ip_literal`, so it is not an independent oracle.
- **`ice_sdp` fuzz oracle:** it exempts any line containing `127.0.0.1` and every loopback IPv4 from the IPv4 check. A line `…127.0.0.1 … 10.0.0.5` would not be flagged by the oracle, though the filter itself rejects it today.
- **`contains_ip_literal` doc** ("any spelling … `inet_aton` accepts"): this overclaims. Bare decimal `3232235796` and `0xC0A80114` pass. That is harmless, because no browser writes those and no kept attribute is used for transport, but correct the comment.
- **Stale numbers:**
  - INV-MSG-5 says "3 min for the others", but after the framing and filter changes only `ice_sdp` (300 s) and `envelope_unframe` (20 s) were re-run. `account_open` was not.
  - INV-SUP-3 still says "159 exempted" and "36 fully audited"; the real output is 158 exempted and 3 partially audited.
- **Fix:**
  - Use the fuzz target's independent `leaks` in the proptest.
  - Remove the `line.contains("127.0.0.1")` blanket exemption; allow only the exact `o=` placeholder.
  - Fix the doc comment and the numbers.

### 4. Nits (no action required for this gate)

- `filter_candidate` re-emits `+1` / `+7` / leading-zero numeric tokens verbatim (component and extension values), and accepts duplicate extension keys. The doc says "canonical form". Emit the parsed integers instead.
- `seal_to_bucket` skips a bucket when its slack is 0–1 byte. PROTOCOL says "smallest that fits". This is harmless, but word it as "smallest with ≥ 2 bytes of slack".
- `gen.py` output must be run through `rustfmt` before it matches the committed file; say so in its docstring. The script is still not run in CI.
- CI clippy never compiles the `cfg(fuzzing)` hooks. Consider a `RUSTFLAGS="--cfg fuzzing" cargo clippy -p veil-core` step; it is clean today.

### 5. Invariant status corrections required

| ID | Claimed | Should be | Reason |
|---|---|---|---|
| INV-MSG-5 | partial, "reach … content handling" | partial; remove the content-handling claim until N1 is fixed | N1 |
| INV-PAIR-1 | tested (core) | tested, but evidence weak; fix the test | N2 |
| INV-REST-4 | partial | partial; add the decoded-content secrets gap | N5 |
| INV-SUP-3 | numbers 36 / 159 | 36 / 3 partial / 158 | N9 |

All other **tested** and **partial** statuses are backed by tests that exist and assert what is claimed. I grepped every test name cited in INVARIANTS.md and all exist.

### 6. What is done well

- **H1:** a clean fix. The sealed payload fills the bucket exactly, inside the encryption, using only libsignal's public API, and the regression test compares every relay-readable field across sizes and message types.
- **H2:** fixed at the right layer. The backend trait can no longer express a non-atomic write.
- **H3:** an allowlist rebuild instead of a blocklist, and it fails closed. Real Firefox and Chrome offers survive unchanged apart from dropped candidates, and fuzzing found and fixed a real `m=` tail bug.
- **Mutation-checked tests:** the M4, M1 and L5 regression tests all fail when their fix is reverted (verified).
- **Honest docs:** the reports are honest about what has not run yet (nightly 1 h fuzzing, PreKey 4 KiB visibility, the unconfirmed AI vet audit), and all TEST_REPORT numbers reproduce exactly.

### 7. Conditions for PASS

1. Fix N1: `contact_plaintext` must reach `decode_strict`/`validate`/`consume_invite_if_proven`, with seeded corpora and a recorded run. Until then, correct the INV-MSG-5, TEST_REPORT and target doc-comment claims.
2. Fix N2 and N3, the remaining INV-PAIR-1 and INV-STATE-1 test gaps.
3. Address N4 to N9 in docs or code, or defer each with a named phase, before the Phase 3 gate.

VERDICT: PASS WITH CONDITIONS

## Phase 2 review, round 3 (2026-10-19)

**Reviewer:** independent code-reviewer agent (adversarial gate), round 3.
**Scope:** `git diff 4f242cb..HEAD` (HEAD = `8fe1c75`, "Address review round 2 conditions (N1-N9)"): `crates/core/src/{account,content,ice}.rs`, `crates/core/tests/session.rs`, the fuzz targets `contact_plaintext`, `contact_inner` and `ice_sdp`, `.github/workflows/ci.yml`, `crates/core/tests/vectors/requirements.txt`, `supply-chain/`, and `docs/{PROTOCOL,ARCHITECTURE,INVARIANTS,TEST_REPORT}.md`. Binary corpus files (≈ 700) were skipped, apart from the statistics below.
**libsignal consulted:** `~/.cargo/git/checkouts/libsignal-2a193a9867decbc4/4beb029/rust/protocol/src/session.rs` (`process_prekey`: identity trust check at `:59`, Kyber prekey lookup at `:139`).

**Verdict: PASS WITH CONDITIONS.** No Critical, High or Medium findings are open. N2, N3, N5, N6, N7 and N9 are fixed, and I mutation-verified N2, N3, N7 and the new `v=`/`t=`/`b=` validation. N1, N4 and N8 are only partially fixed. The main goal of N1 is met: `contact_plaintext` now reaches strict decoding, validation and the post-decrypt rollback. However, the headline coverage figure is inflated by the fixture rebuild, and the invite-proof branches cannot be reached by construction. There are 5 new Low findings and no regressions. Real Chrome and Firefox offers still pass the tightened ICE filter.

### 1. Evidence re-run (real output, 2026-10-19)

| Command | Result |
|---|---|
| `cargo fmt --all --check` | no output, exit 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | `Finished 'dev' profile`, exit 0, no warnings |
| `RUSTFLAGS="--cfg fuzzing" CARGO_TARGET_DIR=target/fuzzing-lint cargo clippy -p veil-core --lib --locked -- -D warnings` | `Checking veil-core v0.1.0 … Finished`, exit 0 |
| `cargo test --workspace --locked` | unit `73 passed; 1 ignored`; `tests/secrets.rs` `3 passed`; `tests/session.rs` `22 passed; 1 ignored`; doctests `0`. **Matches TEST_REPORT.** |
| `cargo deny --locked check` | `advisories ok, bans ok, licenses ok, sources ok`, exit 0 (only `unmatched license allowance` notes) |
| `cargo audit --deny warnings` | `Loaded 1338 security advisories`, `Scanning Cargo.lock … (203 crate dependencies)`, exit 0 |
| `cargo vet --locked` | `Vetting Succeeded (36 fully audited, 2 partially audited, 159 exempted)`, exit 0. **Matches INV-SUP-3 and TEST_REPORT.** |

**Vectors (the new CI `vectors` job, reproduced exactly).**
- I created a fresh `/usr/bin/python3.12` (3.12.3, as on `ubuntu-24.04`) venv and ran `pip install --require-hashes --only-binary=:all: -r requirements.txt`: exit 0.
- Then `python3 -I gen.py`, `rustfmt +1.97.0 --edition 2024 --config-path rustfmt.toml`, and `diff -u vectors.rs`: **byte-identical**. The reviewer venv from round 2 gives the same result.
- The same install under Python 3.13 **fails**: `Expected sha256 c1453022… Got a931079…` (see R3-5).

**Fuzzing.** I ran `cargo +nightly-2026-10-01 fuzz run -O <t> <scratch copy> -- -max_total_time=120 -max_len=70000 -rss_limit_mb=2048`, with corpora copied to the scratchpad and the artifact prefix pointed there. The three targets ran in parallel on 4 cores.

| Target | Runs / 121 s | INITED cov → final cov | `lim` | Crashes |
|---|---|---|---|---|
| contact_plaintext | 10,934 | 6275 → **10,218** (of which **+3,890 at exec #2001**, the fixture rebuild; see R3-1) | 347 | 0 |
| contact_inner | 35,114 | 8797 → 8797 (ft 12,652 → 12,677) | 2254 | 0 |
| ice_sdp | 2,528,898 | 593 → 1057 | 6217 | 0 |

`git status` was clean after every run, and after the mutation runs and probes.

**Mutation runs** (on a `git archive HEAD` copy in the scratchpad, separate target dir):

```
[N2]  remove `if ik != invite.identity` (account.rs:556)        -> package_with_swapped_identity_or_signature_refused FAILED
[N3a] skip expiry check in consume_invite_if_proven              -> known_contact_rekey_invite_paths FAILED
[N3b] ignore verify_proof result there                           -> known_contact_rekey_invite_paths FAILED
[N3c] do not delete invite/prekeys on valid proof                -> known_contact_rekey_invite_paths FAILED
[N3d] transact() commits instead of rolling back on error        -> known_contact_rekey_invite_paths FAILED
[N7]  MAX_BODY_LEN back to 64*1024-2048                           -> largest_valid_content_always_seals FAILED
[M3]  drop the certificate device-id check (account.rs:609)      -> certificate_key_must_match_sealing_key FAILED
[ICE] `v=`/`t=`/`b=` passed through again                        -> ice::tests::addresses_outside_candidates_removed FAILED
[ICE] re-exempt unspecified IPs (`::`) in contains_ip_literal    -> all 12 ice tests PASS  (R3-3)
[ICE] skip the IP scan on kept t=/b= lines                       -> all pass (equivalent mutant: both are digits-only after validation)
[N5]  stop zeroizing Attachment.key in Drop                      -> all pass (expected; INV-REST-4 documents that wiping is unobservable)
```

**Probes** (a scratch crate with a path dependency on an unmodified HEAD copy):

```
# Real browser SDPs, relay-only (ice.rs at HEAD)
Chrome audio+video+datachannel offer (106 lines: b=AS/b=TIAS, 16 extmap URLs incl. AV1 DD
  and video-layers-allocation00, UUID msid, base64 cname with + and /, rid q/h/f,
  a=simulcast:send q;h;f, red 111/111, H265/AV1/VP9 fmtp, IPv6 relay candidate) -> OK, 103 kept
  (dropped: 2 x a=rtcp, 1 host candidate; the relay candidate is re-serialised with raddr 0.0.0.0)
Same as answer with a=setup:active                                               -> OK
Firefox 128 audio+video offer (82 lines: rid a/b/c, a=simulcast:send a;b;c, b=TIAS,
  {uuid} msid and cname, ssrc-group FID, AV1 fmtp, IPv4 and ULA host candidates)  -> OK, 80 kept
b=CT:1000, b=X-YZ:5, b=RR:0, b=as:30, t=3034423619 3042462419, a=ptime/maxptime -> ok
a=ssrc:1 cname:dead:beef                                                          -> ok (not an IP)
a=ssrc:1 cname:a::b / a=mid:x:: / cname:aa:bb:cc:dd:ee:ff:00:11                   -> Malformed (fail closed)

# N7: true PreKey-phase capacity, measured through fuzz_seal_plaintext (skips validation),
# Text with reply_to, max timer and sent_at = u64::MAX, 40 binary searches
largest Text body that seals >= 63,171 B; MAX_BODY_LEN 62,464 -> margin 707 B
200 consecutive max-size PreKey-phase seals: 0 failed; 200 ping-pong (SPQR epochs) seals: 0 failed
```

### 2. Status of the round-2 findings

| # | Status | Evidence |
|---|---|---|
| **N1** `contact_plaintext` stuck at unpadding | **PARTIALLY FIXED** | **Fixed:**<br>• An even first byte → `pad_block(rest)`; an odd first byte → raw.<br>• 406 of the 464 committed corpus files are in pad mode.<br>• The seeds are `encode()` of every body variant, so valid content now opens and `decode_strict`, `validate` and the post-decrypt rollback are exercised.<br>• Input-driven coverage went from 4302 (round 2) to about 6283 before the first re-pair in my run.<br>• Re-pairing every 2,000 inputs fixes the ratchet-drift concern.<br>**Not as claimed** (R3-1):<br>• The "4325 → 10 057" figure is mostly the fixture rebuild.<br>• `consume_invite_if_proven` is entered, but its expiry, proof and delete branches are unreachable: the fixture has no live invite, and invite ids are random per run.<br>• Those branches are now pinned deterministically by N3's unit test, which mitigates this. |
| **N2** INV-PAIR-1 test | **FIXED** | Mallory re-signs both prekeys, so only Veil's identity check can refuse the package. Mutation-verified. |
| **N3** re-key path untested | **FIXED** | `known_contact_rekey_invite_paths` covers bad proof, foreign-bound proof, expired, unknown id and valid proof.<br>• Every refusal asserts a byte-identical backend (`open_checked`).<br>• The final success proves the invite stayed usable after the refusals.<br>• Four independent mutations all fail the test. |
| **N4** docs | **PARTIALLY FIXED** | PROTOCOL §8 now describes the allowlist and matches the code. I checked:<br>• the kept candidate extensions (`ice.rs:105-110`);<br>• the `v=`/`t=`/`b=` rules;<br>• fail-closed on IP literals;<br>• the public-relay rule.<br>mDNS is documented as dropped in every mode, in `ice.rs:14-15` and §8. ADR-0009 matches `seal_to_bucket` (`groupId` filler, `contentHint` toggle, `0x11`). **Still missing, for the third round:** the sentence that no SDP filter can stop the webview's own STUN checks from host candidates, and that only `iceTransportPolicy` can (R3-4). |
| **N5** content secrets | **FIXED** | `Drop` + `zeroize` on `Attachment`, `ContactIntro`, `RekeyInvite` and `MailboxUpdate`. `InviteRecordPb` has no `Clone`/`PartialEq`. `Opened`'s `Debug` prints only the variant, and the test asserts the address is absent.<br>**No soundness concern:** no `unsafe`; prost's derived `merge` and `clear` work through `&mut` field access, and oneof replacement drops the old value once; derived `Clone` copies are each wiped on drop.<br>The residuals (freed prost buffers; wiping cannot be observed) are disclosed in INV-REST-4. |
| **N6** vet audit | **FIXED** | The audit entry was removed. `inout 0.2.4` is an exemption whose note says the CBC/PKCS7 path *is* used, and the stale 0.2.3 exemption is gone. `cargo vet --locked` passes. |
| **N7** max content in PreKey phase | **FIXED** | `MAX_BODY_LEN` = 62,464. Measured margin is 707 B (≈ 2 padding blocks). It held over 200 consecutive PreKey seals and 200 ping-pong seals. The regression test fails with the old limit. Text/Edit are the largest variants: ICE ≤ 33 KB, SDP ≤ 16 KB, re-key ≤ 8.7 KB, which I checked against `validate`. Compatibility: this is pre-release, and receivers now refuse 62,465–63,488-byte bodies, which is intended. |
| **N8** `contact_inner` | **PARTIALLY FIXED** | The type selector is fixed: 6 of 8 values map to Whisper/PreKey. The "genuine" seeds come from a **different random pairing** (`write_contact_inner_seeds` creates its own accounts), so their identity key never matches the fixture's Alice. libsignal refuses them at the trust check (`session.rs:59`), before any prekey lookup or Kyber decapsulation (`:139`). Coverage did not grow in 121 s (R3-2). |
| **N9** oracles, numbers | **FIXED** | Done:<br>• the proptest uses an independent `any_ip_in`;<br>• the fuzz oracle exempts only the exact `o=`/`c=` placeholders;<br>• the doc comment is corrected;<br>• INV-SUP-3 and INV-MSG-5 numbers are corrected.<br>This uncovered a real gap (`v=`/`t=`/`b=` passed through verbatim), which is now validated and mutation-verified. One sub-change, "`::` included", has no test that pins it (R3-3). |
| **M3 remainder** | **FIXED** | A v3 PreKey message gives `UnsupportedVersion`. A self-issued certificate for device 2 gives `AuthFailed`, and the device check is mutation-verified. Without it the error would be `UnknownSender`, and the test asserts the exact error. |
| **L2 nit** | **FIXED** | `::ffff:0:a.b.c.d` is judged by its IPv4, and a test case was added. |
| Round-2 nits | open, no action required | Unchanged:<br>• candidate `+1`/`+7` tokens are not canonicalised;<br>• PROTOCOL `:149` "smallest bucket that fits" wording;<br>• the `gen.py` docstring and the generated header still say `python3 gen.py > vectors.rs` without the `rustfmt` step that CI now uses. |

### 3. New findings

| # | Sev | Area | Location | Summary |
|---|---|---|---|---|
| R3-1 | Low | Fuzzing claims (INV-MSG-5) | `fuzz_targets/contact_plaintext.rs:27-31`; TEST_REPORT N1 row; INVARIANTS INV-MSG-5 | The coverage headline is inflated by the in-loop fixture rebuild, and the invite-proof branches are unreachable |
| R3-2 | Low | Fuzz seeds (N8 residual) | `account.rs` `pq_tests::write_contact_inner_seeds`; `fuzz_targets/pairing.rs:17-30` | "Genuine" PreKey/Whisper seeds are from a foreign pairing and stop at libsignal's identity-trust check |
| R3-3 | Low | Test gap | `ice.rs` `addresses_outside_candidates_removed` (`a=ssrc:1 cname:::`) | The new "`::` included" rule survives mutation: the test input is caught via `e::` by the old rule too |
| R3-4 | Low | Docs (N4 residual) | `docs/PROTOCOL.md:206-207`, `docs/ARCHITECTURE.md:139` | Still no statement that the SDP filter cannot stop the webview's own host-candidate STUN checks |
| R3-5 | Low | CI robustness | `.github/workflows/ci.yml` `vectors` job; `tests/vectors/requirements.txt` | The hash pins cover only the CPython 3.12 `cffi` wheel and rely on the runner's system Python |

#### R3-1. `contact_plaintext` coverage is inflated, and invite proofs are out of reach. [HIGH confidence, observed]

- **What I observed:** in my run, coverage sat at 6283 until exec #2000. At exec **#2001**, the input on which the counter hits `REPAIR_EVERY` and `paired()` runs inside the fuzz callback, it jumped to 10,173 (+3,890 edges, ft +7,417). The edges come from account creation, invite creation and redemption, the `NewContact` path and dropping the old pair.
- **Effect on the numbers and the corpus:**
  - The arbitrary mutant that happened to run then (`MS: 1 InsertByte`) was added to the corpus as `NEW`. Every re-pair can pollute the corpus in this way.
  - TEST_REPORT's "cov 4325 → 10 057 edges" therefore mostly measures the fixture. The input-driven gain is about 4302 → 6283.
- **Invite proofs:**
  - `paired()` creates one invite, and Bob's `NewContact` consumes it (`delete_invite`). During fuzzing, Bob has no live invite.
  - Invite ids are random per run, so no seed can name one.
  - `consume_invite_if_proven` therefore always returns at `account.rs:754` (`let Some(raw) = rec else { return Ok(()) }`). Its expiry, `verify_proof` and `delete_invite` branches are never fuzzed.
  - The commit message, INV-MSG-5 ("reach … invite proofs and rollback") and TEST_REPORT claim otherwise.
- **Scenario:** a regression in the proof or expiry branch that panics on an odd `invite_proof` length would not be found by this target. N3's unit test covers only well-formed proofs. (Today `validate` enforces 32 bytes first, so this is not exploitable.)
- **Fix:**
  - Make the fixture deterministic: seed a `ChaCha20Rng` from a constant in `pairing.rs` instead of `OsRng`.
  - In `paired()`, have Bob also create one long-lived re-key invite (`expires_at` = `NOW + 10 years`) with a known id, and write a seed whose `ContactIntro` names that id with a valid proof.
  - Exclude the fixture's own coverage: call `paired()` twice in the `thread_local` initialiser, so the rebuild and drop paths are covered before the first input. Alternatively, build a small pool up front.
  - Re-measure, and correct the INV-MSG-5 and TEST_REPORT figures (report coverage after the first re-pair, or the pre-re-pair figure).

#### R3-2. `contact_inner` seeds cannot pass the identity check. [HIGH confidence, from source]

- **Why the seeds stop early:**
  - `write_contact_inner_seeds` builds its own `bob`/`alice` with `OsRng`, while the fuzz fixture builds fresh random accounts.
  - A seeded `PreKeySignalMessage` therefore carries an identity key that is not the fixture Alice's.
  - libsignal's `process_prekey` refuses it at `is_trusted_identity` (`session.rs:59`), before the signed/Kyber prekey lookup and decapsulation (`session.rs:139`).
  - Seeded Whisper messages fail the MAC under the wrong chain.
- **Evidence:** in 121 s and 35,114 runs, `cov` stayed flat at 8797. TEST_REPORT's "genuine PreKey (2 030 B, with Kyber)" seeds are genuine only in structure.
- **Fix:** use the same deterministic fixture as in R3-1 for both the seed writer and `pairing.rs`, so the seeds come from the fixture's own session. Until then, reword TEST_REPORT and INV-MSG-5 ("structurally valid seeds from a separate session").

#### R3-3. The `::` rule is not pinned by a test. [HIGH, mutation-verified]

- **What survives:** reverting `contains_ip_literal` to "any IP except unspecified" leaves all 12 `ice::` tests green.
- **Why:** the intended test input `a=ssrc:1 cname:::` is rejected anyway, because the hex/colon run `e:::` contains `e::`, a non-unspecified IPv6.
- **Fix:** use an input whose only IP-like run is `::`, for example `a=mid:x::` or `a=ssrc:1 cname:x::`. Both are rejected at HEAD (I probed them), and they would pass under the reverted rule.

#### R3-4. The STUN caveat is still not documented.

- Round 1 (H3, "Note for Phase 6") and round 2 (N4) both asked for this.
- PROTOCOL §8 still introduces the Rust filter as "Independently, …". ARCHITECTURE `:139` calls it "defence in depth" without saying what it cannot do.
- **Scenario:** a Phase 6 implementer reads §8, decides the filter suffices, and relaxes `iceTransportPolicy` for compatibility. The webview then sends STUN connectivity checks from host candidates directly to the peer's addresses, which leaks the user's IP. No SDP rewriting can prevent this.
- **Fix:** add to §8: "The SDP filter only controls what is *signalled*. It cannot stop the WebRTC stack from gathering host candidates or sending STUN checks from them. Only `iceTransportPolicy: \"relay\"` does that, and Phase 6 must verify it on every platform (packet capture)." Alternatively, defer it explicitly to Phase 6 in INV-NET-1.

#### R3-5. The vectors CI job depends on the runner's Python minor version.

- **The problem:** `requirements.txt` pins one hash per package. For `cffi` 2.1.1 that is the `cp312-cp312-manylinux2014_x86_64` wheel only. The job uses whatever `python3` the `ubuntu-24.04` image ships (3.12.3 today).
- **What breaks:** on any other CPython, the install fails, as my 3.13 run did (`Expected sha256 c1453022… Got a931079…`). The failure is closed, not silent, but the job will turn red on an image update for reasons that have nothing to do with the vectors.
- **Fix:** either add `actions/setup-python` (pinned by SHA) with `python-version: "3.12"`, or list the hashes of the cp313 and cp314 `cffi` wheels as well. While there, update `gen.py`'s docstring and the generated header to include the `rustfmt --config-path rustfmt.toml` step.

**What I checked and found sound:**
- The `v=`/`t=`/`b=` validators accept everything real browsers emit: `b=AS`, `TIAS`, `CT`, `RR`, `X-…`, lower-case types, and NTP `t=` values.
- No allowlisted attribute in the Chrome or Firefox offers contains `::` or a `hexdigit.digit` pair.
- The `Drop` impls compile against prost 0.14.4's derives without behaviour change.
- The `fuzz-hooks-lint` job reproduces locally, and the `vectors` job fails on any diff (`bash -e`, and `diff` exits 1).
- The `MAX_BODY_LEN` change has no other consumers in the workspace.

### 4. Invariant status corrections required

| ID | Claimed | Should be | Reason |
|---|---|---|---|
| INV-MSG-5 | partial, "reach … invite proofs and rollback" | partial; drop "invite proofs" until R3-1 is fixed; describe the `contact_inner` seeds accurately | R3-1, R3-2 |

All other statuses changed in `8fe1c75` are backed by tests that exist and assert what is claimed. I checked INV-CRY-3, INV-MSG-6, INV-PAIR-1, INV-REST-4, INV-STATE-1 and INV-SUP-3; the first four are mutation-verified where cheap, and the vet numbers match.

### 5. What is done well

- **N2 and N3:** both regression tests are tight. Each fails under every mutation I tried, and `open_checked` makes a byte-identical backend after every refusal a reusable assertion.
- **N9:** the independent oracle immediately found a real pass-through (`v=`/`t=`/`b=`), which was fixed by validation rather than by widening an exemption. Real browser SDPs still survive.
- **N7:** fixed from a measurement (63 203 B), with a regression test across both phases and all large variants. My independent measurement agrees within the effect of field sizes.
- **N6:** the AI-read audit was correctly downgraded to an exemption with an accurate note.
- **Honest residuals:** INV-REST-4 now says plainly that prost's freed buffers and the wiping itself cannot be observed.

### 6. Conditions for PASS

1. Correct the INV-MSG-5 and TEST_REPORT claims for `contact_plaintext` (coverage figure, invite proofs) and `contact_inner` (seed provenance). Then either fix R3-1/R3-2 (deterministic fixture, live re-key invite, fixture coverage at init) or defer them to a named phase.
2. Fix R3-3 (a one-line test input) and R3-4 (one paragraph in §8, or an explicit Phase 6 deferral under INV-NET-1).
3. R3-5 and the remaining nits can be fixed or deferred, with a named phase, before the Phase 3 gate.

VERDICT: PASS WITH CONDITIONS

## Phase 2 review, round 4 (2026-10-19)

**Reviewer:** independent code-reviewer agent (adversarial gate), round 4.
**Scope:** `git diff cbc8712..HEAD` (HEAD = `b7cee0a`, "Address review round 3 conditions (R3-1 to R3-5, round-2 nits)"): `crates/core/src/ice.rs`, `crates/core/fuzz/fuzz_targets/{contact_plaintext,contact_inner}.rs`, `crates/core/tests/vectors/requirements.txt`, and `docs/{PROTOCOL,INVARIANTS,TEST_REPORT}.md`. I also read `pairing.rs`, `account.rs` (`create_invite`, `consume_invite_if_proven`, `seal_to_bucket`), `invite.rs` (id, secret and proof derivation), `gen.py`, `SPIKES.md` §C, ADR-0003, and libsignal `4beb029` `state/kyber_prekey.rs`, `state/signed_prekey.rs` and `kem.rs`.

**Verdict: PASS WITH CONDITIONS.** No Critical, High or Medium findings are open. The code changes are correct:
- R3-3 is fixed and mutation-verified.
- R3-4 and R3-5 are fixed.
- The new canonicalisation and extension dedupe in `filter_candidate` behave correctly on every probe I ran.
- Real Chrome and Firefox offers still pass unchanged (103/106 and 80/82 lines kept, the same as in round 3).
- The corrected `contact_plaintext` coverage figures reproduce.

Three new Low findings stay open:
- **R4-1:** the stated reasons for deferring R3-1 and R3-2 are wrong. Both fixes are feasible, and one is a one-line change that I verified.
- **R4-2:** the new canonicalisation and dedupe code has no test, although TEST_REPORT says one was added.
- **R4-3:** one round-2 nit is reported as fixed but was not changed.

### 1. Evidence re-run (real output, 2026-10-19)

| Command | Result |
|---|---|
| `cargo fmt --all --check` | no output, exit 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | `Finished 'dev' profile`, exit 0 |
| `RUSTFLAGS="--cfg fuzzing" CARGO_TARGET_DIR=target/fuzzing-lint cargo clippy -p veil-core --lib --locked -- -D warnings` | `Finished`, exit 0 |
| `cargo test --workspace --locked` | unit `73 passed; 1 ignored`; `tests/secrets.rs` `3 passed`; `tests/session.rs` `22 passed; 1 ignored`; doctests `0`; exit 0. **Matches TEST_REPORT.** The counts did not change from round 3, so no test was added (see R4-2). |
| `cargo deny --locked check` | `advisories ok, bans ok, licenses ok, sources ok`, exit 0 |
| `cargo audit --deny warnings` | `Loaded 1338 security advisories`, `Scanning Cargo.lock … (203 crate dependencies)`, exit 0 |
| `cargo vet --locked` | `Vetting Succeeded (36 fully audited, 2 partially audited, 159 exempted)`, exit 0 |

**Vectors (the CI `vectors` job, reproduced).** For each of `/usr/bin/python3.12` and `/usr/bin/python3.13` I made a fresh venv and ran:
1. `pip install --require-hashes --only-binary=:all: -r requirements.txt`: **exit 0 on both**.
2. `python3 -I gen.py`.
3. `rustfmt +1.97.0 --edition 2024 --config-path rustfmt.toml`.
4. A comparison with the committed `vectors.rs`: **byte-identical on both**.

I checked the two `cffi` pins against PyPI's metadata for `cffi 2.1.1`:
- `c1453022…` is `cp312-cp312-manylinux2014_x86_64`;
- `a9310795…` is `cp313-cp313-manylinux2014_x86_64`.

**Fuzzing.** Command: `cargo +nightly-2026-10-01 fuzz run -O <t> <scratch copy> -- -max_len=70000 -rss_limit_mb=2048 -artifact_prefix=<scratch>`, with the committed corpora copied to the scratchpad. The three targets ran in parallel on 4 cores.

| Target | Time | Runs | INITED cov → final cov | Crashes |
|---|---|---|---|---|
| ice_sdp | 121 s | 2,089,735 | 592 → 1084 | 0 |
| contact_plaintext | 301 s | 23,008 | 6292 → **6300** (last line before #2001) → **10,172 at #2001** → 10,343 | 0 |
| contact_inner | 121 s | 27,636 | 8743 → 8745 | 0 |

- **contact_plaintext:** the #2001 line logs `NEW_FUNC` entries such as `Account::create` and `delete_invite`, so the jump is the fixture rebuild. This matches TEST_REPORT's corrected figures (6275 → 6282 → 10,171 → 10,356) within run-to-run noise. **The corrected claim is accurate.**
- **contact_inner:** coverage is still flat, as R3-2 predicted and as the deferral now documents.
- **Repository state:** no artifacts were written, and `git status` was clean after every run, mutation and probe.

**Mutation runs.** These ran on a `git archive HEAD` copy in the scratchpad, with a separate target dir, using `cargo test -p veil-core --lib -- ice::`:

```
baseline                                                          -> 12 passed
[R3-3] contains_ip_literal ignores unspecified IPs again          -> addresses_outside_candidates_removed FAILED
        (panic message: "a=mid:x::", i.e. the new input is the one that catches it)
[nit]  emit the raw component token instead of the parsed u16     -> 12 passed  (survives; R4-2)
[nit]  emit raw generation/network-id/network-cost values         -> 12 passed  (survives; R4-2)
[nit]  remove the `seen` dedupe check                             -> 12 passed  (survives; R4-2)
[R3-1] fuzz harness returns early on empty input (libFuzzer's
       dummy run), so the fixture builds on the first real input  -> 60 s: INITED cov 10,191, no jump at #2001 (R4-1)
```

**Probes.** These used a scratch crate with a path dependency on the unmodified HEAD copy.

```
# filter_candidate, new canonicalisation / dedupe
a=candidate:1 +1 udp 1 8.8.4.4 9 typ relay                -> "... 1 udp 1 8.8.4.4 9 typ relay raddr 0.0.0.0 rport 0"
a=candidate:1 001 udp ...                                 -> component 1
a=candidate:1 1 udp +7 8.8.4.4 +09 typ relay              -> priority 7, port 9
... generation +0 generation 5 network-id 007 network-cost 0010
                                                          -> "generation 0 network-id 7 network-cost 10"
... generation x generation 5                              -> "generation 5"   (first *valid* occurrence wins)
... ufrag abcd UFRAG efgh ufrag 10.0.0.1                   -> "ufrag abcd"
... generation 4294967296 / generation -0                  -> extension dropped
tcp host (Direct, LAN) tcptype ACTIVE tcptype passive      -> "tcptype active"
component 0 / 257 / 65537                                  -> None
# Real browser SDPs, relay-only
Chrome a+v+dc offer (106 lines) -> OK, 103 kept (2 x a=rtcp, the host candidate dropped; relay candidate re-serialised)
Chrome answer (a=setup:active)  -> OK, 103 kept
Firefox 128 a+v offer (82 lines) -> OK, 80 kept (o= placeholder normalised, 2 host candidates dropped, relay re-serialised)
b=CT/X-YZ/RR/as, t=NTP, ptime/maxptime, cname:dead:beef -> ok (unchanged from round 3)
```

### 2. Status of the round-3 findings and round-2 nits

| # | Status | Evidence |
|---|---|---|
| **R3-1** `contact_plaintext` coverage inflated; invite-proof branches unreachable | **Claim CORRECTED; reach DEFERRED to Phase 8. The justification is inaccurate (R4-1).** | **Corrected:** INV-MSG-5 no longer claims invite proofs, and TEST_REPORT's N1 row carries a correction pointing to honest figures, which my run reproduces. The target's doc comment documents both limitations.<br>**Deferral accepted on its merits:**<br>• The proof branches are pinned by `known_contact_rekey_invite_paths`, mutation-verified in round 3.<br>• `validate` enforces the 32-byte proof before `consume_invite_if_proven`.<br>**But the reasons given are wrong:**<br>• "random per run and so cannot appear in a committed corpus": the invite id, secret and proof key come from the *caller's* RNG (`invite.rs:132-134`, HKDF at `:208`), and so does the redeemer identity (`Account::create`, `account.rs:150-154`). The harness chooses that RNG (`pairing.rs:11-12`).<br>• "Pairing twice at start-up did not move the jump": true, but because libFuzzer discards the coverage of its initial empty-input dummy run. A one-line early return for empty input removes the jump (verified above). |
| **R3-2** `contact_inner` seeds from a foreign pairing | **DEFERRED to Phase 8. The justification is inaccurate (R4-1).** | Documented in the target and in INV-MSG-5.<br>**What is true:** `KyberPreKeyRecord::generate` uses `OsRng` internally (`kyber_prekey.rs:58`).<br>**What is not:** "a deterministic pairing is impossible from the harness" does not follow. libsignal exposes both `kem::KeyPair::generate(key_type, csprng)` (`kem.rs:439`, `pub mod kem`) and `GenericSignedPreKey::new(id, timestamp, &key_pair, &signature)` (`signed_prekey.rs:59`, a public trait method implemented for `KyberPreKeyRecord`). `account.rs:289` can therefore build the Kyber prekey from the caller's RNG, using public API only.<br>Every other libsignal call in Veil's paths takes Veil's RNG; I grepped `account.rs` for `sealed_sender_decrypt_to_usmc`, `message_decrypt` and `process_prekey_bundle` with an explicit `rng`. |
| **R3-3** `::` rule not pinned | **FIXED** | `a=mid:x::` added (`ice.rs:636-642`). The mutant fails on exactly that input. |
| **R3-4** STUN caveat | **FIXED** | PROTOCOL §8 ("What the SDP filter cannot do") and INV-NET-1 state the limitation: only `iceTransportPolicy: "relay"` or the webrtc-rs configuration prevents host or srflx connectivity checks. The Phase 6 packet-capture test is named.<br>I checked the references: ADR-0003 is indeed webrtc-rs on Linux. SPIKES §C's probe did record `host/udp` candidates, under the default policy. |
| **R3-5** vectors job tied to Python 3.12 | **FIXED** | The cp313 wheel hash was added, and the requirements file documents that other interpreters fail closed. Both 3.12 and 3.13 reproduce byte-identical vectors (above).<br>The round-3 "while there" part (the `gen.py` docstring) was not done; see R4-3. |
| Nit: `+1`/`007` numeric tokens not canonical | **FIXED in code, UNTESTED (R4-2)** | The component (`ice.rs:77`) and the numeric extension values (`:118`) are re-emitted from parsed integers. Priority and port were already re-emitted from parsed integers. The probes confirm this. |
| Nit: duplicate extension keys accepted | **FIXED in code, UNTESTED (R4-2)** | `seen` (`ice.rs:104-127`) keeps the first *valid* occurrence; the comment at `:108` says "the first wins". Behaviour is correct and fail-safe: an invalid first occurrence is not recorded, so a later valid one is kept. |
| Nit: PROTOCOL "smallest bucket that fits" | **FIXED** | PROTOCOL §6 step 3 now says "at least 2 bytes to spare", which matches `seal_to_bucket` (`account.rs:495`: `if target < base.saturating_add(2) { continue; }`). |
| Nit: `gen.py` docstring/header omits the `rustfmt` step | **NOT FIXED, not deferred (R4-3)** | `gen.py:5` and `:35`, and therefore `vectors.rs:4`, still say `python3 gen.py > vectors.rs`. The commit message says "Nits: …" without listing this one. The TEST_REPORT row heading "Round-2 nits | **Fixed.**" implies all of them were fixed. |
| Nit: CI never lints `cfg(fuzzing)` | **FIXED (round 2)** | The `fuzz-hooks-lint` job exists (`ci.yml:136`). The local equivalent is clean (above). |

### 3. New findings

| # | Sev | Area | Location | Summary |
|---|---|---|---|---|
| R4-1 | Low | Docs accuracy (deferral reasons) | `fuzz_targets/contact_plaintext.rs:8-15`, `fuzz_targets/contact_inner.rs:8-11`, `docs/TEST_REPORT.md:11-12`, `docs/INVARIANTS.md:25` | The R3-1 and R3-2 deferrals rest on technical claims that are false; both fixes are feasible, and one is a single line |
| R4-2 | Low | Test gap / false claim | `crates/core/src/ice.rs:75-77, 104-127`; test `candidate_case_and_extensions_canonicalised` (`:474-488`); `docs/TEST_REPORT.md:15` | Canonicalisation and dedupe survive mutation, yet TEST_REPORT says "test added" |
| R4-3 | Low | Docs / process | `crates/core/tests/vectors/gen.py:5, 35`, `vectors.rs:4`; `docs/TEST_REPORT.md:15` | The round-2 `gen.py` nit is reported as fixed but is unchanged |

#### R4-1. The deferral reasons for R3-1 and R3-2 are wrong. [HIGH confidence, verified in source and by experiment]

**What the documents claim:**
- The `contact_plaintext` doc comment and TEST_REPORT say the invite-proof branches "need a live random invite id and proof, which no committed corpus can hold".
- The same doc comment says that because pairing twice at start-up "did not move the jump", the jump "is reported rather than hidden".
- `contact_inner` and TEST_REPORT say "a deterministic pairing is impossible from the harness".
- INV-MSG-5 says the Kyber step is "covered by mutation-checked unit tests instead". The PreKey path is exercised by many session tests, but none of them is a mutation check of the Kyber step.

**Why these claims are false:**
1. **Invite id and proof.** The id and secret come from `rng.fill` with the caller's RNG (`invite.rs:132-134`). The proof key is an HKDF of that secret (`:208`). The proof is an HMAC over id and redeemer identity (`:300-306`). The redeemer identity also comes from the caller's RNG (`Account::create`, `account.rs:154`). With a seeded `ChaCha20Rng` in `pairing.rs:11` instead of `OsRng`, a re-key invite created in the fixture has a fixed id and a fixed valid proof that a committed seed can carry. Kyber randomness does not enter the proof.
2. **The coverage jump.** libFuzzer runs the callback once on a dummy empty input before loading the corpus and does not keep that run's coverage. The `thread_local!` fixture is built during that run, so its edges are first credited to whichever input triggers the next re-pair. Adding `if data.is_empty() { return; }` before `PAIR.with(…)` moves the build to the first real corpus input. Result: `INITED cov: 10191`, no jump at #2001, and from then on the per-input NEW/REDUCE lines are honest (60 s run above).
3. **Deterministic Kyber.** `account.rs:289` can replace `KyberPreKeyRecord::generate(…)` with three public-API calls, all taking the caller's RNG: `kem::KeyPair::generate(kem::KeyType::Kyber1024, rng)`, `private.calculate_signature(&kp.public_key.serialize(), rng)` and `KyberPreKeyRecord::new(id, Timestamp::from_epoch_millis(now_ms), &kp, &sig)`. This is not new cryptography: it is the same three steps `generate` performs (`kyber_prekey.rs:53-70`), with the RNG passed in. I did not build the full deterministic fixture, so I rate the end-to-end feasibility [MEDIUM]. The API itself is verified.

**Why it matters:** these reasons are recorded as the basis for the Phase 8 deferral. A Phase 8 implementer reading "impossible" would skip work that is small, in particular the one-line fix in point 2. The deferral itself is acceptable: the branches are unit-tested and length-checked first.

**Fix (docs only for this gate):**
- In all four places, replace the "impossible" and "cannot" wording with the actual reason for deferral: effort or priority, with the unit-test cover.
- Record the three concrete approaches above in INV-MSG-5's Phase 8 note.
- Optionally apply the empty-input early return now. It is one line in the harness, not in shipped code, and makes every future coverage figure honest.

#### R4-2. Canonicalisation and dedupe have no test; TEST_REPORT says one was added. [HIGH, mutation-verified]

**What survives:** all 12 `ice::` tests stay green under each of three independent reversions:
- the raw component token;
- raw numeric extension values;
- no `seen` check.

The unit-test counts are unchanged from round 3 (73 / 3 / 22). TEST_REPORT `:15` nevertheless says "each candidate extension is kept at most once (test added)". The `ice_sdp` fuzz oracle checks for leaked addresses, not canonical form, so it cannot catch these either.

**Scenario:** a later refactor re-emits the raw token. The doc promise "re-serialized in canonical form" (`ice.rs:44`) breaks silently. This is not a leak today, because the values are still validated as integers. The real harm is that CLAUDE.md rule 9 ("every security claim needs a test") is broken and the test report states something untrue.

**Fix:** extend `candidate_case_and_extensions_canonicalised`:
```rust
assert_eq!(
    filter_candidate(
        "a=candidate:1 +01 udp +7 8.8.4.4 +09 typ relay generation +0 generation 5 network-id 007 \
         ufrag abcd ufrag efgh network-cost 0010",
        Mode::RelayOnly,
    )
    .as_deref(),
    Some("a=candidate:1 1 udp 7 8.8.4.4 9 typ relay raddr 0.0.0.0 rport 0 generation 0 network-id 7 ufrag abcd network-cost 10")
);
```
Also change the `ice.rs:108` comment to "the first valid occurrence wins", and correct TEST_REPORT `:15`.

#### R4-3. The round-2 `gen.py` nit is reported as fixed but is unchanged.

**What is unchanged:** `gen.py:5` (docstring) and `:35` (emitted header), and so `vectors.rs:4`, still give `python3 gen.py > vectors.rs` as the regeneration command. The CI job (`ci.yml:129-134`) runs `rustfmt` before the diff, and without that step the output does not match.

**Why it is still open:** round 3 restated this nit under R3-5 ("While there, update `gen.py`'s docstring …"). TEST_REPORT's "Round-2 nits | **Fixed.**" covers it by omission.

**Fix:** in `gen.py`, make the docstring and header say ``python3 -I gen.py > /tmp/v.rs && rustfmt +1.97.0 --edition 2024 --config-path ../../../../rustfmt.toml /tmp/v.rs && cp /tmp/v.rs vectors.rs``. Regenerate `vectors.rs`, because its header line changes too, so the CI diff stays empty. Alternatively, defer the nit explicitly with a named phase.

**What I checked and found sound:**
- **`filter_candidate` changes:** these cannot widen what is emitted.
  - Every emitted value is either a parsed integer re-formatted by `u16`/`u32::to_string`, a lower-cased keyword from a fixed set, or a `ufrag` that still passes `is_ice_token`.
  - `seen` is pushed only for kept extensions, and its size is bounded by `MAX_CANDIDATE`.
  - Component 0 or > 256 and values that overflow `u32` are still refused or dropped.
  - `+`/`-` signs: `u32` parsing accepts a leading `+` and rejects `-`, and the output never contains a sign.
- **R3-4 text:** it does not overclaim, and it names the Phase 6 end-to-end test.
- **TEST_REPORT corrections:** the corrected R3-1 numbers reproduce. The historical N1 row is annotated, not rewritten.

### 4. Invariant status corrections required

| ID | Claimed | Should be | Reason |
|---|---|---|---|
| INV-MSG-5 | partial; Kyber step "covered by mutation-checked unit tests instead"; deferral "impossible" per TEST_REPORT | partial (unchanged). Say "the PreKey/Kyber path is exercised by session tests" and give the real deferral reason | R4-1 |

INV-NET-1's new wording is backed by tests that exist, and the `::` rule is mutation-verified. No other status changed in `b7cee0a`.

### 5. What is done well

- **R3-3:** the new test input was chosen so that only the intended rule can reject it, which the mutant confirms.
- **R3-1 correction:** honest. The inflated headline was withdrawn, the historical row annotated rather than silently rewritten, and the re-measured numbers reproduce exactly. An attempted fix that did not work was reverted and reported, not kept.
- **R3-4:** the STUN caveat now sits where a Phase 6 implementer will read it, in both PROTOCOL §8 and INV-NET-1, with a concrete verification method (packet capture).
- **R3-5:** the hash pins were verified against both interpreters, and the fail-closed behaviour for others is documented in the file.
- **Canonicalisation code:** small and fail-safe. Real Chrome and Firefox offers are unaffected.

### 6. Conditions for PASS

1. **R4-1:** correct the deferral reasons in the four places listed. Either apply the one-line empty-input fix or record it with the other approaches in the Phase 8 note.
2. **R4-2:** add the canonicalisation and dedupe assertions (one test edit), and correct TEST_REPORT `:15`.
3. **R4-3:** fix the `gen.py` docstring and header and regenerate `vectors.rs`, or defer the nit explicitly with a named phase.

All three are Low, and none blocks starting Phase 3 work. They must be closed or explicitly deferred before the Phase 3 gate.

VERDICT: PASS WITH CONDITIONS

## Phase 2 review, round 5 (2026-10-19)

**Reviewer:** independent code-reviewer agent (adversarial gate), round 5.
**Scope:** `git diff 8d31010..6f90435` ("Address review round 4 conditions (R4-1 to R4-3)"), 20 files:
- `crates/core/src/account.rs`: the Kyber prekey change in `create_invite` and the `fuzz_inner_of` hook;
- `crates/core/src/invite.rs`: `fuzz_proof`;
- `crates/core/src/ice.rs`: the R4-2 test;
- `crates/core/fuzz/fuzz_targets/{pairing,contact_inner,contact_plaintext}.rs`, the 8 new `seed-*` corpus files, `fuzz/Cargo.toml` and `fuzz/Cargo.lock`;
- `crates/core/tests/vectors/{gen.py,vectors.rs}`;
- `docs/{TEST_REPORT,INVARIANTS}.md`.

I also read `Account::open`, `consume_invite_if_proven`, `delete_invite` and the older seed writers in `account.rs` and `tests/session.rs`. On the libsignal side (`4beb029`) I read `state/kyber_prekey.rs`, `state/signed_prekey.rs` (`GenericSignedPreKey::new`), `kem.rs` and `session.rs` (`process_prekey_impl`).

**Verdict: PASS WITH CONDITIONS.** All three round-4 findings are fixed, and this time the claims hold up:
- **R4-2:** the new assertion kills all four mutants I tried.
- **R4-3:** the regeneration command in `gen.py` reproduces `vectors.rs` byte for byte on CPython 3.12 and 3.13.
- **R4-1:** the fixture is deterministic across processes. I regenerated all 8 committed seeds and every one is byte-identical. Each seed takes its claimed branch on a fresh fixture.
- **The Kyber change** is equivalent to libsignal's own `KyberPreKeyRecord::generate` in key type, signed bytes and record format. Only the RNG source and the stored timestamp differ. It changes no wire format.

No Critical, High or Medium finding is open. There are five new Lows and one nit:
- **R5-1:** the Kyber step and the bad-proof branch are reached only once per fixture, or only when the seeds happen to run in the right order, so the fuzzer cannot mutate its way into them.
- **R5-2:** some of the new TEST_REPORT fuzz figures do not reproduce, and "no jump" is not quite true.
- **R5-3:** nothing in `cargo test` or CI pins the new deterministic Kyber generation.
- **R5-4:** the RNG contract of `create_invite` is undocumented, and it now covers the post-quantum key too.
- **R5-5:** a stale seed writer still writes the same file names from a random pairing.

### 1. Evidence re-run (real output, 2026-10-19, HEAD = `6f90435`)

| Command | Result |
|---|---|
| `cargo fmt --all --check` | no output, exit 0 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | `Checking veil-core v0.1.0 … Finished 'dev' profile`, exit 0 |
| `RUSTFLAGS="--cfg fuzzing" CARGO_TARGET_DIR=target/fuzzing-lint cargo clippy -p veil-core --lib --locked -- -D warnings` | `Finished`, exit 0 |
| `cargo test --workspace --locked` | unit `73 passed; 1 ignored`; `tests/secrets.rs` `3 passed`; `tests/session.rs` `22 passed; 1 ignored`; doctests `0`; exit 0. This matches TEST_REPORT. The count is unchanged because the R4-2 assertion went into an existing test. |
| `cargo deny --locked check` | `advisories ok, bans ok, licenses ok, sources ok`, exit 0 |
| `cargo audit --deny warnings` | `Loaded 1338 security advisories`, `Scanning Cargo.lock … (203 crate dependencies)`, exit 0 |
| `cargo audit --deny warnings -f crates/core/fuzz/Cargo.lock` | `(194 crate dependencies)`, exit 0. The only lockfile change is `prost` added to `veil-core-fuzz`'s dependency list, at the same `=0.14.4` as the workspace. |
| `cargo vet --locked` | `Vetting Succeeded (36 fully audited, 2 partially audited, 159 exempted)`, exit 0 |

**Vectors.** I ran the exact command now written in `gen.py:6`:

```
python3 -I gen.py > vectors.rs && rustfmt --edition 2024 --config-path ../../../../rustfmt.toml vectors.rs
```

- **Where:** in `crates/core/tests/vectors` of a `git archive HEAD` scratch copy. `rustfmt` 1.97.0 comes from the copy's `rust-toolchain.toml`.
- **Interpreters:** `python3` was on the PATH from three hash-pinned venvs: the provided 3.13 venv, and the round-4 3.12 and 3.13 venvs.
- **Result:** exit 0 each time, and `cmp` against the committed `vectors.rs` reports **IDENTICAL** on all three.
- **Path check:** the relative `--config-path` correctly resolves to the repository root.

**Determinism and seeds (R4-1).**
- **Cross-process determinism.** On a scratch copy, I deleted the 8 `seed-*` files from copies of both corpora and re-ran `VEIL_WRITE_SEEDS=<dir> cargo +nightly-2026-10-01 fuzz run -O <t> <dir> -- -runs=0`. Both exited 0, so the writers' internal `assert_deterministic` and per-seed self-checks passed. All 5 `seed-genuine-*` and all 3 `seed-rekey-*` files came out **byte-identical** to the committed ones.
- **Branch probe.** I used a second scratch copy with two added `cfg(fuzzing)` probe hooks:
  - one reports whether Bob's re-key invite record exists;
  - one counts Bob's Kyber prekeys.

  The targets logged every seed execution, and I ran `-runs=0` over the seed files alone and over the full corpus four times:

```
contact_inner (seeds only, and each of 4 full-corpus runs, same result):
  seed-genuine-0/1/2 (Whisper)  -> Ok(Message)   kyber 1->1
  seed-genuine-4    (PreKey)    -> Ok(Message)   kyber 1->0   (re-key invite consumed: PQXDH + Kyber ran)
  seed-genuine-3    (Whisper)   -> Ok(Message)   kyber 0->0   (old-session message still opens after the PreKey)
contact_plaintext:
  seeds only : unknownid Ok live 1->1 | valid Ok live 1->0 | badproof Ok   live 0->0   <- not AuthFailed
  full run 1 : badproof AuthFailed     | unknownid Ok      | valid Ok live 1->0
  full run 2 : unknownid Ok            | valid Ok live 1->0| badproof Ok  live 0->0   <- not AuthFailed
  full run 3 : badproof AuthFailed     | unknownid Ok      | valid Ok live 1->0
  full run 4 : valid Ok live 1->0      | badproof Ok       | unknownid Ok             <- not AuthFailed
```

  - Every seed takes its claimed branch **on a fresh fixture**, and "valid proof → accepted and consumed" is true.
  - In real runs, though, `seed-rekey-badproof` reaches `verify_proof`'s failure branch only when libFuzzer happens to run it before `seed-rekey-valid`. The three seeds are the same size (144 bytes), so their order is random. That happened in 2 of 5 runs. Otherwise the invite has already been deleted and the seed takes the unknown-id `return Ok(())`. INITED coverage tracks this exactly: 10 855 when the bad proof is reached, 10 831 when it is not. See R5-1.
- **contact_inner after a 60 s run** (probe binary, 16 747 runs): exactly one execution moved Bob's Kyber prekeys from 1 to 0, and the store held 0 for all later executions. See R5-1.

**Fuzzing on scratch corpus copies.** Clean HEAD build, `-O`, `-max_len=70000 -rss_limit_mb=2048`. The two targets ran in parallel on 4 cores. No crashes, no artifacts.

| Target | Time | Runs | INITED cov → final | Jumps of ≥ 15 edges |
|---|---|---|---|---|
| contact_plaintext | 181 s | 15 702 | 10 779 → 10 947 | **#2003: 10 793 → 10 859 (+66)**; #5628 +17; #11952 +24 |
| contact_inner | 151 s | 44 572 | 9885 → 9931 | #923 +29 (not a re-pair; this target never re-pairs) |

- **contact_plaintext at the re-pairs:** #4003, #6003, #8002 and #10002 log `NEW` with features only and no edge gain, so the round-4 setup jump (+3872) is gone.
- **The +66 at the first re-pair:** I repeated it with `-runs=2100 -print_pcs=1` and got `#1719 cov 10808` → `#2003 cov 10874`, with `NEW_FUNC … drop_glue::<veil_core::store::MemoryBackend>` and `NEW_FUNC … drop_glue::<contact_plaintext::pairing::Fixture>`. The new PCs are zeroizing `write_volatile`s plus `contact_plaintext.rs:86` (the re-pair line itself). That code is the teardown of the old fixture, which first runs at the first re-pair. See R5-2.
- **Against TEST_REPORT's 150 s rows:** contact_inner 9877 → 9910 and contact_plaintext 10 803 → 10 952 reproduce within run-to-run noise.

**INITED with `-runs=0`** (TEST_REPORT's "before / with the seeds" rows):

| Corpus | contact_inner | contact_plaintext |
|---|---|---|
| committed corpus minus `seed-*` | 9310, 9310 | 10 752, 10 752 |
| committed corpus | 9847, 9764 | 10 779, 10 779 |
| `seed-*` only | 9431 | 9354 |
| empty dir | 8780 | 9025 |
| **TEST_REPORT** | **3429 → 6028** ("~2 600 edges") | **6068 → 6246** |

None of my configurations comes near TEST_REPORT's figures. See R5-2.

**Mutation runs** on a `git archive HEAD` scratch copy, with a separate target dir:

```
cargo test -p veil-core --lib -- ice::
baseline                                                    -> 12 passed
[R4-2] emit the raw component token                         -> candidate_case_and_extensions_canonicalised FAILED
[R4-2] emit raw generation/network-id/network-cost values   -> candidate_case_and_extensions_canonicalised FAILED
[R4-2] remove the `seen` dedupe check                       -> candidate_case_and_extensions_canonicalised FAILED
[R4-2] first occurrence wins even if invalid (seen.push
       before validation)                                    -> candidate_case_and_extensions_canonicalised FAILED

cargo test -p veil-core   (create_invite, Kyber prekey)
sign the signed-prekey bytes instead of the Kyber public key -> 6 lib tests FAILED   (signature is pinned)
store Timestamp 0 instead of timestamp(now)                  -> all pass (expected: libsignal never reads it)
revert to KyberPreKeyRecord::generate (internal OsRng)       -> all pass (73/3/22)   (R5-3)
```

`git status` was clean after every run. All copies, corpora, probes and target dirs were under the scratchpad.

### 2. The Kyber change compared with libsignal's `generate`

The libsignal side is `kyber_prekey.rs:53-74` at `4beb029`. Veil's replacement is `account.rs:289-296`.

| Aspect | libsignal `generate` | Veil `create_invite` | Same? |
|---|---|---|---|
| Key type | caller-given (`Kyber1024` was passed) | `kem::KeyType::Kyber1024` | yes |
| Key pair | `kem::KeyPair::generate(type, &mut OsRng.unwrap_err())` | `kem::KeyPair::generate(type, rng)` (caller's `Rng + CryptoRng`) | API yes; RNG source differs |
| Signed bytes | `key_pair.public_key.serialize()` (with key-type byte) | the same | yes |
| Signing key | the identity `PrivateKey` | the same (`private`) | yes |
| Record | `KyberPreKeyRecord::new(id, ts, &kp, &sig)` (`GenericSignedPreKey::new`) | the same | yes, same `SignedPreKeyRecordStructure` |
| Timestamp | wall clock in ms, with two `expect`s | `timestamp(now)` = caller's `now × 1000`, the same as the signed prekey at `:337` | value differs. libsignal never reads a Kyber prekey's timestamp (its only `timestamp()` uses are unacknowledged-session ages), and `PackagePb` does not carry it. Two potential panics are removed. |

What goes on the wire is unchanged: `PackagePb` holds the same public key, id and signature bytes. The redeemer's `process_prekey_bundle` still verifies the signature, as the `sign wrong key` mutant shows. No new primitive or composition is introduced; this uses libsignal's own public API in the same steps, so no ADR is needed.

On whether a weak RNG can reach this in production:
- **Today:** `crates/core` is the only crate, and nothing outside it calls `create_invite`.
- **Existing callers:** the tests pass `OsRng.unwrap_err()`. The only seeded caller is the fuzz harness, which is outside the library.
- **The bound does not help:** `CryptoRng` is only a marker trait, and `StdRng::seed_from_u64` satisfies it.
- **The post-quantum secret now depends on the caller's RNG:** before this change it was the one invite secret that stayed independent of it. See R5-4.

### 3. Status of the round-4 findings

| # | Status | Evidence |
|---|---|---|
| **R4-1** false deferral reasons for R3-1/R3-2 | **FIXED.** R3-1 and R3-2 are now fixed rather than deferred, apart from the reach limits in R5-1. | The false "impossible" and "cannot" wording is gone. The round-3 TEST_REPORT rows are annotated as superseded, not rewritten.<br>The fixture is deterministic within one process (`assert_deterministic`) and across processes (seeds regenerated byte-identical).<br>**R3-2:** the genuine seeds match the fixture. All 5 open in real runs, and the PreKey seed goes through PQXDH and the Kyber step (Kyber prekey 1 → 0).<br>**R3-1:** the valid-proof seed reaches `verify_proof` and `delete_invite`.<br>**Coverage jump:** the empty-input early return removed the setup jump. A residual +66 at the first re-pair comes from fixture teardown (R5-2). |
| **R4-2** canonicalisation and dedupe untested; false "test added" | **FIXED** | The assertion is at `ice.rs:488-499`. All four mutants are killed. The comment now says "first *valid* occurrence wins". TEST_REPORT `:37` carries an explicit correction of the false claim. |
| **R4-3** `gen.py` docstring | **FIXED** | `gen.py:5-6` and `:36-37`, and `vectors.rs:4-5`, give the full command. It reproduces the vectors byte for byte on 3.12 and 3.13. |

### 4. New findings

| # | Sev | Area | Location | Summary |
|---|---|---|---|---|
| R5-1 | Low | Fuzz reach | `fuzz_targets/contact_inner.rs:19-26, 71-87`; `contact_plaintext.rs:38-73, 85-87`; `docs/INVARIANTS.md:25` | The Kyber step and the bad-proof branch are one-shot or order-dependent per process, so mutated inputs cannot explore them |
| R5-2 | Low | Docs accuracy | `docs/TEST_REPORT.md:19, 21, 22` | The `-runs=0` figures do not reproduce, and "no jump" is not quite true (+66 from fixture teardown) |
| R5-3 | Low | Test gap | `account.rs:289-296`; `fuzz_targets/pairing.rs:66-70` | Reverting to `KyberPreKeyRecord::generate` passes every test and CI, and would silently invalidate every genuine seed |
| R5-4 | Low | Security docs (defence in depth) | `account.rs:254-256`; `docs/PROTOCOL.md` §4.2 | The RNG contract of `create_invite` is undocumented, and it now covers the ML-KEM secret |
| R5-5 | Low | Stale tooling | `account.rs:919-985` (`write_contact_inner_seeds`) | The old seed writer produces the same `seed-genuine-0..4` names from a random pairing |
| N1 | Nit | Docs | `invite.rs:288-296` | `fuzz_proof` was inserted under `proof_key_bytes`'s doc comment |

#### R5-1. The Kyber step and the bad-proof branch are one-shot or order-dependent. [HIGH, verified by probe and in libsignal source]

**contact_inner.**
- **What happens:** the fixture is built once and never rebuilt. The first time `seed-genuine-4` runs, Bob consumes the re-key invite: `consume_invite_if_proven` calls `delete_invite`, which deletes the Kyber, signed and one-time prekeys.
- **What then fails:** `process_prekey_impl` (`session.rs:97-142`) either returns early on a known base key (`promote_matching_session`) or fails at `get_signed_pre_key` / `get_kyber_pre_key` before any decapsulation.
- **Effect:** for the rest of the process, no input reaches PQXDH or ML-KEM decapsulation. The probe shows `kyber 1->0` once, then `0->0` for 16 747 runs. The Kyber step is executed by exactly one input, the unmutated seed, and the fuzzer never mutates the ciphertext into it.

**contact_plaintext.**
- **What happens:** `seed-rekey-valid` deletes the invite. For the rest of that 2000-input fixture, `seed-rekey-badproof` and any mutated proof take the unknown-id `return Ok(())`, not `verify_proof`.
- **Effect:** whether INITED covers the bad-proof branch depends on libFuzzer's random ordering of three same-size files. In my runs it was 2 of 5 (24 edges).
- **A further gap:** the writer's self-check (`:69-70`) accepts `Ok(Message)` for both "valid" and "unknownid". It therefore never checks that the valid proof was accepted and the invite consumed. That is true (my probe), but unverified by the harness.

**Why it matters:**
- INV-MSG-5 and the target doc comments say the targets "reach … PQXDH and the Kyber step" and "the invite-proof branches". That is literally true, but a reader will take it to mean those branches are fuzzed, and they are not.
- This is a fuzz-depth gap, not a product bug: the branches are unit-tested, and libsignal's own decapsulation has its own tests.

**Fix:**
1. Add a `cfg(fuzzing)` hook `Account::fuzz_has_invite(&self, id: &[u8]) -> bool`.
2. In both targets, rebuild the fixture right after any input that leaves `!f.bob.fuzz_has_invite(&f.rekey.id)`. For `contact_inner` this means keeping the whole `Fixture` in `PAIR` and adding the same re-pair logic as `contact_plaintext`.
3. In `contact_plaintext::write_seeds`, assert `!g.bob.fuzz_has_invite(&g.rekey.id)` after "valid" and `g.bob.fuzz_has_invite(...)` after "unknownid".
4. Either fix the ordering (re-pairing after consumption makes it irrelevant), or state the limit in INV-MSG-5: "reached once per fixture".

#### R5-2. Some TEST_REPORT fuzz figures do not reproduce. [HIGH for the measurements; MEDIUM for the cause of the author's numbers]

**What does not reproduce:**
- **The `-runs=0` rows (`TEST_REPORT.md:19, 21`):** "contact_inner 3429 → **6028**, the genuine seeds alone add ~2 600 edges" and "contact_plaintext 6068 → 6246" match no configuration I measured (table in §1).
  - The genuine seeds add about **450–540** edges (9310 → 9764/9847), not about 2600.
  - The re-key seeds add about **27** (10 752 → 10 779).
  - The figures also contradict the same report's 150 s rows (`INITED 9877` and `10 803`), which come from the same build and corpus and do reproduce.
  - I could not find how 3429 or 6068 arose. They may come from an earlier harness version.
- **"No jump across seven re-pairs" (`:22`):** the first re-pair still adds **+66 edges** (10 808 → 10 874 and 10 793 → 10 859 in two runs). `-print_pcs` attributes them to `drop_glue::<Fixture>` and `drop_glue::<MemoryBackend>` (zeroize) and to the re-pair line. That is far smaller than round 4's +3872, and its cause differs from the parenthetical's explanation.

**Why it matters:** this is the third round in which a coverage figure in TEST_REPORT does not reproduce. CLAUDE.md requires "real command output".

**Fix:**
- Replace rows 19 and 21 with real output, including the exact corpus and build used, or delete them.
- Change "No jump" to "+66 at the first re-pair (teardown of the old fixture); no setup jump".
- Optionally, run `drop(paired());` once in each target's `thread_local!` initialiser, so that teardown is part of the baseline as well.

#### R5-3. Nothing pins the deterministic Kyber generation. [HIGH, mutation-verified]

**What survives:** replacing `account.rs:289-296` with the old `KyberPreKeyRecord::generate(…)` passes `cargo test --workspace` (73/3/22) and clippy.
- **Why the fuzz smoke job would not catch it either:** `assert_deterministic` runs only when `VEIL_WRITE_SEEDS` is set.
- **What breaks silently:** the fixture's PQXDH shared secret would become random per run, so every committed genuine seed (all 5) would stop opening. The R3-2 fix would quietly undo itself.
- **What is affected:** the commit message and TEST_REPORT present "every invite key comes from one injected source" as a property, and nothing tests it.

**Fix (either is enough):**
- **A unit test** in `account.rs`. Create the same account twice from `StdRng::seed_from_u64(1)`, call `create_invite` on each with a fresh `StdRng::seed_from_u64(2)`, and assert `a.sealed_package == b.sealed_package`.
- **An unconditional check in the fuzz init:** call `pairing::assert_deterministic()` in both targets' initialisers, so the CI smoke run fails on regression. It costs two extra pairings once per process.

#### R5-4. `create_invite`'s RNG contract is undocumented, and it now covers the ML-KEM secret. [MEDIUM: design judgement; no production caller yet]

**The trade-off:**
- **Before this change:** the invite's ML-KEM secret came from libsignal's `OsRng`. If a caller passed a weak or seeded RNG, the EC prekeys would be predictable, but PQXDH's KEM shared secret would still be secret. A passive attacker could still not derive the session key, since the inviter's EC privates alone do not give `SS`.
- **Now:** every invite secret depends on the caller's RNG. This is a reasonable choice: one injected source, testability, and two fewer `expect`s. It removes one layer of independence, though.
- **The guard is weak:** `R: Rng + CryptoRng` is only a marker, and seeded `StdRng` satisfies it. No document states what callers must pass.

**Scenario:** the Phase 4 client wires `create_invite` to a convenience RNG, for example a `StdRng` seeded once from the clock. Before this change the post-quantum layer would still have protected the session. Now it does not.

**Fix (docs only):** add to the doc comment at `account.rs:254`, and to PROTOCOL §4.2 or INV-ID:

```rust
/// `rng` must be an OS-seeded CSPRNG (`OsRng.unwrap_err()` or `rand::rng()`); it supplies
/// every secret of the invite, including the ML-KEM prekey. Seeded RNGs are for tests and
/// fuzzing only.
```

Add the same note to `Account::create` and `redeem_invite`. Phase 4 should list this as a review item for the client wiring.

#### R5-5. A stale seed writer still writes `seed-genuine-0..4` from a random pairing. [HIGH, read]

**What it does:** `account.rs:919-985`, `write_contact_inner_seeds` (round 2, `#[ignore]`):
- builds a pairing from `OsRng`;
- writes `seed-genuine-0` through `seed-genuine-4`, exactly the names the new deterministic writer uses.

**Why it is harmful:** its doc comment still says `Run with VEIL_SEED_DIR=crates/core/fuzz/corpus/contact_inner …`. Following it overwrites the five committed deterministic seeds with foreign-pairing ones, which reintroduces R3-2 silently. Nothing would fail.

**Not affected:** `tests/session.rs:1137-1167` (`write_contact_plaintext_seeds`) writes `seed-body-*` and does not collide.

**Fix:** delete `write_contact_inner_seeds`, which the harness writer supersedes, or rename its output and change its doc comment to point to `VEIL_WRITE_SEEDS`.

#### N1. `fuzz_proof` sits under the wrong doc comment.

`invite.rs:288-289`: the new function was inserted between `proof_key_bytes` and its doc comment. As a result, `fuzz_proof`'s rustdoc starts with "Exposes the proof key so the inviter can verify redemptions…", and `proof_key_bytes` has no doc.

**Fix:** move line 288 below `fuzz_proof`, directly above `pub(crate) fn proof_key_bytes`.

**What I checked and found sound:**
- **`fuzz_inner_of` and `fuzz_proof`** are compiled only under `cfg(fuzzing)`: the impl block at `account.rs:830`, and `invite.rs:290`. Neither exposes the invite secret or proof key, only a proof for a given redeemer. Clippy is clean with `--cfg fuzzing`.
- **The harness's fixed seed** lives only in the fuzz crate, not in the library.
- **Fuzz inputs** are still sealed with `OsRng`, as documented.
- **`seed-genuine-3`** (an old-session Whisper message) still opens after the PreKey seed has promoted the new session, because libsignal tries previous states. So corpus order does not hurt the Whisper seeds.
- **The `prost` dependency** added to the fuzz crate is pinned exactly and matches the workspace version.
- **INV-MSG-5 status** stays **partial**, which is correct (no nightly run recorded yet).

### 5. Invariant status corrections required

| ID | Claimed | Should be | Reason |
|---|---|---|---|
| INV-MSG-5 | partial; the targets "reach … PQXDH and the Kyber step … the invite-proof branches" | partial (unchanged). Add: "reached once per fixture; `contact_inner` never re-pairs, so mutated PreKey inputs do not reach decapsulation" (or fix R5-1) | R5-1 |

No other invariant changed in `6f90435`.

### 6. What is done well

- **The Kyber change** is the minimal, correct one. It reuses libsignal's public API in libsignal's own order, keeps the signature semantics, stores the same timestamp convention as the signed prekey, and removes two latent panics (`expect("Time should move forward")` and `expect("Timestamp too large")`).
- **Determinism is real and self-checking.** The seeds regenerate byte-identically in a separate process. The writers replay every seed on a fresh fixture before writing it, a good guard against the "test added but never applied" class of error from round 4.
- **The R4-2 test** covers all three behaviours with one input, and its "first *valid* occurrence" case kills a mutant (`seen.push` before validation) that I had not asked for.
- **The empty-input fix** removed the +3872 setup jump. Round-3 claims were annotated as superseded rather than silently rewritten, and the false "test added" claim is explicitly retracted.

### 7. Conditions for PASS

1. **R5-1:** re-pair after the invite is consumed in both targets, and check consumption in the writer. Alternatively, state the "once per fixture" limit in INV-MSG-5 and the target doc comments, and defer the fix to a named phase.
2. **R5-2:** replace TEST_REPORT rows 19 and 21 with reproducible output, and correct "No jump".
3. **R5-3:** add the determinism unit test, or call `assert_deterministic` unconditionally.
4. **R5-4:** document the RNG contract on `create_invite`, `Account::create` and `redeem_invite`, and in PROTOCOL §4.2.
5. **R5-5:** delete or retarget `write_contact_inner_seeds`.
6. **N1** is optional.

All are Low, and none blocks Phase 3 work. Each must be fixed, or explicitly deferred to a named phase with an accurate reason, before the Phase 3 gate.

VERDICT: PASS WITH CONDITIONS

## Phase 2 review, round 6 (2026-10-19)

**Scope.** `104928f..75b6dcd` (7 files, +122/−83):
- `crates/core/src/account.rs`: the `fuzz_has_invite` hook, the RNG doc comments, the deletion of `write_contact_inner_seeds`, and the new test `invite_keys_come_only_from_the_callers_rng`;
- `crates/core/src/invite.rs` (N1);
- `crates/core/fuzz/fuzz_targets/{contact_inner,contact_plaintext}.rs`;
- `docs/{PROTOCOL,TEST_REPORT,INVARIANTS}.md`.

I re-read CLAUDE.md and rounds 1–5. I verified every claim myself and did not rely on the author's descriptions. All probes, mutants, corpora and target dirs were scratch copies under the session scratchpad (`…/scratchpad/r6`, with target dirs under `…/scratchpad/r5/target-*`). `git status` was clean after every step.

### 1. Evidence

| Check | Result |
|---|---|
| `cargo fmt --all --check` | exit 0 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | exit 0 |
| `RUSTFLAGS='--cfg fuzzing' cargo clippy -p veil-core --lib --all-targets --locked -- -D warnings` | exit 0 |
| `cargo test --workspace --locked` | **74 / 3 / 22 (+1 ignored) / 0 doc**, all pass. Matches TEST_REPORT: one test added, and the ignored lib writer is gone. |
| `cargo deny check` | advisories ok, bans ok, licenses ok, sources ok |
| `cargo audit` | exit 0 (1338 advisories, 203 crates) |
| `cargo vet` | Vetting Succeeded (36 fully audited, 2 partially audited, 159 exempted) |
| Vectors: `python3 -I gen.py > vectors.rs && rustfmt …` on a `git archive HEAD` copy, with the argon2 venv | exit 0; `cmp` reports **IDENTICAL** |
| `cargo +nightly-2026-10-01 fuzz build -O` of both contact targets | no warnings |

### 2. Status of the round-5 findings

| # | Status | Evidence |
|---|---|---|
| **R5-1** Kyber / bad-proof reach was one-shot | **FIXED** | See 2.1. |
| **R5-2** TEST_REPORT figures did not reproduce | **FIXED.** One residual imprecision is listed as optional nit R6-N1. | See 2.2. |
| **R5-3** nothing pinned the injected-RNG Kyber generation | **FIXED** | The round-5 mutant (`KyberPreKeyRecord::generate(kem::KeyType::Kyber1024, kyber_id.into(), &private)?`, applied by the round-5 `mutk.py` on a scratch copy) now gives `invite_keys_come_only_from_the_callers_rng ... FAILED` at `account.rs:1488` (the `sealed_package` equality), 73 passed / 1 failed. The test compares the whole sealed package, so it also catches any other invite secret drawn from a different RNG (prekey ids, EC keys, nonce). |
| **R5-4** RNG contract undocumented | **FIXED.** Wording nit R6-N2. | See 2.3. |
| **R5-5** stale seed writer collided | **FIXED** | See 2.4. |
| **N1** misplaced doc comment | **FIXED** | `invite.rs:288-298`: `fuzz_proof` has its own doc, and "Exposes the proof key…" sits directly above `proof_key_bytes`. |

#### 2.1 R5-1: Kyber and bad-proof reach

I instrumented a scratch copy, which was never committed:
- `store.rs` `get_kyber_pre_key` increments a counter after it loads a record. libsignal does this only once it has passed the session, version and signed-prekey checks; ML-KEM decapsulation follows.
- `consume_invite_if_proven` counts `verify_proof` Ok and Err.
- The targets log consumption, re-pairs (with timing) and which seed was run.

**Run:** clean `-O` build, 90 s, corpus copies.

**contact_inner** (23 298 runs):
- `SEED4 kyber_get=1 consumed=true` → re-pair (13.5 ms). This happens once, during INITED.
- After that, **30 mutated (non-seed) inputs** loaded Bob's Kyber prekey (`kind=other len=2030 kyber_get=1 consumed=false`), spread over the whole run (#5383 … #22123).
- In round 5, the Kyber store held 0 entries for every input after the first.
- No mutated input consumed the invite, so the seed caused the only re-pair.

**contact_plaintext**, with two libFuzzer seeds so the INITED order differs:
- `-seed=1`: `SEED-badproof bad=1` runs **before** `SEED-valid ok=1` → `repair consumed=true`. Mutated inputs later reach `verify_proof` Err (`kind=other bad=1`) after periodic re-pairs.
- `-seed=7`: `SEED-valid ok=1` → `repair consumed=true` → `SEED-badproof bad=1`. The bad-proof branch is reached even though the valid seed ran first.
- So the bad-proof branch is reached in both orders. The re-pair check runs **before** each input, which makes the order irrelevant.

**Pathological loops and starvation:** none.
- Consumption re-pairs happened once per run in all three runs. A re-pair costs 13–23 ms.
- Throughput is unchanged from round 5 on clean builds: contact_inner 279 exec/s vs 295, contact_plaintext 86 vs 86.
- The RSS growth (contact_plaintext about 240 → 785 MB in 180 s) is the same as in round 5, so it is not new.

**Writer self-check:** `contact_plaintext.rs:69-84` now asserts the invite's fate per case: valid → consumed; badproof → `AuthFailed` and live; unknownid → `Ok` and live. That closes the round-5 gap where "valid" and "unknownid" could not be told apart.

**Hook scope:**
- `fuzz_has_invite` (`account.rs:869`) is inside the `#[cfg(fuzzing)] #[doc(hidden)] impl` block (`:842-908`) and is referenced nowhere else.
- It returns only a bool for an id the caller already holds. It exposes no secret.
- It maps a store error to "not live". That only causes an extra re-pair in the harness, which is harmless.

**INVARIANTS (INV-MSG-5):** the new wording ("rebuilt whenever an input consumes the re-key invite, so the Kyber step and both proof branches stay reachable for mutated inputs") is accurate, and the status stays **partial** (no nightly run recorded), which is correct.

#### 2.2 R5-2: coverage figures

All measurements used a clean HEAD build and scratch corpus copies. I used both the bare binary and the exact `cargo +nightly-2026-10-01 fuzz run -O <t> <copy> -- -runs=0` command.

| Measurement | TEST_REPORT | Reproduced |
|---|---|---|
| contact_inner, `-runs=0`, no `seed-*` | 9378 | **9378** (4 of 4 runs) |
| contact_inner, `-runs=0`, committed corpus | 9750 ("seeds add ~370") | **Bimodal over 35 runs:** 30 runs at 9886–9920, 5 at 9744–9798. 9750 is a real low-mode value; the typical gain is about 510–540. See R6-N1. |
| contact_plaintext, `-runs=0`, no `seed-*` | 10 828 | **10 828** (2 of 2) |
| contact_plaintext, `-runs=0`, committed corpus | 10 896 | **10 896 / 10 897** |
| contact_inner, 180 s | 49 300 runs, 9795 → 9952 | 50 618 runs, 9910 → 9961, no step of ≥ 15 edges |
| contact_plaintext, 180 s | 15 931 runs, 10 897 → 10 954 | 15 649 runs, 10 893 → 10 972. One +16 step at #7556, not at a re-pair. Around the periodic re-pairs (#2001–2049, #4001–4049, …) only `pulse`/`REDUCE`/`NEW` with ≤ 2 edges. |

**Teardown jump is gone:**
- I repeated the round-5 attribution run (`contact_plaintext -runs=2600 -print_pcs=1`, which crosses the first periodic re-pair): 10 897 → 10 904, only **7** `NEW_PC`s after INITED.
- There is no `drop_glue::<Fixture>`, `drop_glue::<MemoryBackend>`, zeroize or `paired` PC. The only `drop_glue` is `drop_glue<veil_core::content::CallKind>`, which is content decoding.
- The round-5 +66 at #2003 is absent. The `drop(paired())` in both initialisers works as claimed.

**History handling:** the withdrawn round-4 rows are struck through with a reason rather than silently rewritten, and the "no jump" correction is explicit. That is the right handling.

#### 2.3 R5-4: RNG contract

**PROTOCOL §4.2 "Randomness" is accurate.** I traced `create_invite` (`account.rs:264-355`) and `Invite::generate` / `seal_package` (`invite.rs:123-134, 221-227`). The id, secret, prekey ids, EC one-time and signed prekeys, both signatures, the Kyber key pair and the package nonce all draw from `rng`.

**The doc comments** on `create` (`:150-153`), `create_invite` (`:259-262`) and `redeem_invite` (`:363-366`) state the contract: "must be an OS-seeded CSPRNG… Seeded RNGs are for tests and fuzzing only". That is the substance asked for. The text was copied verbatim, though, so two of the three are slightly off; see R6-N2.

#### 2.4 R5-5: seed writers

`write_contact_inner_seeds` is deleted.

`grep` for `seed-` / `VEIL_SEED_DIR` / `VEIL_WRITE_SEEDS` finds three writers:
- the two harness writers (`seed-genuine-N`, `seed-rekey-{valid,badproof,unknownid}`), both deterministic and self-checking;
- `tests/session.rs:1139-1166`, which writes `seed-body-NN`. This name collides with nothing, and the seeds are fixture-independent plaintext inputs.

No name collisions remain.

### 3. New findings

No Critical, High, Medium or Low findings. Two optional nits:

| # | Sev | Location | Summary |
|---|---|---|---|
| R6-N1 | Nit | `docs/TEST_REPORT.md:23-25` | contact_inner's INITED with the full corpus is bimodal; the report's 9750/9795 are the low mode |
| R6-N2 | Nit | `crates/core/src/account.rs:152, :365` | The RNG doc comment was copied onto `create` and `redeem_invite` with invite-specific wording |

#### R6-N1. contact_inner's INITED is bimodal; the report shows the low mode. [HIGH: 35 runs]

**What I measured:** with the committed corpus, `-runs=0` gives 9886–9920 in 30 of 35 runs and 9744–9798 in 5 of 35. Before the seeds are added the figure is a stable 9378.

**What the report shows:**
- TEST_REPORT's 9750 ("the genuine seeds add ~370") and its 180 s INITED of 9795 are both low-mode values. They are real output, but not typical.
- The report's own "unattributed +119 at run 765" is that low-mode run catching up to the usual level, about 9912. The report notes that a re-run started at INITED 9912.
- I did not pin down the cause. Removing `seed-genuine-4` alone gives 9577 or 9804, so it depends on whether INITED's single pass happens to hit some of the PQXDH/session paths.
- This is not introduced by the diff: round 5 also saw 9764 vs 9847.

**Optional fix:** change the cell to "INITED 9886–9920 in 30 of 35 runs, 9744–9798 in 5 (low mode); the genuine seeds add ~370–540". Change the +119 note to "low-mode INITED catching up".

#### R6-N2. The RNG doc comment was copied with invite-specific wording. [HIGH: read, and checked against libsignal]

**Where it is wrong:**
- **`Account::create` (`:152`)** says "including (for invites) the ML-KEM prekey". `create` makes no invite or Kyber key; it makes the identity key and registration id.
- **`redeem_invite` (`:365`)** says the same. The redeemer creates no prekey. Its `rng` reaches `process_prekey_bundle` (`:439-447`), so it supplies the EC base key and the **ML-KEM encapsulation randomness** (`kem.rs:350` `encapsulate<R: CryptoRng>`). That randomness is just as important for the post-quantum layer, but the comment names the wrong secret.

**Why it is only a nit:** the contract itself, OS-seeded CSPRNG only, is correct on all three.

**Optional fix:**
- `create`: "…it supplies the identity key pair and registration id."
- `redeem_invite`: "…it supplies the EC base key and the ML-KEM encapsulation randomness of the new session, so a weak RNG here also weakens the post-quantum layer."

**Considered and not a finding:**
- **`fuzz_has_invite` keys on the invite record, not the Kyber prekey.** A known contact's PreKey message whose content is not a proven intro would delete the Kyber prekey (libsignal's `mark_kyber_pre_key_used`) and leave the invite live, so the harness would not re-pair. It is unreachable here: the fuzzer cannot forge a decryptable PreKey message, the only genuine one (`seed-genuine-4`) carries a valid proof, and the probe saw no such case. The product semantics of that path are pre-existing and outside this diff.
- **Re-pair loops:** see §2.1. One consumption re-pair per run, about 15 ms, no change in throughput.

### 4. Invariant status

No changes needed. INV-MSG-5 stays **partial**, and its new wording matches the probe.

### 5. What is done well

- **The R5-1 fix is minimal and correct.** It is one fuzz-only predicate, checked before each input in `contact_plaintext`, which removes the order dependence entirely. The writer now distinguishes all three proof outcomes by the invite's fate rather than by the return value alone.
- **The R5-3 test is a strong oracle.** It compares the whole sealed package as well as the Kyber key, so it pins every invite secret to the injected RNG, and it kills the exact mutant from round 5.
- **R5-2 was handled honestly.** Non-reproducible rows are withdrawn and struck through with a reason, a step the author could not attribute is reported as such instead of explained away, and the new contact_plaintext and no-seed figures reproduce exactly.
- **The teardown-baseline change** (`drop(paired())`) removed the residual +66, as `-print_pcs` confirms.

### 6. Conditions

None. R6-N1 and R6-N2 are optional nits and can go in with any later docs change.

VERDICT: PASS

---

## Phase 3 review, round 1 (2026-10-19)

**Reviewer:** code-reviewer agent (Agent tool, `subagent_type: "code-reviewer"`, model override `opus`), adversarial brief. Scope: `git diff 0958b70^..HEAD` (HEAD = `80043a9`). Report follows verbatim.

# Phase 3 review: round 1

## Verdict: FAIL
fmt, clippy and the tests pass, and so do the smoke test against the container, `cargo deny` and `cargo vet`. The wire layer, the auth handshake, token hashing and invite atomicity are sound. Two High findings still block Phase 3. I reproduced both.

- **P3-1:** the relay is OOM-killed under the shipped `mem_limit: 512m` once it holds about 600 MB of envelopes. The cause is redb's default 1 GiB in-process cache plus the full-table scan in `sweep`. Anyone can trigger it, because mailbox creation is open. `restart: unless-stopped` and the immediate first sweep tick then turn it into a crash loop.
- **P3-2:** delivery-token rows whose hash starts with 16 `0xFF` bytes survive `DeleteMailbox` and the idle sweep. An anonymous client can use this to grow the database without bound, outside every quota.

Neither is a one-line fix with an existing test: P3-1 needs a cache setting, a sweep redesign and a memory test. So the verdict is FAIL, not PASS WITH CONDITIONS. Six Medium findings add test soundness gaps (two tests that the docs rely on cannot fail for the property they claim), denial-of-service gaps with no timeouts, and a coturn config that lets anyone relay UDP to any port on the host.

## Commands I ran and their results

```text
$ cargo fmt --all --check                                         → exit 0
$ cargo clippy --workspace --all-targets --locked -- -D warnings  → exit 0
$ cargo test --workspace --locked                                 → exit 0
  veil_core 74 passed | secrets 3 | session 22 passed, 1 ignored | veil_relay (lib) 10 | relay.rs 10 | smoke 0 (1 ignored) | veil_wire 5
$ cargo deny --locked check   → advisories ok, bans ok, licenses ok, sources ok
$ cargo vet --locked          → Vetting Succeeded (43 fully audited, 5 partially audited, 207 exempted)
$ cargo +nightly-2026-10-01 fuzz run -O wire_frames corpus/wire_frames -- -max_total_time=60 -max_len=70000
  #2166798 DONE cov: 1827 ft: 5743 ... exec/s: 35521   Done 2166798 runs in 61 second(s)   (0 crashes; new corpus files removed afterwards)
```

Mutation checks. Each mutant was applied, the test run, then reverted with `git checkout`.

```text
M1 store.rs ack(): drop sub_stat(ENVELOPE_BYTES)               → envelope_bytes_are_capped_and_released FAILED  (good)
M2 store.rs sweep(): drop env_freed += len for expired rows    → envelope_bytes_are_capped_and_released FAILED  (good)
M3 server.rs Deposit handler: tracing::warn!(hex(mailbox))     → relay_logs_nothing_about_clients FAILED        (good; the documented mutant)
M4 store.rs Store::deposit: tracing::warn!(hex(mailbox))       → relay_logs_nothing_about_clients ... ok        (SURVIVES, P3-6)
M5 tls.rs: with_protocol_versions(&[TLS13, TLS12])             → tls_is_1_3_only_and_pinned ... ok              (SURVIVES, P3-7)
```

Memory and sweep cost. A scratch crate outside the repo called the real `veil_relay::store::Store`. The DB was on tmpfs because the root disk had only 1.2 GB free.

```text
$ bench fill db.redb 9600     (9 600 × 64 KiB envelopes = 630 MB payload; file 1.48 GB)
filled 9600 in 8.86s          VmHWM: 1086124 kB
$ bench sweep db.redb          (fresh process, nothing expired)
sweep removed 0 in 980ms; second sweep 410ms     VmHWM: 1053444 kB
$ docker run --memory=512m --memory-swap=512m ... veil-relay:local (bench sweep)  → OOMKilled=true Exit=137
$ docker run --memory=2g ...                                                     → exit 0, VmHWM 1084432 kB
```

Token-row leak (P3-2), same scratch crate:

```text
normal token after delete+recreate: Err(Unauthorized)
FF-prefixed token after delete+recreate: Ok(1)
FF-prefixed token after idle sweep+recreate: Ok(1)
```

Deployment, `deploy/` exactly as the README describes (`.env`, `secrets/turn_secret` 0644 in a 0700 dir, `gen-cert`, `up -d`):

```text
SPKI SHA-256 pin: fca73b1b…; coturn running; relay running
smoke: test deployed_relay_round_trip ... ok
coturn /proc/<pid>/status: Uid 65534, CapPrm 0, CapEff 0, CapBnd 0x400, NoNewPrivs 1
relay: Uid 65532, CapEff 0, ReadOnly=true CapDrop=[ALL] no-new-privileges, Memory=536870912, SigCgt 0x100000442 (SIGTERM not caught)
turnutils_uclient -c -e 192.0.2.2 -r 40000 (relay-minted creds; 192.0.2.0/24 is in denied-peer-ip)
  → host UDP listener on 192.0.2.2:40000: "udp packets received = 5"
$ time docker compose stop relay → real 0m10.307s, Exit=137, no "veil-relay stopped" line
$ docker compose down -v; rm -rf deploy/.env deploy/secrets; git status --short → (empty)
```

## Findings

### Critical
None.

### High

**P3-1: The relay is OOM-killed and crash-loops once it stores about 600 MB of envelopes (redb 1 GiB default cache, full-table sweep, 512m limit).** `crates/relay/src/store.rs:237-238` (`Database::create` with defaults), `store.rs:639-737` (`sweep`), `server.rs:289-298` (`sweep_loop`), `deploy/docker-compose.yml` (`mem_limit: 512m`).
- **What is wrong:**
  - redb 4.4.0's default cache is 1 GiB (`redb-4.4.0/src/db.rs:2045`), held in the process heap.
  - `sweep` runs every 60 s in one write transaction. It calls `env.retain(...)`, which reads every envelope value. Then it iterates all mailboxes and all blobs.
  - Scanning 630 MB of envelopes drives RSS to 1.05 GB. Under the compose limit the process is OOM-killed (`OOMKilled=true`, reproduced above). Deposits alone also reached 1.08 GB RSS.
  - `tokio::time::interval` fires its first tick immediately. After `restart: unless-stopped` the sweep runs again at once, so the relay crash-loops. Expiry only happens in the sweep, so the data never shrinks and the loop never ends.
  - The sweep also holds the single redb writer for the whole scan (0.4–1 s on tmpfs, much longer on an SD card), which blocks every deposit, ack, auth touch and creation.
- **Exploit:** anyone creates 2 mailboxes, registers tokens and deposits about 10 000 × 64 KiB envelopes (well under the 5 000-per-mailbox and 4 GiB caps). Within a minute the relay dies and stays down. It also happens under ordinary load. This contradicts README "1 GB RAM is plenty" and TEST_REPORT "the sweeper scans all envelopes once a minute (fine at Pi scale)".
- **Required fix:**
  - Open the DB with `redb::Builder::new().set_cache_size(..)`: a bounded, configurable size such as 64–128 MiB (`VEIL_DB_CACHE_MB`), consistent with `mem_limit`.
  - Replace the value-reading full scans with an expiry index table, e.g. `EXPIRY: expires_be ‖ mailbox ‖ seq → ()` for envelopes and the same for invites and blobs. Range-delete `..=now` in bounded batches, each its own short transaction.
  - Fix the README and TEST_REPORT claims.
- **Test:**
  - A store test that fills N records and asserts the sweep touches only expired keys, for example a counter in a test-only hook, or timing that does not scale with live data.
  - A CI step in `relay-deploy` (or an `#[ignore]` soak test run there) that loads at least 1 GB of envelopes into the container and runs past two sweep intervals. It asserts `docker inspect -f '{{.State.OOMKilled}}'` is `false` and the restart count is 0.

**P3-2: Token rows with a hash starting `FF×16` survive mailbox deletion and idle expiry. This allows unbounded, unaccounted disk growth.** `store.rs:212-215` (`prefix_end`), used at `store.rs:319-321` (`delete_mailbox`) and `store.rs:685-686` (idle sweep).
- **What is wrong:**
  - `prefix_end(id)` returns `id ‖ FF×16` (48 bytes) and is used as an exclusive upper bound.
  - TOKENS keys are `id ‖ h` (64 bytes), and `h` is chosen freely by the client in `UpdateTokens.add`.
  - Any key with `h[0..16] == FF×16` sorts above the bound, so it is never deleted. Nothing else ever removes TOKENS rows, and they count against no quota.
  - Reproduced above: the row still authorises deposits after delete+recreate and after the idle sweep.
- **Exploit:**
  - Loop: CreateMailbox → Authenticate → UpdateTokens add 512 hashes of the form `FF×16 ‖ random16` → DeleteMailbox.
  - Even at the relay-wide creation rate (1/s), that leaks about 44 M rows (several GB) per day.
  - Nothing reclaims them. When the disk fills, every redb write fails and the relay is down for good. This bypasses "the caps are what keep a stranger from filling the disk" (README).
  - ENVELOPES and BLOB_CHUNKS are not affected today, because their suffixes are 8 and 4 bytes.
- **Required fix:** make the upper bound cover every possible suffix. Either `prefix_end = id ‖ [0xFF; 33]`, or better, compute the lexicographic successor of the 32-byte prefix, or use an inclusive `..=id ‖ [0xFF; suffix_len]` per table.
- **Test:** a store unit test that adds tokens `[0xFF;32]` and `FF×16 ‖ 00×16`, then deletes the mailbox (and separately idle-sweeps it). It asserts that a test-only `count_rows(TOKENS)` is 0, and that a deposit with those hashes into a recreated mailbox returns `Unauthorized`.

### Medium

**P3-3: No write timeout. A client that stops reading pins a connection slot forever, plus about 2 MB or more of buffered response.** `server.rs:323-342`.
- **What is wrong:**
  - Only `source.next()` is wrapped in the idle timeout.
  - `sink.send(...).await` (lines 332 and 337) has no timeout. Once the peer's TCP window is full, the task blocks forever inside `send`. It holds its semaphore permit and the fully encoded `ServerFrame` in tungstenite's out buffer, up to `MAX_FRAME` ≈ 2.1 MB for a 32 × 64 KiB fetch.
- **Exploit:** one attacker fills its own mailbox with 32 × 64 KiB envelopes, then opens connections that authenticate, send `Fetch{limit:32}` and never read. About 150–250 such connections reach the 512m limit and OOM the relay. 1024 connections hold every slot permanently, with no keep-alive needed. This contradicts INV-ROB-1 "timeouts".
- **Required fix:**
  - Wrap every `sink.send` in `tokio::time::timeout(write_timeout, ...)` and hang up on expiry.
  - Set `WebSocketConfig::max_write_buffer_size`.
  - Bound total in-flight response bytes relay-wide, e.g. a byte semaphore of 64 MiB acquired before building a `Fetch` or `BlobGet` reply.
- **Test:** an integration test with `max_connections = 1` and a short `write_timeout`. Client A authenticates, fetches 32 × 64 KiB and never reads. The test asserts that client B can connect within `write_timeout + ε`.

**P3-4: One anonymous client can take the whole connection cap indefinitely, and this is not documented.** `server.rs:264-283`, `Config::default` (`max_connections: 1024`, `idle_timeout: 5 min`).
- **What is wrong:** the slot is taken before the TLS handshake. A connection needs no authentication to stay open, because a WS ping every under-5 minutes resets the idle timer. Nothing limits connections per source.
- **Exploit:** one host opens 1024 TLS+WS connections and pings each every 4 min (about 4 pings/s in total). Every legitimate client is then refused. THREAT_MODEL §5, README "Known limits" and ADR-0010 cover storage-cap exhaustion but not this cheaper, total outage.
- **Required fix:**
  - Add an in-memory per-peer-address concurrent-connection cap (e.g. 32). Keep the count only while the connection is open: never logged, never persisted, entry removed at zero. This keeps INV-META-2, which is about storage and logs; the relay already holds IPs in memory (README).
  - Add a short pre-auth idle timeout, e.g. 30 s until the first successful Authenticate or Deposit.
  - If the project rejects per-IP state on principle, state this DoS explicitly in THREAT_MODEL §5 and the README instead.
- **Test:** with a per-source cap of 2, a third connection from 127.0.0.1 is refused. A connection that never authenticates is closed after the pre-auth timeout.

**P3-5: Anyone can drain the relay-wide CreateMailbox bucket at about 1 request/s, blocking onboarding and the mandatory 7-day mailbox rotation for everyone.** `server.rs:447-461`.
- **What is wrong:** `create_mailbox.allow()` is consumed before any validation, including for invalid keys and for ids that already exist (Conflict). The bucket is global (burst 20, 1/s).
- **Exploit:** one connection sends CreateMailbox with a bad key once per second. Every legitimate creation gets `RateLimited`. Rotation (PROTOCOL §2, every 7 days) also fails for all users.
- **Required fix:**
  - Validate first (key decodes, mailbox count, id free), then consume.
  - Add a per-connection creation limit.
  - Consider a small proof-of-work, or an optional operator gate such as a registration secret, for creation.
  - Document the remaining starvation risk.
- **Test:** flood the bucket with invalid-key requests, then assert a valid creation still succeeds. Add a per-connection-limit test.

**P3-6: `relay_logs_nothing_about_clients` cannot see anything logged from the store layer, and does not exercise what INV-META-2 says it does.** `crates/relay/tests/relay.rs:620-691`.
- **What is wrong:**
  - The test uses `tracing::subscriber::set_default`, which is thread-local.
  - Every `Store` call runs on `spawn_blocking` threads (`server.rs:211-219`), so those events go to no subscriber in the test. In production, `main.rs` installs a global subscriber and they would be printed.
  - Mutant M4 (logging the mailbox id inside `Store::deposit`) survives.
  - INV-META-2 says the session covers "blobs". The test never calls BlobUploadToken, BlobPut, BlobGet or TurnCredentials.
- **Required fix:** move the test to its own test binary (e.g. `tests/logs.rs`) and install the capture with `tracing::subscriber::set_global_default`. Add blob upload/download and TURN credentials to the session. Record M4 as a required mutant.
- **Test:** M3 and M4 must both fail the test.

**P3-7: `tls_is_1_3_only_and_pinned` passes even if the relay accepts TLS 1.2.** `relay.rs:528-545`, `tests/common/mod.rs:151-160`.
- **What is wrong:** the TLS 1.2 client uses `PinVerifier`, whose `verify_tls12_signature` always returns `Err`. The handshake therefore fails on the client side whatever the server negotiates. Mutant M5 (server offering TLS13 + TLS12) survives. INV-NET-2 and TEST_REPORT cite this test as proof of "TLS 1.3 only". The production code is correct today; the test does not guard it.
- **Required fix:**
  - Give the TLS 1.2 probe a verifier that accepts TLS 1.2 signatures: pin check plus `rustls::crypto::verify_tls12_signature`.
  - Assert the specific failure: `rustls::Error::AlertReceived(AlertDescription::ProtocolVersion)` or the equivalent peer-incompatible error.
  - Add a positive control: the same verifier with TLS 1.3 connects.
- **Test:** M5 must fail it.

**P3-8: coturn relays UDP to every port on the server's own addresses, for anyone. The README says nobody can use it to reach your LAN.** `deploy/coturn/entrypoint.sh:27-31`, `deploy/README.md:162-169`.
- **What is wrong:**
  - The entrypoint adds `allowed-peer-ip` for the public and the private address, with no port restriction (coturn cannot express one).
  - TURN credentials need only an authenticated mailbox, and mailbox creation is open to anyone. So any internet user can relay UDP to any service on the relay host.
  - Reproduced: relay-minted credentials delivered 5 datagrams to 192.0.2.2:40000, inside a denied range, apart from the allow line.
  - On a home Pi (option B, `public/192.168.1.20`) this exposes LAN-bound UDP services such as Pi-hole DNS, mDNS, SNMP and WireGuard/Tailscale ports through the TURN server.
  - The README line "Only clients holding relay-minted credentials (… authenticated mailboxes only)" also suggests a restriction that does not exist. The TURN server is an open UDP relay to the public internet for anyone, and on a home deployment abuse traffic leaves from the operator's IP.
- **Required fix:**
  - Allow only what relayed calls need: drop the private-address allow unless it is shown to be required.
  - Ship a documented host firewall rule limiting coturn's traffic to its own addresses to the relay port range, e.g. nftables `meta skuid 65534 ip daddr { <own IPs> } udp dport != 49160-49259 drop`.
  - Correct the README and THREAT_MODEL: anyone can obtain TURN credentials, and the host's own UDP services are in scope.
- **Test:** extend the CI `relay-deploy` step with a host UDP listener on a port outside 49160–49259 and `turnutils_uclient -e $TURN_IP -r <that port>`. Assert 0 datagrams are received.

### Low

**P3-9: The relay ignores SIGTERM, so every `docker stop` or upgrade is a SIGKILL.** `main.rs:314-316`.
- **What is wrong:** only `ctrl_c` (SIGINT) is handled. As PID 1, SIGTERM is ignored. Reproduced: `docker compose stop` took 10.3 s, exit 137, and no "stopped" line was logged.
- **Consequence:** redb has to recover after each unclean shutdown. With P3-1 that recovery can itself exceed the memory limit.
- **Fix:** also handle `tokio::signal::unix::signal(SignalKind::terminate())`, or add `STOPSIGNAL SIGINT` to the Dockerfile. Drain connections, then drop the DB.
- **Test:** in CI, `docker compose stop relay` exits 0 within 3 s and logs "veil-relay stopped".

**P3-10: Incomplete blobs are not reclaimed when their upload token expires, despite the comment.** `store.rs:711-720`.
- **What is wrong:** the comment says "and incomplete blobs whose token is gone", but only `meta.expires <= now` (30 days) is checked. An abandoned upload holds up to 100 MiB of the blob quota for 30 days instead of about 24 h.
- **Fix:** give incomplete blobs the token's expiry and extend it to `blob_ttl` on completion, or delete incomplete blobs whose bound token is gone.
- **Test:** upload 1 of 2 chunks, sweep past `upload_token_ttl`, assert the blob and its bytes are freed.

**P3-11: `DeleteMailbox` leaves other connections authenticated and subscribed for that id.** `server.rs:566-571`.
- **What is wrong:** only this connection's `authed` set and none of the subscribers are cleared. If the id is recreated (by the owner, or by anyone after the idle sweep), stale connections can Fetch, Ack and UpdateTokens on the new mailbox. This needs id reuse, so the impact is low.
- **Fix:** keep a per-mailbox generation or auth key in `authed` and re-check it in `require_auth`, or broadcast a revocation to connections.
- **Test:** A authenticates on two connections, deletes on one, recreates with a new key; the other connection's Fetch returns `Unauthorized`.

**P3-12: The TURN secret's first in-memory copy is not zeroized.** `main.rs:271-274`.
- **What is wrong:** `std::fs::read` returns a plain `Vec` that is dropped without wiping, and only the trimmed copy is `Zeroizing`.
- **Fix:** `let raw = Zeroizing::new(std::fs::read(&path)?);` and then trim from `raw`.
- **Test:** a code review check is enough.

**P3-13: Several doc claims are inaccurate.**
- README "Rate limits slow this down" and THREAT_MODEL §5 "slow this down without stopping it": with 512 tokens × burst 60 per mailbox and 20 mailboxes per burst, the 4 GiB envelope cap fills as fast as the uplink allows.
- README "1 GB RAM is plenty" (see P3-1).
- INV-ROB-1 "timeouts" (no write timeout, P3-3).
- INV-META-2 "full session (… blobs …)" (P3-6).
- INV-NET-2 "a TLS 1.2-only client is refused" as tested evidence (P3-7).
- **Fix:** correct these with the fixes above.

## Claims I checked and found accurate
- The test, clippy and fmt results and counts in the TEST_REPORT Phase 3 section reproduce exactly (74/3/22+1/10/10/0+1/5). The `cargo deny` result and the `cargo vet` numbers (43/5/207) reproduce.
- The documented mutation checks reproduce: an async-path log of the mailbox id fails the log test; dropping byte releases fails `envelope_bytes_are_capped_and_released`. I also killed the ack and expiry-path variants.
- **`wire`:**
  - The size check comes before parsing.
  - Canonical re-encode is required, so unknown, duplicate and out-of-order fields are rejected.
  - `v == 1` is enforced and `id != 0` for client frames.
  - Every request field is length- or range-checked.
  - `NewEnvelopes` must have `id == 0`.
  - Envelope seq ≤ last_seq.
  - TURN URLs must be `turn:`/`turns:` ASCII.
  - `MAX_CLIENT_FRAME` = 64 KiB + 1 040, matching PROTOCOL §14.
  - A 32-envelope fetch fits `MAX_FRAME`.
  - The fuzz target ran 2.17 M runs in 61 s with 0 crashes.
- **Auth:**
  - The nonce is removed before any check (single use), is per connection, and is bound to the mailbox.
  - The signed message includes the relay SPKI pin.
  - The ±120 s skew applies both to `unix_secs` and to challenge age.
  - `verify_strict` is used, keys are checked at creation, and auth is required for UpdateTokens, Fetch, Ack, DeleteMailbox, PutInvite, BlobUploadToken and TurnCredentials.
- Delivery and upload tokens are stored only as domain-separated SHA-256 hashes. Unknown mailbox and unknown token both return `Unauthorized`.
- TakeInvite reads and deletes in one write transaction. The invite TTL is capped. PutInvite does not store the mailbox.
- Every store mutation is one redb transaction. Counter updates are consistent on the ack, delete, expiry and idle-expiry paths for envelopes, apart from the P3-2 key-range bug. Records are decoded with checked offsets.
- The peer address from `accept()` is dropped. Nothing IP-keyed exists. The deployed relay logged exactly one startup line and coturn logged nothing.
- `#![forbid(unsafe_code)]` is present in `wire/lib.rs`, `relay/lib.rs` and `relay/main.rs`. Secret-holding types (`TurnConfig`, `Config`, `Shared`, `Store`) have redacting or opaque `Debug` and no `Clone` or `Serialize`.
- **TLS:**
  - The server config is TLS 1.3 only with ring.
  - `gen-cert` writes `key.pem` with mode 0600 and `create_new`, refuses to overwrite (also in the container), and prints a pin equal to the loaded pin.
  - A cert/key mismatch is refused.
  - A wrong pin is refused, both in-process and against the container.
- TURN credentials (`expiry:hex16`, base64 HMAC-SHA1) are accepted by coturn 4.7.0: allocation succeeded with relay-minted credentials, and wrong passwords and private peers were refused, per CI and my run.
- **Containers:**
  - The relay runs as uid 65532 with a read-only root, `CapDrop=[ALL]`, `no-new-privileges` and CapEff 0.
  - coturn runs as uid 65534 with CapPrm and CapEff 0, CapBnd only `NET_BIND_SERVICE`, and NoNewPrivs 1. This matches the README claim that the effective set is empty.
  - Base images are digest-pinned.
- **GitHub Actions:** the `relay-deploy` job uses a SHA-pinned checkout with `persist-credentials: false` and inherits the workflow-level `permissions: contents: read`. Its log-line and coturn-403 assertions can fail.

## Claims I could not verify
- arm64 / Raspberry Pi build and run. The README says amd64 only.
- Image build reproducibility from the committed Dockerfile. I did not rebuild; the existing `veil-relay:local` image was used.
- The "7.6 M runs in 180 s" and the earlier 180 s fuzz figures in INV-MSG-5 and TEST_REPORT. I ran 60 s only. Any ≥ 1 h nightly fuzz run (none recorded).
- The `relay-deploy` CI job as actually executed on GitHub runners.
- Sweep and recovery timings on real SD-card storage. My measurements were on tmpfs, so real-disk times will be longer than those shown.

---
Housekeeping: the working tree is clean (`git status --short` is empty). I ran `docker compose down -v` and removed `deploy/.env` and `deploy/secrets`. I removed the new fuzz corpus files and my scratch DB in `/dev/shm`. I stopped the dockerd I had started; a defunct `dockerd` process entry remains. A container `eager_chatterjee` (coturn, created 17:07, before this review) was left untouched. The scratch benchmark crate is at `/tmp/claude-0/-home-user-ataraxia/929457e9-49df-558b-9ee2-363e38c8130c/scratchpad/bench`. Nothing was committed or pushed.

---

## Phase 3 review, round 2 (2026-10-19)

**Reviewer:** code-reviewer agent (Agent tool, `subagent_type: "code-reviewer"`, model override `opus`), adversarial brief. Scope: round-1 fixes in `af98aa9` plus `git diff 0958b70^..HEAD`. Report follows verbatim.

# Phase 3 review: round 2

## Verdict: FAIL
The two round-1 High findings are fixed, and the fixes hold up.
- **P3-1:** the expiry index is kept consistent on every insert and remove path. Stale index entries are harmless, because each one is re-checked against the record's due time. The worst case, a sweep batch of idle mailboxes, freed 563 MiB in one transaction in 407 ms with a 70 MB peak.
- **P3-2:** `prefix_end` covers every key length in every table.
- fmt, clippy (`-D warnings`) and the full test suite pass. `cargo deny` and `cargo vet` pass. 11 mutants of round-1 regression tests were all killed by the intended tests.

The gate still fails on one new High finding, P3R2-1. Upload tokens have no count limit at all, and delivery-token rows are limited only by 512 per mailbox × 100 000 mailboxes. A single anonymous host can therefore fill the disk with tens of GB that sit outside every byte cap. That contradicts the README's "these caps are what keep a stranger from filling the disk", which is the same class of problem as round-1 P3-2.

Five of the round-1 fixes are only partial. I reproduced each gap:
- **P3-3 / P3-4:** 31 non-reading connections from one source hold the whole 64 MiB response budget. Every other client's `Fetch` is refused (10/10).
- **P3-5:** one host drains the relay-wide creation budget by reconnecting: 20 creations in 78 ms, then the victim gets `RateLimited`.
- **P3-8:** the "required" nft rule does not stop TURN from reaching a UDP service that Docker publishes on the host. 5/5 packets were echoed, which covers the README's own example of a Pi-hole in Docker.
- **P3-6:** the log test does not notice a `?id` (Debug) log of the mailbox id, or a log of the stored size.
- **P3-11:** a connection whose authentication was revoked still receives `NewEnvelopes` pushes for the re-created mailbox.

## Round-1 findings: status
| ID | Status | Evidence |
|---|---|---|
| P3-1 | **Fixed** | Bounded cache in `open_with_cache`. The sweep reads only due `EXPIRY` keys, 256 per transaction. Every insert and remove path pairs `index_put` with `index_del`, and `expire_one` re-checks the due time, so stale entries are only dropped. I found no full scans: fetch's skip of expired rows is bounded by the 5 000-envelope mailbox cap. `EXPIRY` holds one entry per live record, so it grows only as fast as the records themselves (see P3R2-1). Bench, real disk, worst case of 2 idle mailboxes holding 9 000 × 64 KiB of live envelopes: one batch removed everything in 407 ms, VmHWM 70 148 kB. Mutant R2-M2 (batches never continue) is killed. Container: 300 MiB soak, `docker stats` 90.46 MiB / 512 MiB. |
| P3-2 | **Fixed** | `prefix ‖ FF×33` is above every key `prefix ‖ s` with \|s\| ≤ 32. That covers TOKENS (32-byte suffix), ENVELOPES (8), BLOB_CHUNKS (4), the fetch range `id‖seq+1 .. id‖FF×33`, and the full-ack range. EXPIRY's `due_keys` uses an exclusive `kind‖now+1` bound, plus a separate `now == u64::MAX` branch. Mutant R2-M1 (`FF×16`) is killed: "delete: rows left behind". |
| P3-3 | **Partially fixed** | The write timeout works: mutant R2-M10 (no timeout on replies) fails `a_client_that_stops_reading_is_dropped` after 16.3 s. But the response budget can be held entirely by one source (P3R2-2). |
| P3-4 | **Fixed** (with residual risks P3R2-2, P3R2-7) | The per-source cap holds: mutant R2-M4 is killed. The pre-auth deadline holds: mutant R2-M11 (Ping sets `established`) is killed. A connection sending only Pings, either WebSocket or application-level, really does close. IPv4-mapped IPv6 addresses fold to the IPv4 key. `established` can be earned cheaply by authenticating any mailbox the attacker owns; this is documented. |
| P3-5 | **Partially fixed** | Bad requests no longer spend the relay-wide budget, and the test passes. But the per-connection limiter resets on every reconnect, so one host drains the budget with valid requests (P3R2-3). |
| P3-6 | **Partially fixed** | The global subscriber and its positive control work, and M4 (R2-M7, hex in `Store::deposit`) is killed. Debug-formatted ids and sizes survive (R2-M8, R2-M9) → P3R2-4. |
| P3-7 | **Fixed** | Mutant R2-M6 (server offers TLS 1.3 + 1.2) fails with "TLS 1.2 must be refused by the relay". |
| P3-8 | **Partially fixed** | A plain host listener on 192.0.2.2:40000 received 0 packets, and the nft counter counted 1 drop. A UDP port published by Docker is reached 5/5, because Docker's `nat OUTPUT` DNAT runs before the filter hook (P3R2-5). The rule handles IPv6, since it is in the `inet` family. TCP is out of scope because of `no-tcp-relay`. "Required" is enforced only in CI, and persistence across reboots is optional in the README. Dropping the private `allowed-peer-ip` is **not** a regression: with `external-ip=198.51.100.7/192.0.2.2`, the `-y` client↔client relay lost 0 packets, because coturn maps its own public address internally. |
| P3-9 | **Fixed** | `docker compose stop relay`: 310 ms, ExitCode=0, "veil-relay stopped" logged. |
| P3-10 | **Fixed** | Mutant R2-M5 (incomplete blob gets `blob_ttl`) fails `abandoned_uploads_expire_with_their_token`. |
| P3-11 | **Partially fixed** | `require_auth` re-checks the key: mutant R2-M3 is killed. Push subscriptions are not revoked (P3R2-6). |
| P3-12 | **Fixed** | `main.rs`: `std::fs::read(&path).map(Zeroizing::new)`, and the trimmed copy is `Zeroizing` too. |
| P3-13 | **Partially fixed** | The round-1 claims are corrected. The new text contains several claims that are false (P3R2-3, P3R2-4, P3R2-5, P3R2-8). |

## Commands I ran and their results
```text
$ cargo fmt --all --check                                         → fmt exit 0
$ cargo clippy --workspace --all-targets --locked -- -D warnings  → clippy exit 0
$ cargo test --workspace --locked                                 → test exit 0
  veil_core 74 | secrets 3 | session 22 (+1 ignored) | veil_relay lib 14 | logs.rs 1 | relay.rs 15 | smoke 0 (2 ignored) | veil_wire 5
$ cargo deny --locked check → advisories ok, bans ok, licenses ok, sources ok
$ cargo vet --locked        → Vetting Succeeded (43 fully audited, 5 partially audited, 207 exempted)
```
Mutation checks. Each mutant was applied with an exact-match replace, the named test was run, and the file was then restored with `git checkout`.
```text
R2-M1  prefix_end FF×16                         → ff_prefixed_tokens_are_deleted_with_their_mailbox FAILED ("delete: rows left behind")
R2-M2  sweep: more = false                      → sweep_touches_only_due_records FAILED
R2-M3  require_auth accepts any current key     → deleting_a_mailbox_revokes_other_connections FAILED
R2-M4  per-source cap u32::MAX                  → connections_are_capped_per_source_and_must_authenticate FAILED
R2-M5  incomplete blob expires = now+blob_ttl   → abandoned_uploads_expire_with_their_token FAILED ("the abandoned blob")
R2-M6  server offers TLS13+TLS12                → tls_is_1_3_only_and_pinned FAILED
R2-M7  tracing::warn!(m = %hex(id)) in Store::deposit → relay_logs_nothing_about_clients FAILED
R2-M8  tracing::warn!(m = ?id) in Store::deposit      → relay_logs_nothing_about_clients ... ok   (SURVIVES)
R2-M9  tracing::info!(bytes = value.len()) in Store::deposit → relay_logs_nothing_about_clients ... ok (SURVIVES)
R2-M10 reply send without write timeout         → a_client_that_stops_reading_is_dropped FAILED (16.30 s)
R2-M11 Request::Ping sets established           → connections_are_capped_per_source_and_must_authenticate FAILED
```
Temporary probe tests, written as `crates/relay/tests/r2_probe.rs` and deleted afterwards, using the default `Config`:
```text
PROBE budget: victim fetch(limit 32) refused 10/10 over 5.03s by 31 non-reading connections from one source
              (with 30 connections: 0/10, since 30 × 2 050 KiB leaves room for one more reservation)
PROBE push:   revoked connection received NewEnvelopes last_seq=[1, 2]
PROBE create: one host created 20 mailboxes in 78.2ms over sequential connections; victim got Err(RateLimited)
```
Store bench, using the scratch crate with the real `veil_relay::store::Store` on real disk. The DBs were deleted afterwards.
```text
idlefill 9000 (mailboxes created at T, deposits at T+59d) → idle-filled 9000 in 10.07s (2 mailboxes), VmHWM 70716 kB
  file: apparent 2155876352 B, allocated (du) 1154588 KiB
idlesweep (T+60d+120 s)  → idle sweep removed 2 (records counted) in 406.97ms, VmHWM 70148 kB
uploadtok 100000         → 100000 upload tokens in 36.22s (2 760 commits/s); file 15 863 808 B (≈159 B per token)
tokrows 102400           → 102400 delivery-token rows in 200 mailboxes; file 16 846 848 B (≈164 B per row)
```
Deployment, following deploy/README:
- Setup: `.env` with `TURN_EXTERNAL_IP=192.0.2.2`, `secrets/turn_secret` 0644 in a 0700 directory, `gen-cert`, `nft -f firewall/veil-turn.nft`, `up -d`, using the existing `veil-relay:local` image without a rebuild.
```text
smoke deployed_relay_round_trip ... ok
uc -y -c -n 20                                   → Total lost packets 0 (0.000000%)
host listener 192.0.2.2:40000, uc -e 192.0.2.2 -r 40000 → host listener: udp packets received = 0; nft counter packets 1 … drop
docker run -p 40001:3480/udp … turnutils_peer;  uc -c -e 192.0.2.2 -r 40001
   → tot_send_msgs=5, tot_recv_msgs=5, Total lost packets 0 (0.000000%)
   → nft veil_turn counter unchanged (1); ip nat DOCKER: "udp dport 40001 counter packets 1 … dnat to 172.17.0.2:3480"
same rule at `priority mangle`: same probe → Total lost packets 5 (100%); uc -y client↔client → lost 0
TURN_EXTERNAL_IP=198.51.100.7/192.0.2.2: uc -y → lost 0;  uc -e 198.51.100.7 -r 40001 → lost 0 (Docker service reached)
soak VEIL_SOAK_MB=300 → deposited 4800 × 64 KiB in 8.17s; docker stats 90.46MiB / 512MiB
relay log: exactly 1 line (startup) after smoke + soak; coturn log: empty
docker compose stop relay → 310 ms, ExitCode=0 OOMKilled=false, "veil-relay stopped"
```
Cleanup:
- I ran `docker rm -f r2-udp-svc`, `docker compose down -v`, `rm -rf deploy/.env deploy/secrets` and `nft delete table inet veil_turn`.
- I removed the probe file and the bench DBs.
- `git status --short` is empty. Nothing was committed or pushed.

## New findings
### Critical
None.

### High
**P3R2-1: Upload tokens and delivery-token rows are outside every storage cap, so one anonymous host can fill the relay's disk.**
- **Where:**
  - `crates/relay/src/store.rs:612` (`add_upload_token` has no quota of any kind);
  - `store.rs:428` (`update_tokens` is limited only per mailbox);
  - `server.rs:771` (`BlobUploadToken` is limited only by the per-mailbox rate, burst 20 then 0.1/s);
  - the `Quotas` defaults in `server.rs`.
- **What is wrong:**
  - Each upload token costs about 159 B on disk (measured), including its `EXPIRY` row, and lives 24 h.
  - Nothing counts or caps the number of upload tokens, so their total is rate × 24 h.
  - The rate grows linearly with the number of mailboxes the attacker owns. Mailboxes are free to create, at about 1/s from one host (P3R2-3).
  - Delivery-token rows (about 164 B each, measured) are capped at 512 per mailbox × 100 000 mailboxes = 51.2 M rows, or about 8.4 GB. They live until idle expiry, which is 60 days.
  - Neither kind counts toward `max_envelope_bytes_total` or `max_blob_bytes_total`.
- **Exploit, one IPv4 host:**
  1. Create mailboxes at about 1/s by reconnecting.
  2. After about 10 h (36 000 mailboxes), each mailbox's 0.1/s token rate adds up to 3 600 tokens/s. One source's 32 connections × 50 frames/s caps this at about 1 600/s.
  3. 1 600/s × 86 400 s × 159 B ≈ 22 GB of live upload tokens, refilled continuously.
  4. Add up to 8.4 GB of token rows. This is far beyond the "~18 GB" the README sizes for the caps.
  5. When the disk is full, every redb write fails: deposits, auth touches and creations.
  6. Each token is also one fsync'd commit (2 760/s on this disk). On an SD card the attacker saturates the single writer, which stalls every legitimate write before the disk even fills.
- **Required fix:**
  - Add a relay-wide cap on live upload tokens, tracked in `STATS` and released on completion and expiry. Add a small per-mailbox cap on outstanding upload tokens.
  - Either cap total token rows relay-wide or charge them to a byte budget. Alternatively, reduce `max_tokens_per_mailbox × max_mailboxes` to a product the docs size for.
  - Add the resulting worst case to README disk sizing.
- **Test:**
  - A store unit test showing that `add_upload_token` past the cap returns `Quota`, and that expiry or completion frees a slot.
  - A test of the relay-wide token-row cap.
  - The mutant "skip the count check" must fail them.

### Medium
**P3R2-2: One source holds the entire relay-wide response budget, so every other client's `Fetch` is refused.**
- **Where:** `server.rs:706` (`reserve(limit × (MAX_ENVELOPE+64))`), with the defaults `response_budget_bytes: 64 MiB` (`server.rs:181`) and `max_connections_per_source: 32` (`server.rs:176`).
- **What is wrong:**
  - A `limit=32` fetch reserves 2 050 KiB, so 31 reservations exhaust the 64 MiB budget.
  - A single source is allowed 32 connections, so it can hold every reservation itself.
- **Exploit:** reproduced as PROBE budget, 10/10 refusals.
  1. Deposit 32 × 64 KiB into your own mailbox.
  2. From 31 connections, authenticate and pipeline `Fetch{limit:32}` without reading.
  3. Each connection holds 2 MiB of budget for `write_timeout` (30 s). Reconnect and repeat.
  4. Every legitimate client receives `RateLimited` on full-size fetches relay-wide.

  This contradicts README:205-206 ("slow or non-reading clients cannot hold memory or connection slots" implies no lasting effect on others).
- **Required fix:**
  - Give each source a share of the budget, for example at most budget/8, keyed by the existing `SourceSlot` key and held in memory only.
  - And/or reserve the actual encoded size after the DB read rather than `limit × max`.
  - Document the remaining multi-source risk.
- **Test:** an integration test with the defaults: 31 non-reading connections from 127.0.0.1, then a fresh client's `fetch(limit 32)` must succeed. The mutant "no per-source share" must fail it.

**P3R2-3: One host drains the relay-wide mailbox-creation budget and fills `max_mailboxes`. The docs say it takes a distributed attacker.**
- **Where:**
  - `server.rs:523` (the per-connection `create_mailbox` limiter is new for every connection);
  - `deploy/README.md:226-228`;
  - `docs/THREAT_MODEL.md:79`.
- **What is wrong:**
  - The per-connection limit (burst 4) resets on reconnect.
  - Reproduced: one host created 20 mailboxes in 78 ms over 6 sequential connections, and the victim then got `RateLimited`.
  - Sustained at 1/s, one host also reaches `max_mailboxes` (100 000) in about 28 h. Those mailboxes idle-expire only after 60 days, so onboarding and the mandatory 7-day rotation fail for every user for weeks.
  - The docs ("an attacker with many addresses", "a distributed attacker") understate this.
- **Required fix:**
  - Key creation by source as well, using the in-memory `SourceSlot` key with the same lifetime rules, and/or add a proof of work or an operator registration secret.
  - Expire never-authenticated mailboxes much sooner than 60 days.
  - Correct README and THREAT_MODEL.
- **Test:** one host creates over many sequential connections; after N creations it gets `RateLimited` while a different source key still succeeds. The idle-expiry test should cover the shorter never-authenticated TTL.

**P3R2-4: The log test cannot see the most natural way to leak a mailbox id or a size.**
- **Where:** `crates/relay/tests/logs.rs:161-175`.
- **What is wrong:**
  - The needles are hex prefixes and specific decimal sizes.
  - `tracing::warn!(m = ?id)` prints `[12, 200, …]`, and logging the stored record length prints `4112`, not `4096`. Both survive (R2-M8, R2-M9).
  - INV-META-2 and INV-LOG-1 say the test "finds no mailbox id … or size".
- **Required fix:** the relay is meant to log nothing during a session, so assert that. After the canary, the captured output must be empty, or match an explicit allowlist of event names with no fields. Keep the needle search as a second check.
- **Test:** R2-M8 and R2-M9 must fail it.

**P3R2-5: The "required" TURN firewall rule misses UDP services that Docker publishes on the host, such as Pi-hole or wg-easy in Docker.**
- **Where:** `deploy/firewall/veil-turn.nft:22` (`hook output priority filter`).
- **What is wrong:**
  - For locally generated packets, Docker's `ip nat OUTPUT` chain (`fib daddr type local … jump DOCKER`, priority dstnat −100) rewrites `daddr` to the container address before this filter chain (priority 0) runs.
  - `fib daddr type local` is then false, so the packet is accepted.
  - Reproduced: a container publishing 40001/udp echoed 5/5 relayed packets, the nft drop counter did not move, and the Docker DNAT counter did. The same happened with the option-B `public/private` external IP.
  - README:194 names Pi-hole as protected. On a Raspberry Pi, Pi-hole usually runs in Docker.
- **Required fix:**
  - Hook before NAT, at `priority mangle` (−150) or `raw`. Verified: at mangle the probe lost 5/5 and client↔client relaying still lost 0.
  - Alternatively, match `ct original ip daddr` / `ip6 daddr`.
  - Make persistence a required step, because after a reboot `restart: unless-stopped` brings coturn back without the rule.
  - Correct the README claim.
- **Test:** extend the CI P3-8 step with `docker run -d -p 40001:3480/udp … turnutils_peer` and assert `uc -e $TURN_IP -r 40001` reports `Total lost packets 5 (100`. With the rule at priority filter, the step must fail.

### Low
**P3R2-6: A revoked connection keeps receiving pushes for the re-created mailbox.**
- **Where:** `server.rs:669` (subscribe), `server.rs:576` and `server.rs:735` (`authed.remove` without unsubscribing). Subscriptions are only cleared by `unsubscribe_all` at disconnect.
- **What is wrong:** after `DeleteMailbox` and re-creation under a new key, the old connection got `NewEnvelopes last_seq=[1, 2]` (PROBE push). So the holder of a revoked key keeps learning deposit timing and counts for as long as it pings. PROTOCOL §6.3 says deleting "revokes all connections".
- **Fix:**
  - Unsubscribe `(m, conn)` wherever `authed.remove(&m)` happens.
  - In `notify`, or at delete, drop subscribers whose key no longer matches. Simplest: store the auth key in the subscriber entry and remove entries on `delete_mailbox`.
- **Test:** extend `deleting_a_mailbox_revokes_other_connections` with a deposit to the new mailbox, and assert the stale connection receives no push.

**P3R2-7: All IPv6 clients may share one source key under the shipped Docker setup [MEDIUM confidence, not reproduced here].**
- **Where:** `deploy/docker-compose.yml` (`ports: "8443:8443/tcp"` on the default bridge, without IPv6), `server.rs:290`.
- **What is wrong:** Docker serves IPv6 connections to an IPv4-only container through `docker-proxy`. The relay then sees the bridge gateway as the peer for every IPv6 client, and the same goes for any TCP proxy or load balancer in front of it. The 32-per-source cap becomes 32 in total for those clients, and one of them can lock out the rest.
- **Fix:** document it, or enable IPv6 on the compose network / set `userland-proxy: false`. Consider making the per-source cap configurable (`VEIL_MAX_CONN_PER_SOURCE`).
- **Test:** a deploy check that connects over `[::1]` and from IPv4, and shows separate counts. Or a README note.

**P3R2-8: Documentation figures and test claims that do not reproduce or do not test what they claim.**
- **"3.4× the payload" (ADR-0010, README, `.env.example`):** this is the file's *apparent* size, a redb growth step. 9 000 and 9 600 envelopes both give exactly 2 155 876 352 B, while the allocated size for 563 MiB was 1.15 GB (about 2×). The disk sizing is conservative but described wrongly.
- **INV-ROB-1 / TEST_REPORT "soak … then two sweep intervals under 512 MiB":** the soak's envelopes have a 14-day TTL, so those sweeps have nothing due. The soak tests filling, not expiry, under the memory limit. Expiry is covered only by the unit test and the bench.
- **`Store::sweep` doc (`store.rs:767`) "Returns the number of envelopes … removed":** envelopes removed together with an idle mailbox are not counted. The bench reported "removed 2" for 9 000 envelopes.
- **Fix:** correct the text.

**P3R2-9: No database schema version and no migration of the expiry index.**
- **Where:** `store.rs` `open_with_cache`.
- **What is wrong:** a database created by the round-1 image (`80043a9`, publicly documented deploy) opens without error with an empty `EXPIRY` table. None of its records ever expire.
- **Fix:** store a schema version in `STATS`. On mismatch, refuse to start or rebuild the index.
- **Test:** open a DB without a version row and assert a refusal or a rebuilt index.

## Claims I checked and found accurate
- TEST_REPORT test counts (74/3/22+1/14/1/15/0+2/5), and fmt, clippy, deny and vet (43/5/207).
- Every row of the TEST_REPORT finding→fix→test→mutant table that I re-ran (P3-1, 2, 3 (timeout part), 4, 6 (M4), 7, 10, 11 (auth part)): each mutant fails its test.
- PROTOCOL §6.3 limits match the code:
  - 1 024 connections and 32 per source;
  - 30 s pre-authentication, 5 min idle, 30 s write;
  - 64 MiB budget;
  - 1 GiB and 4 GiB caps;
  - incomplete blobs expire with their token;
  - rate-limit refusals echo the request id (`frame_rate_limit_echoes_the_request_id`).
- `source_key` folds IPv4-mapped IPv6 and keeps IPv6 keys apart from IPv4 keys. The source entry is removed at zero, and the peer address is not stored or logged: one relay log line after smoke and soak.
- Decoding before the frame limit is not a CPU amplifier: input is capped at about 66 KiB by the WebSocket limits, and decoding is linear, the same order as the TLS and WebSocket work already done.
- The budget is dropped only after the send completes or times out, so there is no race between the budget and the send. The error paths drop it at once.
- Memory: 90.46 MiB with 300 MiB stored, consistent with README's 92 MiB at 600 MiB. Idle-mailbox expiry of 563 MiB in a single batch: 407 ms, VmHWM 70 MB.
- SIGTERM: clean stop in 310 ms with exit 0 (TEST_REPORT says 533 ms).
- The coturn deny list, `no-tcp-relay`, the 403 for private peers, and the wrong-password refusal behave as described. Client↔client relaying lost 0 packets with the rule loaded.
- Dropping the private `allowed-peer-ip` does not break the `public/private` configuration: coturn relayed both legs via its own public address without needing hairpin NAT.
- The CI P3-8 probe can fail for a host-bound listener. It does not cover Docker-published services (P3R2-5).

## Claims I could not verify
- arm64 / Raspberry Pi, SD-card commit and sweep timings, and an actual home router (option B) with hairpin NAT. I tested only the coturn side of the mapping.
- The CI `relay-deploy` job as actually run on GitHub, including the 1.1 GB soak and `memory.peak`.
- The TEST_REPORT figures "71 MB peak while filling 630 MB in a 512 MiB container" and "expire 9 600 in 0.77 s at 36 MB". I measured comparable numbers natively, not in a container, and used 300 MiB in the deployed container.
- P3R2-7 (IPv6 clients sharing the Docker gateway source) is based on Docker's documented `docker-proxy` behaviour. This sandbox has no external IPv6.
- Whether kernel socket send buffers, which are outside the response budget, can push a 512 MiB container into OOM with about 1 000 non-reading connections. I did not test this.
- Image reproducibility: I did not rebuild `veil-relay:local`.

---
Housekeeping: the working tree is clean (`git status --short` is empty) and nothing was committed or pushed. The temporary probe test, the bench DBs, the TURN credential file, the test UDP container, the compose stack and its volume, `deploy/.env`, `deploy/secrets` and the `inet veil_turn` table have all been removed. The scratch bench crate now has extra modes (`idlefill`, `idlesweep`, `uploadtok`, `tokrows`), at `/tmp/claude-0/-home-user-ataraxia/929457e9-49df-558b-9ee2-363e38c8130c/scratchpad/bench/src/main.rs`. The mangle-priority rule I tested is at `/tmp/claude-0/-home-user-ataraxia/929457e9-49df-558b-9ee2-363e38c8130c/scratchpad/veil-turn-mangle.nft`.

---

## Phase 3 review, round 3 (2026-10-19)

**Reviewer:** code-reviewer agent (Agent tool, `subagent_type: "code-reviewer"`, model override `opus`), adversarial brief. Scope: round-2 fixes in `73a8688`, CI fixes in `0d9f412`, plus `git diff 0958b70^..HEAD`. Report follows verbatim.

# Phase 3 review: round 3

## Verdict: PASS WITH CONDITIONS
All nine round-2 findings are addressed, and the core fixes hold up when tested adversarially.
- **Counters:** a randomized probe of 30 000 operations checked the `STATS` counters and the `EXPIRY` index after every operation. They always matched the real row counts exactly.
- **Firewall:** the Docker-published UDP service is blocked by the `priority mangle` rule (5/5 packets lost). The round-2 rule at `priority filter` lets 5/5 through.
- **Mutation checks:** 11 of 13 mutants were killed by the intended tests.
- **Tooling:** fmt, clippy (`-D warnings`), tests, deny, vet and gitleaks all pass.

There are no Critical or High findings, but the fixes introduced four Medium problems:
- The new relay-wide token caps turn the old disk-fill into a relay-wide lockout. For token rows, **one** host can reach it in about 32 h; the docs say this needs "many sources" (P3R3-1).
- The new per-source limits cannot be configured. Behind Docker's userland proxy, which in the shipped compose covers IPv6 clients, every client shares one source's creation, upload-token and response-budget allowance. I reproduced this (P3R3-2).
- One host can keep the single DB writer busy with no-op commits. A victim's deposit latency went from 3.4 ms to 62 ms (P3R3-3).
- "Never by IP" is now false in five places, and IP-derived limiter keys stay in memory for the life of the process (P3R3-4).

**Conditions for PASS:**
1. P3R3-1: either give every mailbox a floor that the global cap cannot take away, or size the caps so they are never the binding limit. In both cases, correct README and THREAT_MODEL to state how many sources each cap needs.
2. P3R3-2: make the per-source limits configurable, or derive them from `VEIL_MAX_CONN_PER_SOURCE`, and correct the README advice.
3. P3R3-3: skip commits for writes that change nothing, and rate-limit `UpdateTokens` and `Ack`, or document the risk with numbers.
4. P3R3-4: correct the five "never by IP" texts, and prune full buckets in the sweep loop.

The Lows can follow later.

## Round-2 findings: status
| ID | Status | Evidence |
|---|---|---|
| P3R2-1 | **Fixed** (disk fill). New lockout: P3R3-1 | **Counters exact on every path.** Probe `r3_counters_stay_exact`: a temporary `#[cfg(test)]` module appended to `store.rs`, then reverted. It ran 30 000 random operations with tiny quotas: create, touch, delete, `update_tokens` with duplicate and FF-prefixed hashes, deposit, ack, invite put/take, upload tokens with frequent id collisions (2 261 successes), chunks, sweep and clock ticks. After every operation it asserted that each of these matches the actual rows:<br>• `STAT_{MAILBOXES,TOKEN_ROWS,UPLOAD_TOKENS,INVITES,ENVELOPE_BYTES,BLOB_BYTES}`;<br>• `EXPIRY` = mailboxes + envelopes + invites + upload tokens + blobs (no stale entries);<br>• each mailbox's `tokens` and `count` field.<br>It passed.<br>**Mutants killed:** M1–M5 (cap off, completion not freeing, expiry not freeing, row cap off, delete not freeing).<br>**Not done:** the round-2 request for a *per-mailbox outstanding* upload-token cap was not implemented. |
| P3R2-2 | **Fixed** (residual risk documented qualitatively) | The 8 MiB share works; M7 is killed. A full fetch reserves 2 050 KiB, so one source holds 3 reservations. **11 sources** fill the 64 MiB budget for full-size fetches. README and THREAT_MODEL say "many addresses" without a number. |
| P3R2-3 | **Fixed** | The per-source bucket (M8 killed) and the 24 h lifetime of never-authenticated mailboxes (M11 killed) both work. `touch_mailbox` writes when `!authed`, even within the same minute.<br>**Residual:** draining the relay-wide creation bucket continuously takes about 60 sources at 1/min each. One host that re-authenticates its mailboxes reaches `max_mailboxes` (100 000) in about 69 days. |
| P3R2-4 | **Fixed** | The test is not vacuous: the canary from `spawn_blocking` must appear, and any other line fails it. M12 (`tracing::warn!(m = ?id)` in `Store::deposit`) is killed at `logs.rs:167`. `tracing-subscriber` is built without `tracing-log`, so `main.rs`'s `.init()` installs nothing the test lacks. |
| P3R2-5 | **Fixed** (unit issues: P3R3-5) | Deployed stack with the committed rule:<br>• Docker-published echo on 40001/udp: lost 5/5; the nft counter went to 1;<br>• the same rule at `priority filter`: lost 0/5;<br>• no rule at all: lost 0/5.<br>So the CI step does fail with the old rule. Client↔client relay lost 0, and the private peer got 403. `systemd-analyze verify` is clean, with no ordering cycle: the unit's dependencies mirror Debian's `nftables.service`. |
| P3R2-6 | **Fixed** | M9 (no key filter in `notify`) fails `pushes_follow_the_current_mailbox_key`. Delete drops all subscribers, and a failed re-check unsubscribes. |
| P3R2-7 | **Partially fixed** → P3R3-2 | Only the connection cap is configurable. Reproduced: through `docker-proxy`, clients from 127.0.0.3 and 127.0.0.4 share 127.0.0.1's creation bucket. |
| P3R2-8 | **Fixed** | README, ADR-0010, `.env.example`, INV-ROB-1 and the `Store::sweep` doc are corrected. |
| P3R2-9 | **Fixed** (edge case: P3R3-7) | M10 is killed. An unversioned database holding only upload tokens or token rows is stamped as v2 (reproduced). |

## Commands I ran and their results
```text
$ cargo fmt --all --check                                         → fmt exit 0
$ cargo clippy --workspace --all-targets --locked -- -D warnings  → clippy exit 0
$ cargo test --workspace --locked                                 → test exit 0
  veil_core 74 | secrets 3 | session 22 (+1 ignored) | veil_relay lib 18 | logs 1 | relay 18 | smoke 0 (+2 ignored) | veil_wire 5
$ cargo deny --locked check → advisories ok, bans ok, licenses ok, sources ok (exit 0)
$ cargo vet --locked        → Vetting Succeeded (43 fully audited, 5 partially audited, 207 exempted)
$ /tmp/claude-0/gl/gitleaks git --redact --exit-code 1 .   (8.30.1) → 43 commits, no leaks found, exit 0
  with only the default rules (no allowlist): exit 1, generic-api-key in Cargo.lock, crates/core/fuzz/Cargo.lock, spikes/libsignal/Cargo.lock
  negative test, a scratch repo with the repo's .gitleaks.toml:
    sub/Cargo.lock with api_key="8f3a…0a" (40 lowercase hex) and heroku_api_key="5a4c3e2f-…" → NOT reported
    the same content in sub/notlock.toml → reported (generic-api-key, heroku-api-key)
```
Mutation checks. Each mutant was an exact single-match replace, the named test was run, and the file was then restored with `git checkout`.
```text
R3-M1  add_upload_token: `if false && live >= max`        → upload_tokens_are_capped_and_released FAILED (store.rs:1298)
R3-M2  completion does not decrement STAT_UPLOAD_TOKENS   → upload_tokens_are_capped_and_released FAILED (1303)
R3-M3  expiry does not decrement STAT_UPLOAD_TOKENS       → upload_tokens_are_capped_and_released FAILED (1306)
R3-M4  token-row cap check removed                        → token_rows_are_capped_relay_wide FAILED (1327)
R3-M5  remove_mailbox does not subtract token rows        → token_rows_are_capped_relay_wide FAILED (1337)
R3-M6  shrink exemption removed (`rows > max` only)       → token_rows_are_capped_relay_wide ok   (SURVIVES)
R3-M7  reserve: no per-source share                       → one_source_cannot_hold_the_response_budget FAILED
R3-M8  no per-source create check                         → mailbox_creation_is_limited_per_source FAILED
R3-M9  notify: no key filter                              → pushes_follow_the_current_mailbox_key FAILED
R3-M10 schema: any version accepted                       → foreign_schema_is_refused FAILED
R3-M11 touch does not set authed                          → never_authenticated_mailboxes_expire_early FAILED
R3-M12 tracing::warn!(m = ?id) in Store::deposit          → relay_logs_nothing_about_clients FAILED (logs.rs:167)
R3-M13 per-source upload-token limiter removed            → whole veil-relay suite passes (SURVIVES)
```
Temporary probes. These were `crates/relay/tests/r3_probe.rs`, `r3_proxy_probe.rs` and two appended `#[cfg(test)]` modules in `store.rs`, all deleted or reverted afterwards.
```text
R3 counters probe: 30000 ops, successes {ack 977, chunk 440, create 1314, delete 1004, deposit 470, invite 1369,
   sweep 2333, take 416, tick 2327, tokens 973, touch 1005, uptok 2261}: every invariant held after every op
R3 schema probe: unversioned DB holding 1 upload token + 1 orphan token row → Ok (stamped v2);
   rows after sweep(u64::MAX-1): [("tokens", 1), ("upload_tokens", 1)]
R3 PROBE token rows (max_token_rows lowered to 5 120): one source registered 5120 rows in 705 ms;
   victim from 127.0.0.2 adds 1 token → Err(QuotaExceeded)
R3 PROBE no-op writes, default Config, debug build: one source, 31 conns, 4 s → 1932 accepted UpdateTokens{} (483/s),
   each a committed write transaction
R3 PROBE victim deposit latency (p50, max): idle (3.40 ms, 5.32 ms), during no-op spam (61.8 ms, 79.8 ms)
```
Deployment. Setup followed deploy/README: `.env` with `TURN_EXTERNAL_IP=192.0.2.2`, `secrets/turn_secret` 0644 inside a 0700 directory, `gen-cert`, `nft -f firewall/veil-turn.nft`, `up -d`, with the existing `veil-relay:local` image (created 18:25:05Z).
```text
smoke deployed_relay_round_trip (VEIL_SMOKE_ADDR=127.0.0.1:8443) ... ok
  (with VEIL_SMOKE_ADDR=192.0.2.2:8443 the test client hung at connect, although openssl s_client connected; see "could not verify")
uc -y -c -n 20                               → Total lost packets 0 (0.000000%)
uc -c -e 10.0.0.1                            → 403 (Forbidden IP)
docker run -d --name udp-svc -p 40001:3480/udp … turnutils_peer
uc -c -e 192.0.2.2 -r 40001, committed rule  → Total lost packets 5 (100.000000%); counter packets 1 … drop
same, rule switched to `priority filter`     → Total lost packets 0 (0.000000%)
same, no rule                                → Total lost packets 0 (0.000000%)
docker-proxy probe (via 127.0.0.1:8443, after smoke used 1 creation):
  conn0-2 from 127.0.0.1: 9 × Ok; conn3 from 127.0.0.3: Ok, RateLimited, RateLimited; conn4 from 127.0.0.4: 3 × RateLimited
relay log: 1 line (startup); coturn log: 1 line "udp send: Operation not permitted" (firewall drop, no address)
docker stats: relay 2.8 MiB / 512 MiB, coturn 7.2 MiB
docker compose stop relay → 446 ms, ExitCode=0 OOMKilled=false, "veil-relay stopped"
systemd-analyze verify veil-turn-firewall.service → no output, exit 0
/lib/systemd/system/nftables.service: ExecStart/ExecReload=nft -f /etc/nftables.conf, ExecStop=nft flush ruleset;
/etc/nftables.conf line 3: "flush ruleset"
```
Cleanup:
- Ran `docker rm -f udp-svc`, `docker compose down -v` (volume `veil_relay-data` removed), `rm -rf deploy/.env deploy/secrets` and `nft delete table inet veil_turn`.
- Removed the probe files, the TURN credential file, and the 16 `/tmp/veil-*` store dirs left by my panicking mutant runs.
- `git status --short` is empty. HEAD is still 0d9f412. Nothing was committed or pushed.

## New findings
### Critical
None.

### High
None.

### Medium
**P3R3-1: The relay-wide token caps are a lockout that one host (token rows) or about 7 hosts (upload tokens) can trigger. The docs say it takes "many sources".** [HIGH confidence]
- **Where:**
  - `crates/relay/src/store.rs:506-511` (`update_tokens` global row check);
  - `store.rs:679-682` (`add_upload_token`);
  - defaults at `server.rs:174-176` (`max_tokens_per_mailbox: 512`, `max_token_rows: 1_000_000`, `max_upload_tokens: 20_000`) and `server.rs:104-111` (per-source rates);
  - `deploy/README.md` "Denial of service by many sources" bullet;
  - `docs/THREAT_MODEL.md:79`.
- **What is wrong:** the caps bound disk use, but nothing reserves any share of them for anyone, and `UpdateTokens` has no rate limit.
  - **Token rows:** 1 000 000 / 512 = 1 954 mailboxes are enough. At the per-source creation rate (10, then 1/min) one IPv4 host has them in (1 954 − 10) min ≈ **32.4 h**.
    - Each mailbox needs one authentication and 8 `UpdateTokens` of 64 tokens.
    - The mailboxes then live 60 days per authentication, so one re-authentication every 59 days keeps the lockout going indefinitely.
    - After that, **every** `UpdateTokens` that adds a token fails with `QuotaExceeded` relay-wide.
  - **Upload tokens:** one source gets 30 + 86 400/30 = 2 910 per 24 h, so 7 sources keep all 20 000 live permanently. Every attachment upload relay-wide is refused.
  - Round 2's required fix also asked for "a small per-mailbox cap on outstanding upload tokens". That was not implemented.
- **Exploit:** reproduced at reduced scale, with `max_token_rows` = 5 120.
  1. One source registered 5 120 rows in 705 ms.
  2. A different source's first `UpdateTokens` → `QuotaExceeded`.
  3. At default scale, PROTOCOL §2 says pairing registers a delivery token and every 7-day rotation registers new tokens. So after about 32 h of one host's effort, new contacts and rotation fail for every user. [MEDIUM confidence on how the Phase 4 client reacts]
- **Required fix:**
  - Guarantee each mailbox a floor that the global cap cannot take away. For example, the global row cap applies only to tokens above the first 64 per mailbox. Or make the cap non-binding: lower `max_tokens_per_mailbox` (for example to 64, which still fits contacts padded to multiples of 8) and set `max_token_rows ≥ max_mailboxes × max_tokens_per_mailbox`, with the resulting size (6.4 M rows ≈ 1.05 GB) in the README disk sizing.
  - For upload tokens, add an in-memory per-mailbox outstanding count. Then the cap needs about 20 000 / k mailboxes' worth of attackers, and that number should be documented.
  - In README and THREAT_MODEL, state how many sources each cap takes: rows 1 host in about 32 h, upload tokens 7 hosts, response budget 11, creation about 60.
- **How to test:**
  - A store test: with the global row cap full, a fresh mailbox can still register its floor.
  - An integration test: an attacker source exhausts its share, and a victim from 127.0.0.2 can still `UpdateTokens` and get an upload token.
  - Mutant: "global check without the floor" must fail the test.

**P3R3-2: Only the connection cap can be configured. The new per-source limits collapse onto a single source behind Docker's userland proxy (all IPv6 clients in the shipped compose) or any reverse proxy.** [HIGH confidence on the mechanism (reproduced); MEDIUM for IPv6 specifically, because this sandbox has no IPv6]
- **Where:**
  - `server.rs:104-111` (`create_mailbox_per_source`, `upload_token_per_source`) and `server.rs:202` (`response_budget_per_source`), all hard-coded;
  - `main.rs:85-104` (`limits_from_env` reads only `VEIL_MAX_CONN_PER_SOURCE`);
  - `deploy/README.md` "raise `VEIL_MAX_CONN_PER_SOURCE` then";
  - `deploy/.env.example:22-25`.
- **What is wrong:** behind `docker-proxy` every client has the bridge gateway as its peer address, so one source key covers them all. That key's limits then apply to everyone together:
  - 10 creations, then 1/min;
  - 30 upload tokens, then 1/30 s;
  - an 8 MiB response share, i.e. 3 concurrent full fetches;
  - 32 connections (the only one that can be raised).

  The README tells the operator that raising `VEIL_MAX_CONN_PER_SOURCE` is the remedy, but that does not lift the other three.
- **Reproduced:** through `127.0.0.1:8443`, which goes through `docker-proxy`, connections bound to 127.0.0.3 and 127.0.0.4 were rate-limited by the creations already made from 127.0.0.1. The in-process tests treat 127.0.0.2 as a separate source.
- **Scenario:** on a dual-stack VPS, one IPv6 client holds 4 non-reading fetches, or 32 connections. Every IPv6 user's fetches, or all their connections, are then refused. Even without an attacker, more than 3 IPv6 users syncing at once get `RateLimited`.
- **Required fix (any one of these):**
  - expose `VEIL_PER_SOURCE_CREATE`, `…_UPLOAD` and `…_BUDGET_MB`;
  - scale them with `VEIL_MAX_CONN_PER_SOURCE`;
  - enable IPv6 on the compose network, or `userland-proxy: false`, so real addresses arrive;
  - in any case, correct the README and `.env.example` text.
- **How to test:** a unit test of `limits_from_env` for the new variables, and an integration test where `per_source` is raised and 20 creations from one source succeed.

**P3R3-3: One source can keep the single redb writer busy with write transactions that change nothing.** [HIGH confidence on the mechanism; MEDIUM on the SD-card impact, which was not measured]
- **Where:**
  - `store.rs:482-516`: `update_tokens` with empty `add` and `remove` still inserts into `STATS` and `MAILBOXES` and commits;
  - `store.rs:590-615`: `ack` commits even when nothing is removed;
  - `server.rs:776-835`: no rate limit on `UpdateTokens` or `Ack`, only the frame limit of 50/s per connection × 32 connections.
- **Exploit (measured):**
  1. One source authenticates one mailbox on 31 connections.
  2. It loops `UpdateTokens{}`: 483 commits/s accepted (debug build; the writer was the bottleneck).
  3. A victim's deposit latency from another source went from p50 3.4 ms to 61.8 ms, max 79.8 ms. That is on this fast disk.

  On a Raspberry Pi SD card, where each fsync costs milliseconds to tens of milliseconds, the same load serialises every deposit, auth touch and creation behind about 30 queued commits. This degrades the service for every user without filling anything. It is not documented.
- **Required fix:**
  - Return early without committing when an `update_tokens` or `ack` changes nothing.
  - Add per-mailbox token buckets for `UpdateTokens` and `Ack` (for example burst 20, then 1/s).
  - Document the residual multi-source write load.
- **How to test:** a store unit test showing that an empty `update_tokens` or `ack` leaves the database unchanged (or that a commit counter does not move). An integration test: `UpdateTokens` beyond the burst → `RateLimited`.

**P3R3-4: "Never by IP" is now false in five places, and IP-derived keys stay in memory for the life of the process.** [HIGH confidence]
- **Where:**
  - `docs/PROTOCOL.md:214` ("**Never by IP.**");
  - `docs/THREAT_MODEL.md:78` ("Rate limits are never keyed by IP");
  - `docs/ARCHITECTURE.md:196` ("No IP-keyed rate limits or records"), which directly contradicts the next bullet;
  - `crates/relay/src/limits.rs:2`;
  - `server.rs:10`;
  - mechanism: `server.rs:255-256` (`KeyedLimiter` keyed by `limiter_key(source)`, the full IPv4 address) and `limits.rs:84-108` (eviction only when 100 000 keys are tracked).
- **What is wrong:**
  - Mailbox creation and upload tokens are now rate-limited by source address.
  - The per-source buckets are never pruned on a time basis. On a personal relay, which never reaches 100 000 keys, the full IPv4 address of every client that created a mailbox or requested an upload token since startup stays in memory.
  - Mailbox rotation happens every 7 days, so that list covers effectively every user.
  - The docs promise the opposite, and only for connection counts and budget shares does the code forget at zero.
- **Scenario:** a memory image of a running relay (host compromise, seizure, or a core dump) yields the IP addresses of all users since the last restart. The README and THREAT_MODEL tell operators that IPs are never retained.
- **Required fix:**
  - Correct the five texts: rate limits are also keyed by an in-memory source key, here is how long it lives, and here is why.
  - In `sweep_loop`, drop buckets that have refilled to burst; they are indistinguishable from fresh buckets, as `evict` already notes. Retention is then bounded to about 10 min for creation and 15 min for upload.
  - Or key the buckets by a keyed hash with a per-process random key, rotated daily.
- **How to test:** a `KeyedLimiter` unit test: after a refill interval, `prune(now)` leaves 0 keys. Mutant: no prune → fails.

### Low
**P3R3-5: The systemd unit stops Docker on removal or restart, and does not survive nftables.service.** [HIGH confidence from systemd.unit(5) and the Ubuntu unit files; not run, since this sandbox has no systemd]
- **Where:** `deploy/firewall/veil-turn-firewall.service:15-17`, and the "Remove" line at `veil-turn.nft:16`.
- **What is wrong:**
  - `RequiredBy=docker.service` puts this unit in docker's `Requires=`. When a required unit is explicitly stopped or restarted, the requiring unit is stopped or restarted too. So the documented `systemctl disable --now veil-turn-firewall` stops Docker and every container on the host, a Pi-hole included. A `systemctl restart` after editing the port range restarts all of them.
  - There is no ordering against `nftables.service`. Its start, reload (`nft -f /etc/nftables.conf`, which begins with `flush ruleset` on Debian and Ubuntu) and stop (`nft flush ruleset`) silently delete `inet veil_turn`, while this oneshot unit still reports active and coturn keeps running.
- **Fix:**
  - Replace `RequiredBy` with a docker drop-in `ExecStartPre=/usr/sbin/nft list table inet veil_turn`, which refuses to start Docker without the rule but does not propagate stop.
  - Add `After=nftables.service`, `PartOf=nftables.service`, `ReloadPropagatedFrom=nftables.service` and `ExecReload=/usr/sbin/nft -f /etc/veil-turn.nft`.
  - Or document adding `include "/etc/veil-turn.nft"` to `/etc/nftables.conf`.
- **Test:** in CI (the runners have systemd), install the unit and enable it, then `systemctl restart nftables` → `nft list table inet veil_turn` still succeeds; and `systemctl stop veil-turn-firewall` → `systemctl is-active docker` is still active.

**P3R3-6: The gitleaks allowlist is global and wider than "crate names".** [HIGH confidence, reproduced]
- **Where:** `.gitleaks.toml:9-13`.
- **What is wrong:** the allowlist applies to every rule and matches any secret made only of `[a-z0-9_-]`. In any `Cargo.lock` it hides lowercase-hex API keys and Heroku keys; both were reproduced as not reported. The commit message's "real-looking keys in a Cargo.lock are still reported" is only partly true.
- **Fix:**
  ```toml
  [[allowlists]]
  targetRules = ["generic-api-key"]
  condition = "AND"
  paths = ['''(^|/)Cargo\.lock$''']
  regexTarget = "line"
  regexes = ['''^\s*"[a-z0-9][a-z0-9_-]*",?\s*$''']
  ```
- **Test:** the three current findings stay suppressed, and the two negative-test values in a `Cargo.lock` are reported.

**P3R3-7: The schema check treats a database holding only upload tokens, token rows, chunks or envelopes as "empty".** [HIGH confidence, reproduced]
- **Where:** `store.rs:384-396` checks only `MAILBOXES`, `INVITES` and `BLOBS`.
- **What is wrong:** reproduced with an unversioned database holding 1 upload token, 1 orphan token row and no index entries.
  - It is stamped as v2.
  - Both rows survive `sweep(u64::MAX-1)`, and `STAT_UPLOAD_TOKENS` undercounts.
  - Orphan FF-prefixed token rows are exactly what the pre-P3-2 image left behind.
- **Fix:** require all record tables to be empty, including `TOKENS`, `UPLOAD_TOKENS`, `ENVELOPES`, `BLOB_CHUNKS` and `EXPIRY`, and all `STATS` counters to be zero.
- **Test:** extend `foreign_schema_is_refused` with a database containing only an upload token, and one containing only a token row.

**P3R3-8: Security claims with no test, and stale doc rows.**
- **Untested claims:**
  - R3-M13 survives the whole suite. The per-source upload-token limit, claimed in the TEST_REPORT P3R2-1 row, PROTOCOL §6.3 and README, has no test.
  - R3-M6 survives. The "Shrinking is always allowed" comment in `token_rows_are_capped_relay_wide` never runs in an over-cap state.
- **Stale docs:**
  - PROTOCOL §14 does not list the new limits: token rows, upload tokens, the per-source creation, upload and budget limits, and the 24 h lifetime of never-authenticated mailboxes.
  - The INV-LOG-1 row still cites only M3 and M4.
- **Fix:** add `upload_tokens_are_limited_per_source` (31st token from one source → `RateLimited`, another source → Ok), and update §14 and INV-LOG-1. CLAUDE.md rule 9 applies.

**P3R3-9: When the relay-wide creation bucket is empty, a legitimate creation still spends its per-source token.**
- **Where:** `server.rs:717-722`.
- **What is wrong:** during a multi-source drain, each retry by a victim burns their own 10-token burst. They then stay locked out for minutes after the attack stops.
- **Fix:** check the relay-wide bucket without consuming it first, or refund the per-source token on refusal.
- **Test:** with the global bucket exhausted, 11 refused attempts, then one global token appears, and the source can create.

## Claims I checked and found accurate
- TEST_REPORT round-2 test counts (74 / 3 / 22+1 / 18 / 1 / 18 / 0+2 / 5), and fmt, clippy, deny and vet (43/5/207).
- Every mutant named in the TEST_REPORT round-2 table that I re-ran fails its test:
  - P3R2-1 (cap and freeing);
  - P3R2-2 (share);
  - P3R2-3 (per-source check, touch marking);
  - P3R2-4 (M8 style);
  - P3R2-6 (key filter);
  - P3R2-9 (version).
- "Counted in `STATS` in the same transaction, released on completion, expiry, removal, delete and idle expiry": verified exact by the 30 000-operation probe, including upload-token id collisions and FF-prefixed token hashes.
- The `EXPIRY` index stays exactly one entry per live record; no stale entries accumulate.
- P3R2-5: `priority mangle` blocks a Docker-published service, and the round-2 `priority filter` rule does not. So the CI step's claim "fails with the old rule" holds, and calls still relay with 0 loss.
- "relay log lines after smoke + probes: 1"; coturn logs only its address-free drop line; clean SIGTERM stop (446 ms here vs 299 ms reported; same order).
- README record sizes: about 165 MB for 1 000 000 token rows and about 3 MB for 20 000 upload tokens, consistent with round 2's measured 164 and 159 B per row.
- `.env.example` and README now describe the apparent 3.4× vs allocated about 2× file size correctly. `Store::sweep` documents what it counts.
- The CI `relay-deploy` job has actions pinned by SHA, `persist-credentials: false` and `permissions: contents: read`, and it installs protoc.

## Claims I could not verify
- The systemd unit on a real systemd host (no PID-1 systemd here); P3R3-5 is from the man page and unit files.
- IPv6 clients behind `docker-proxy` (this sandbox has no IPv6). I demonstrated the collapse with proxied IPv4 loopback clients.
- The SD-card or Raspberry Pi impact of P3R3-3; measured only on this disk, in a debug build.
- Why the smoke client hung connecting to `192.0.2.2:8443` (the DNAT path) while `openssl s_client` connected. Through `127.0.0.1` (docker-proxy) it passed. This is probably a sandbox networking quirk, but I did not prove it.
- The ADR-0010 container figures (71 MB peak, 0.77 s at 36 MB) and a fresh 1.1 GB soak; I did not repeat a soak, because only 3 GB of disk was free.
- How the Phase 4 client reacts when `UpdateTokens` fails during pairing or rotation (P3R3-1 impact).
- The `relay-deploy` job as actually run on GitHub.

---
Housekeeping: the working tree is clean (`git status --short` is empty, HEAD 0d9f412) and nothing was committed or pushed. These are all gone:
- the compose stack and its volume;
- `udp-svc`;
- `deploy/.env` and `deploy/secrets`;
- `inet veil_turn`;
- the probe tests and the TURN credential file;
- my `/tmp/veil-*` dirs (7 older ones that predate this review were left in place).

Copies of the probe code are in `/tmp/claude-0/-home-user-ataraxia/929457e9-49df-558b-9ee2-363e38c8130c/scratchpad/r3/` (`r3_probe.rs`, `counters_probe.rs`, `mut.py`).

---

## Phase 3 review, round 4 (2026-10-19)

**Reviewer:** code-reviewer agent (Agent tool, `subagent_type: "code-reviewer"`, model override `opus`), adversarial brief. Scope: round-3 condition fixes in `d12d769`, CI fix `583d14b`, plus `git diff 0958b70^..HEAD`. Report follows verbatim.

# Phase 3 review: round 4

## Verdict: PASS WITH CONDITIONS
I found no Critical or High issues, and the core of every round-3 condition holds up under test. I replayed the 30 000-operation probe adapted to the floor, with 540 extra floor probes. The `token_rows_over_floor` counter matched the real rows after every operation, no mailbox under its floor was ever refused, and the rows over the floor never went past the cap. The no-op early returns, the per-mailbox limiters, pruning and the creation refund are all mutation-killed. No "never by IP" claim is left. The gitleaks allowlist is narrow, and its negative tests are still reported.

I can't give a plain PASS, for three reasons:
- **C1 is only partly met.** The README disk sizing still describes the round-2 caps, so it understates the new bound by about 1.4 GB.
- **The P3R3-5 work has two real problems,** which I reproduced under a real systemd 255 in a throwaway container. The new `firewall-unit` CI job fails as written. And the TURN rule is silently lost when `nftables.service` is started from inactive or stopped, although the README says it is re-applied on start.
- **Two Medium defects in the round-3 scope.** The C2 scaling made `VEIL_MAX_CONN_PER_SOURCE ≤ 8` break every full `Fetch` (reproduced on the deployed image). `BlobPut` re-sends are an unthrottled write path that costs no quota: about 90 MiB/s of disk writes from one host on the release image, and the docs don't mention it.

All five are small, well-understood fixes, listed as conditions below.

**Conditions:**
1. **P3R4-1:** correct the README disk sizing for the new bound.
2. **P3R4-2:** fix the `firewall-unit` CI job, and the README "refuses to start Docker" wording, so the job passes for the right reasons.
3. **P3R4-3:** make the TURN rule survive `nftables.service` start and stop, or document the gap and give the operator a step that closes it.
4. **P3R4-4:** don't scale the response share below one full response.
5. **P3R4-5:** bound `BlobPut` writes per upload token, and name this path in the residual write-load docs.

## Round-3 conditions and findings: status
| ID | Status | Evidence |
|---|---|---|
| C1 / P3R3-1 | **Partially** | **Counters exact:** I appended a temporary `#[cfg(test)]` probe to `store.rs` (reverted since) with floor 2, `max_token_rows` 4 and 30 000 random operations, including FF-prefixed tokens, deletes, idle expiry and sweeps. After every operation `STAT_TOKEN_ROWS` equalled Σ max(0, rows − floor), `rec.tokens` matched the real rows, there were no orphan rows, and the over-floor rows stayed ≤ the cap. <br>**Floor guaranteed:** 540 probes of "a mailbox under its floor adds one new token" were all accepted (0 refused). <br>**Mutation:** the floor-removal mutant is killed. <br>**Source counts in README and THREAT_MODEL are correct:** (1e6/448 − 10) min = 37.05 h; 1e6 / (30 + 1 440) per day = 680; 1 024/32 = 32; 64 MiB / (3 × 2 050 KiB) → 11; creation 60. <br>**Not met:** the README disk sizing (`deploy/README.md:32-33`) still says "1 000 000 rows, about 165 MB" and "20 000 upload tokens, about 3 MB". The actual bound is `max_mailboxes × floor + max_token_rows` = 7.4 M rows (about 1.2 GB) plus 1 M upload tokens (about 160 MB). See P3R4-1. |
| C2 / P3R3-2 | **Met** (new defect: P3R4-4) | **Scaling:** n=64 doubles the per-source creation and upload allowances and the response share (tested). n=1024 gives creation 320, upload 960, and a share of 256 MiB capped to 64 MiB. Rounding is `ceil` with a minimum of 1. <br>**Small n:** n=1 gives creation burst 1 and upload burst 1, each then 1 per 32 min, and a 256 KiB share. Any n ≤ 8 gives a share below one full fetch, so every `limit: 32` fetch is refused. Reproduced in-process and on the deployed image (P3R4-4). <br>**Mutants:** "response share not scaled" and "upload-per-source not scaled" are both killed. |
| C3 / P3R3-3 | **Met** (residual docs incomplete: P3R4-5, P3R4-6) | **Mutants killed:** removing the `update_tokens` early return, the `ack` early return, or the per-mailbox UpdateTokens limiter. <br>**Deployed image:** 25 × `UpdateTokens{}` gave 19 ok and 6 RateLimited. <br>**Other commits that change nothing** (my probe compared a full DB snapshot before and after every committed operation): <br>• `update_tokens` with the same token in `add` and `remove` (30 cases); <br>• `put_chunk` re-sends; <br>• `sweep` with nothing due (5 commits per minute, not attacker-driven); <br>• `add_upload_token` on an id collision (a probe artifact, unreachable in production). <br>`touch_mailbox`, deposit errors and a `take_invite` miss do not commit. |
| C4 / P3R3-4 | **Met** (minor doc gaps: P3R4-8) | **No "never by IP" claim left.** I searched the whole repo. `PROTOCOL.md:39` ("per token, never per IP") is about deposits and is accurate. <br>**Mutants killed:** "prune not called from the sweep" and "prune keeps everything". <br>**Retention:** about 10 min for creation and 30 min for upload, plus up to one sweep interval, as stated. README L9 and L255 still say addresses are held "while connected" (Low). |
| P3R3-5 | **Partially** → P3R4-2, P3R4-3 | `systemd-analyze verify` is clean. <br>**Real systemd 255 (Ubuntu 24.04 container, a stand-in `docker.service`, the real Ubuntu `nftables.service`):** <br>• restart and reload of nftables re-apply the rule within milliseconds; <br>• stopping the unit leaves Docker active; <br>• Docker fails to start when `/etc/veil-turn.nft` cannot load. <br>**But:** <br>• the CI job fails at step 3, and probably at step 2 (P3R4-2); <br>• `systemctl start nftables` from inactive (the default on Debian and Ubuntu) and `systemctl stop nftables` both leave no rule while Docker runs (P3R4-3). |
| P3R3-6 | **Met** | `gitleaks git --redact --exit-code 1 .` (8.30.1): "no leaks found", 46 commits, exit 0. <br>**My negative tests** (temporary repo): <br>• 40-hex `api_key`, `secret` and `token` lines in a `Cargo.lock` were reported; <br>• a crate-name pair in `other.txt` was reported; <br>• the crate-name pair in `Cargo.lock` was suppressed. |
| P3R3-7 | **Met** (one clause untested: P3R4-7) | All 8 tables, plus `STATS`, must be empty before a database is stamped. The lone-token and lone-upload-token cases are tested. The mutant that drops the `STATS` check **survives**. |
| P3R3-8 | **Met** | **Mutants killed:** R3-M13 (per-source upload check removed) and R3-M6 (shrinking blocked when over the cap). Growing while over the cap (M12) is also killed. <br>**Docs:** §14 lists the new limits; INV-LOG-1 lists M3, M4, M8 and M9. §14 omits the Ack limit (Low). |
| P3R3-9 | **Met** (same pattern elsewhere: P3R4-10) | Removing both layers is killed. Each layer alone survives, as the author says. The refund-on-race path has no test of its own. |

## Commands I ran and their results
```text
$ cargo fmt --all --check                                          # exit 0
$ cargo clippy --workspace --all-targets --locked -- -D warnings   # exit 0
$ cargo test --workspace --locked                                  # exit 0
  veil_core 74 | secrets 3 | session 22 (+1 ignored) | veil_relay lib 23 | logs 1 | relay 23 | smoke 0 (+2 ignored) | veil_wire 5
$ cargo deny --locked check  → advisories ok, bans ok, licenses ok, sources ok
$ cargo vet --locked         → Vetting Succeeded (43 fully audited, 5 partially audited, 207 exempted)
$ gitleaks git --redact --exit-code 1 .  → 46 commits scanned … no leaks found (exit 0)
$ systemd-analyze verify veil-turn-firewall.service → exit 0, no output
```
**Counter probe** (temporary module appended to `store.rs`, reverted):
```text
R4 probe: successes {"ack": 884, "chunk": 391, "create": 1179, "delete": 898, "deposit": 403, "floor": 540,
  "invite": 1217, "sweep": 2128, "take": 371, "tick": 2146, "tokens": 773, "touch": 897, "uptok": 2082}
 no-op commits {"chunk": 1, "sweep": 1322, "tokens": 30, "uptok": 286}
 floor probes 540, refused 0
test store::r4_probe::r4_counters_stay_exact ... ok
The same probe with mutant M7 (remove_mailbox subtracts all rows):
  assertion `left == right` failed: token rows over floor  left: 0  right: 1
```
**Mutation checks** (`cargo test -p veil-relay`; each file restored afterwards):
```text
M1  floor ignored in update_tokens                     KILLED
M2  update_tokens no-op early return removed           KILLED
M3  ack no-op early return removed                     KILLED
M4  prune_limiters not called in sweep loop            KILLED
M5  would_allow pre-check removed (alone)              SURVIVED (by design; covered by M6)
M6  refund removed (alone)                             SURVIVED (race path untested)
M5+M6 both removed                                     KILLED
M7  remove_mailbox subtracts all rows, not over-floor  SURVIVED  ← P3R4-7
M8  schema: STATS-emptiness check removed              SURVIVED  ← P3R4-7
M9  per-mailbox UpdateTokens limiter removed           KILLED
M10 KeyedLimiter::prune keeps everything               KILLED
M11 response share not scaled                          KILLED
M12 over-cap check lets a mailbox grow by 1            KILLED (3 tests)
M13 per-source upload-token check removed (R3-M13)     KILLED
M14 shrinking blocked when over the cap (R3-M6)        KILLED
M15 upload-per-source not scaled                       KILLED
```
**In-process probes** (temporary `crates/relay/tests/r4_probe.rs`, debug build, deleted):
```text
R4 n=1: share 256 KiB, create burst 1, upload burst 1; one idle fetch(limit 32) -> Err(RateLimited)
R4 n=8: share 2048 KiB, create burst 3, upload burst 8; one idle fetch(limit 32) -> Err(RateLimited)
R4 n=9: share 2304 KiB ... -> Ok      R4 n=32: share 8192 KiB ... -> Ok
R4 net-zero UpdateTokens{add:[X],remove:[X]} x40: ok 19, rate-limited 21   (each ok = a commit with no net change)
R4 victim deposit latency (p50,max): idle (3.0ms, 3.7ms), during BlobPut re-send (171.4ms, 199.7ms)
R4 BlobPut re-sends of one 64 KiB chunk, one source, 31 conns, 4 s: 760 accepted, refused 0
```
**Docker deploy.** I checked that `veil-relay:local` contains `token_rows_over_floor`, so it is the d12d769 code. Then I followed the README: `.env` with `TURN_EXTERNAL_IP=192.0.2.2`, `secrets/turn_secret`, `gen-cert`, `nft -f firewall/veil-turn.nft`, `docker compose up -d`.
```text
relay-1 | INFO veil-relay started listen=0.0.0.0:8443 pin=f346fab9… turn=true
smoke deployed_relay_round_trip (127.0.0.1:8443) ... ok
VEIL_MAX_CONN_PER_SOURCE=8 → smoke deployed_relay_round_trip FAILED: smoke.rs:58 owner.fetch(m,0).unwrap() → Err(RateLimited)
VEIL_MAX_CONN_PER_SOURCE=9 → ok
Release image, one source, 30 conns, BlobPut re-sending one 64 KiB chunk for 5 s (temporary test, deleted):
R4D UpdateTokens{} x25: ok 19, rate-limited 6
R4D victim deposit (p50,max) idle (1.12ms, 1.90ms), during BlobPut re-sends (22.6ms, 46.5ms); 7167 re-sends in 5 s (1433/s, 89.6 MiB/s)
```
**systemd 255.** Throwaway `ubuntu:24.04` container (`--privileged`, its own network namespace) with `systemd`, `nftables` and a stand-in `docker.service` running `sleep infinity`. I replayed the CI job's commands:
```text
step 1: verify=0; enable --now ok; restart docker ok; table present; docker active
step 2: flush ruleset in /etc/nftables.conf: yes
        restart nftables; nft list table → "No such file or directory" (after_restart=1)
        reload nftables;  nft list table → "No such file or directory" (after_reload=1)
        5× restart: immediately=1, after 1 s=0;   5× reload: immediately=1, after 1 s=0
step 3: stop veil-turn-firewall → docker active; table gone
        systemctl restart docker → SUCCEEDS ("CI WOULD FAIL: Docker started without the rule");
        veil-turn-firewall active again, table present (pulled in by the drop-in's Wants=)
nftables inactive, rule loaded → systemctl start nftables (+1 s): table=1 (absent), veil=active
systemctl stop nftables → table absent, docker=active, veil=inactive
/etc/veil-turn.nft missing, unit stopped → restart docker: "control process exited with error code", docker=failed
```

## New findings
### Critical
None.

### High
None.

### Medium
**P3R4-1: The README disk sizing still gives the round-2 caps and understates the new bound by about 1.4 GB.** [HIGH]
- **Where:**
  - `deploy/README.md:31-33`;
  - the code is `Quotas` defaults at `crates/relay/src/server.rs` (`token_floor_per_mailbox: 64`, `max_upload_tokens: 1_000_000`) and the `store.rs` doc comment ("bounded by `max_mailboxes × floor + max_token_rows`").
- **What is wrong:**
  - The README says token rows are at most 1 000 000 (about 165 MB) and upload tokens at most 20 000 (about 3 MB).
  - Floor rows don't count against the relay-wide cap. So the bound is 100 000 × 64 + 1 000 000 = 7.4 M rows, about 1.2 GB at the measured 164 B per row.
  - Live upload tokens are now 1 000 000, about 160 MB.
  - C1 required this to be documented. TEST_REPORT has the 160 MB figure; README, ADR-0010 ("Disk is sized from the caps") and `.env.example` don't.
- **Scenario:** an operator sizes a Pi SD card from the README.
  - With 60 or more sources, an attacker creates 100 000 mailboxes (relay-wide 1/s, about 28 h) and registers each one's 64 free tokens.
  - That is about 1.2 GB of rows the operator didn't plan for, and about 3.4× that in apparent file size.
- **Fix:** state 7.4 M token rows (about 1.2 GB) and 1 M upload tokens (about 160 MB) in README L31-33. Add them to the "3.5× the caps" total, or lower `max_mailboxes` and the floor.
- **Test:** this is a docs change. Optionally add a store test that fills `max_mailboxes × floor` rows past a full cap, to back the stated bound.

**P3R4-2: The new `firewall-unit` CI job fails as written, and the README misdescribes the drop-in.** [HIGH for step 3, reproduced. MEDIUM for step 2, which is a timing race that failed 10 of 10 times here]
- **Where:**
  - `.github/workflows/ci.yml:292-301`;
  - `deploy/firewall/docker-veil-turn.conf:4` (`Wants=veil-turn-firewall.service`);
  - `deploy/README.md:137-138`.
- **What is wrong:**
  - **Step 3:** after `systemctl stop veil-turn-firewall`, the job expects `systemctl restart docker` to fail. But the drop-in's `Wants=` makes systemd start the firewall unit again as part of Docker's restart. The rule is loaded, `ExecStartPre` passes, Docker starts, and the job exits 1.
  - So the README sentence "refuses to start Docker if the rule is not loaded" is inaccurate. Docker re-loads the rule itself, and refuses only when the rule *cannot* be loaded (verified: with `/etc/veil-turn.nft` missing, Docker fails).
  - **Step 2:** `systemctl restart nftables` and `systemctl reload nftables` return before the propagated job on `veil-turn-firewall` has finished. The `nft list table` on the next line runs inside that window. Here it failed 10 of 10 times; one second later the rule was present.
- **Scenario:** the job is red on its first run. The TEST_REPORT row for P3R3-5 rests entirely on this job, which has not passed yet.
- **Fix:**
  - Step 2: wait for the propagated job before checking (`systemctl is-active --wait`-style polling, or a short retry loop on `nft list table`).
  - Step 3: either `systemctl mask veil-turn-firewall`, or move `/etc/veil-turn.nft` aside before `restart docker`, so the rule genuinely cannot load. Then expect failure.
  - Reword README L137: "Docker loads the rule when it starts and refuses to start if it cannot".
- **Test:** the corrected job, run once on GitHub. Mutant: put `RequiredBy=docker.service` back, and step 3's `is-active docker` must fail.

**P3R4-3: The TURN rule is silently lost when `nftables.service` is started from inactive, or stopped. The README says it is re-applied on start.** [HIGH, reproduced under systemd 255 with Ubuntu's `nftables.service`]
- **Where:**
  - `deploy/firewall/veil-turn-firewall.service:11-15` (`After=`, `PartOf=`, `ReloadPropagatedFrom=`);
  - `deploy/README.md:135` ("re-applied whenever `nftables.service` starts, restarts or reloads").
- **What is wrong:**
  - `PartOf=` propagates only stop and restart, and `ReloadPropagatedFrom=` only reload. Starting an inactive `nftables.service` runs `flush ruleset` from `/etc/nftables.conf`, and nothing re-applies the rule. The unit stays "active". `nftables.service` is disabled by default on Debian and Ubuntu, so this is the common first-time case.
  - `systemctl stop nftables` stops the unit, which deletes the table, while Docker and coturn keep running.
  - Every restart or reload also leaves a gap of a few milliseconds with no rule.
- **Scenario:** after installing Veil, the operator hardens the VPS with `systemctl enable --now nftables`.
  - From then until the next reboot, anyone with TURN credentials (mailbox creation is open) can relay UDP into every service on `TURN_EXTERNAL_IP`: DNS, Pi-hole, WireGuard and SNMP. That is exactly what P3-8 closed.
  - `nft list table inet veil_turn` fails, but nothing alerts the operator.
- **Fix (either):**
  - Ship an `nftables.service` drop-in with `ExecStartPost=/usr/sbin/nft -f /etc/veil-turn.nft`, plus `ExecReload=` re-listing the original command followed by `/usr/sbin/nft -f /etc/veil-turn.nft`. This makes loading the rule part of nftables' own start and reload.
  - Or document `include "/etc/veil-turn.nft"` in `/etc/nftables.conf`, which loads it atomically, and keep the unit for hosts without nftables.service.
  - In both cases, correct README L135. State that `systemctl stop nftables` removes the protection.
- **Test:** add a CI step that runs `systemctl stop nftables; systemctl start veil-turn-firewall; systemctl start nftables`, waits, then runs `nft list table inet veil_turn`. It must succeed.

**P3R4-4: `VEIL_MAX_CONN_PER_SOURCE` ≤ 8 makes every full `Fetch` fail; the C2 scaling broke it.** [HIGH, reproduced in-process and on the deployed image]
- **Where:**
  - `crates/relay/src/server.rs:178-190` (`set_per_source_connections` scales the share down as well as up);
  - `server.rs:904` (a fetch reserves `limit × (MAX_ENVELOPE + 64)`; 2 050 KiB for `limit: 32`);
  - `server.rs:752-760` (`reserve` refuses when the reservation is larger than the source's share);
  - `main.rs` and `.env.example` accept 1–1024 with no warning.
- **What is wrong:**
  - The share becomes 8 MiB × n/32. For n ≤ 8 that is ≤ 2 048 KiB, smaller than one `MAX_FETCH` reservation, so every `Fetch{limit:32}` is `RateLimited` permanently, even on an idle relay.
  - n = 1 also cuts creation and upload tokens to one per 32 min per source.
  - Before d12d769, lowering the connection cap did not touch these allowances.
- **Scenario:** an operator lowers the cap to 4 or 8 "for safety" on a personal relay. No client can retrieve messages. The deployed smoke test fails at `smoke.rs:58` with `RateLimited`.
- **Fix:** clamp the per-source share to at least one worst-case response, `max(share, MAX_FRAME)` still capped by the relay-wide budget, or scale only upwards (`factor.max(1.0)`). Document what lowering the cap does.
- **Test:** for n ∈ {1, 8, 1024}, `set_per_source_connections(n)` followed by `client.fetch(m, 0)` succeeds. Mutant: drop the clamp, and n = 8 fails.

**P3R4-5: `BlobPut` re-sends are an unthrottled write path that costs no quota. The documented residual write load names only deposits.** [HIGH, measured]
- **Where:**
  - `crates/relay/src/server.rs:989-997` (no rate limit on `BlobPut`, only 50 frames/s per connection × 32 connections);
  - `crates/relay/src/store.rs:755-850` (`put_chunk` rewrites and commits an existing chunk on every re-send until the blob completes);
  - docs: `deploy/README.md:274-277` and the THREAT_MODEL §5 "Resource exhaustion" bullet.
- **What is wrong:**
  - One upload token and one chunk of a two-chunk blob, re-sent forever.
  - Each re-send is a committed 64 KiB write. `STAT_BLOB_BYTES` doesn't change, so no quota ever stops it, and the upload token lasts 24 h.
  - The docs say the writer can be kept busy "with real writes into its own mailboxes: deposits…" and quote 62 ms.
- **Measured:**
  - Release image, one source: 1 433 re-sends/s = **89.6 MiB/s** of commits. Victim deposit p50 rose from 1.1 ms to 22.6 ms.
  - Debug build: 171 ms p50, against the documented 62 ms (also debug).
- **Scenario:** on the Raspberry Pi target, one host saturates the SD card's write bandwidth for 24 h per upload token, at about 7 TB/day of rewrites. That is SD-card wear, not just latency, and it costs the attacker no storage quota.
- **Fix:**
  - Bound chunk writes per upload token in the store. For example, store a put counter in the token record and refuse after `total + 16` puts.
  - Or add a per-token `KeyedLimiter` (for example burst 64, then 50/s).
  - Name this path and its numbers in README and THREAT_MODEL.
- **Test:** a store test showing that put number `total + 17` on one token returns `Quota` or `RateLimited`. Mutant: no counter → fails.

### Low
**P3R4-6: "Requests that change nothing are not written" is not quite true.**
- **Where:** `store.rs:519-536`; `deploy/README.md:239`; `docs/PROTOCOL.md:214`.
- **What is wrong:** `UpdateTokens{add:[X], remove:[X]}` with X already present removes and re-inserts X, then commits. Probe: 30 snapshot-identical commits; 19 of 40 accepted in-process. The per-mailbox limiter bounds it, so the impact is small.
- **Fix:** skip ids that appear in both `add` and `remove`, or reword the claim to "no-op requests".

**P3R4-7: Two counter and schema clauses have no killing test (CLAUDE.md rule 9).**
- **M7:** `remove_mailbox` subtracting all rows instead of the rows over the floor (`store.rs:323`) survives the suite. Every delete or expiry test uses floor 0. My probe kills it, which shows the bug class is real: the counter undercounts and the disk bound breaks.
- **M8:** dropping the `STATS` emptiness check (`store.rs:411`) survives.
- **Fix:**
  - Add a delete and an idle-expiry test with `token_floor_per_mailbox > 0` that checks the over-floor counter.
  - Extend `foreign_schema_is_refused` with a database holding only a `STATS` counter.

**P3R4-8: Leftover doc imprecisions.**
- **Where:** `deploy/README.md:9` and `deploy/README.md:255`, plus the PROTOCOL §14 table.
- **What is wrong:**
  - README L9 and L255 still say IP addresses are held only "for as long as a connection is open" or "while connected". Source-keyed buckets keep them for up to about 31 min after, and about 33 min at n = 1.
  - PROTOCOL §14 omits the Ack limit (20, then 1/s per mailbox) that §6.3 states.
- **Fix:** align these with the README "Relay connections" bullet, and add the Ack row to §14.

**P3R4-9: The README update path now leaves the relay stopped on an existing database.**
- **Where:** `store.rs` (`SCHEMA_VERSION` 2 → 3); `deploy/README.md:173` "Updates".
- **What is wrong:** a v2 database makes `serve` exit with `StoreError::Schema`. The documented `git pull && docker compose build && docker compose up -d` then leaves the relay crash-looping. The DB shares the volume with the TLS key, and moving it aside inside a distroless container is not documented.
- **Fix:** add an "incompatible database" note to Updates, with the exact commands to move `/data/relay.redb` aside while keeping `/data/tls`.

**P3R4-10: The P3R3-9 pattern remains on upload tokens.**
- **Where:** `server.rs:975-983`.
- **What is wrong:**
  - The per-mailbox upload bucket is spent before the per-source check, so a per-source refusal still costs the mailbox a token.
  - When `add_upload_token` returns `Quota`, both buckets have been spent.
- **Fix:** check both buckets with a non-spending peek first, or refund on refusal, as for creation.

## Claims I checked and found accurate
- TEST_REPORT round-3 counts: 74 / 3 / 22+1 / 23 / 1 / 23 / 0+2 / 5, plus fmt, clippy, deny, vet (43/5/207) and gitleaks "no leaks found".
- "Every mailbox keeps a floor of 64": the floor is guaranteed (540 probes, 0 refused). Counters are exact on every path over 30 000 random operations, including delete, idle expiry and FF-prefixed tokens. The relay-wide over-floor rows never pass the cap. An over-cap mailbox can shrink but not grow (M12, M14).
- The "sources needed" table in README and THREAT_MODEL: 1 host in about 37 h, 32, 11, about 60, about 680. All recomputed and correct.
- The no-op early returns for `update_tokens` and `ack`, the `commit` helper as the single commit path, and the per-mailbox UpdateTokens and Ack limits (20, then 1/s; deployed image: 19 ok, 6 refused).
- `would_allow` plus `refund`: refused creations no longer spend the source's allowance (both-removed mutant killed).
- `KeyedLimiter::prune` runs every sweep for all 8 keyed limiters, and source keys are forgotten after refill (M4, M10 killed).
- "Never by IP" is gone everywhere. ARCHITECTURE, PROTOCOL §6.3, THREAT_MODEL §5, `limits.rs` and `server.rs` now describe the source key accurately.
- The gitleaks allowlist covers only `generic-api-key`, only in `Cargo.lock`, and only crate-name pairs. Hex and secret-looking values in a `Cargo.lock` are still reported.
- The schema check requires all 8 tables and `STATS` to be empty. The new image stamps v3, and the deployed smoke test passes.
- Firewall unit:
  - `systemd-analyze verify` is clean;
  - under a real systemd, nftables restart and reload re-apply the rule;
  - stopping the unit no longer stops Docker;
  - Docker fails to start when the rule cannot load.
- The nft rule body is unchanged since round 3; only comments changed. The deployed stack loads it at `priority mangle`.
- 583d14b only narrows the round-trip CI step to `deployed_relay_round_trip`. The soak keeps its own step (`ci.yml:245-247`).
- The `firewall-unit` job pins `actions/checkout` by SHA with `persist-credentials: false`, and the workflow sets top-level `permissions`.

## Claims I could not verify
- The `firewall-unit` job and `relay-deploy` as actually run on GitHub runners. My systemd checks used a stand-in `docker.service` (`sleep infinity`), not Docker Engine.
- Whether the step-2 race (P3R4-2) also fails on a GitHub runner, where `sudo` adds latency. It failed 10 of 10 times here.
- The TURN probes (turnutils, host and Docker-published ports). I did not re-run them, because the rule body is unchanged since round 3.
- The SD-card or arm64 impact of P3R4-5 (measured only on this disk), and IPv6 behind `docker-proxy` (no IPv6 here).
- How the Phase 4 client handles a `RateLimited` Ack or UpdateTokens, and which fetch `limit` it uses (the test helper uses 32).
- A soak or a large DB fill. I did none, because the disk had only 2.1 to 2.5 GB free.

---
**Housekeeping:**
- **Git:** working tree clean (`git status --short` empty), HEAD still 583d14b. Nothing was committed or pushed.
- **Docker:** I ran `docker compose down -v` (volume `veil_relay-data` and network removed) and removed the anonymous volume my deploy created (`3c01f0b5…`). The throwaway `r4sysd` container and the `r4-systemd` and `ubuntu:24.04` images are gone.
- **Files:** `deploy/.env` and `deploy/secrets` are deleted. `nft delete table inet veil_turn` is done; only the pre-existing ip/ip6 tables remain. The temporary tests and the store probe are removed or reverted, and `/tmp/veil-r4-*` is deleted.
- **Left behind:**
  - incremental build artifacts in the git-ignored `target/` (the free disk went from about 2.5 GB to 2.1 GB);
  - probe sources in `/tmp/claude-0/-home-user-ataraxia/929457e9-49df-558b-9ee2-363e38c8130c/scratchpad/r4/`.

## Final gate, round 1: Phase 4 client, app, release workflow (2026-10-19)

**Reviewer:** independent code-reviewer agent (adversarial gate). Scope: `crates/client`, `app/`, `.github/workflows/release.yml`, `deny.toml`, spot-check of d158de3, docs honesty. HEAD = `0b0d8c6` + docs commit.

## Veil final review gate: Phase 4 (client, app, release) and spot-check of the Phase 3 round-4 fixes

VERDICT: FAIL

**Scope read in full:** `crates/client/src/{relay,db,keystore,service,qr,lib}.rs`, `crates/client/tests/pair_and_message.rs`, `app/src/**`, `app/scripts/lint.mjs`, `app/index.html`, `app/src-tauri/{src/lib.rs,tauri.conf.json,capabilities/default.json,Cargo.toml}`, `.github/workflows/release.yml`, `deny.toml`, the d158de3 diff, the relevant sections of ARCHITECTURE, INVARIANTS and TEST_REPORT, and the `Account::open` path in core.

**Commands run (read-only):**
- `cargo test -p veil-client`: 4 unit tests and 1 integration test, all pass.
- `cargo clippy -p veil-client --all-targets -D warnings`: clean.
- `pnpm typecheck` and `pnpm lint`: clean.
- The four new round-4 relay tests: pass.

The result is FAIL because of five High findings. Two of them let the relay or contacts beat the lock, one makes setup permanently unusable, one sends both vault factors to cloud backup by default, and one exposes the release signing key and release-signed builds of unreviewed branches. The pin verifier, the CSP and the shape of the IPC surface are sound (see "Verified good" at the end).

---

### High

**P4-1 (High): a hostile relay can freeze the client actor forever, so Lock, auto-lock and unlock never complete.** `crates/client/src/service.rs:988-1037`
- **What happens:** `sync()` loops for as long as `Fetch` returns a non-empty batch. It never checks that `seq > after`, and there is no limit on batches per sync.
- **Scenario 1:** the relay returns the same items with `seq <= last_seq`. `last` stays equal to `after`, so the loop repeats forever. Each round also does a DB write and an `Ack`.
- **Scenario 2:** the relay hands out an endless stream of junk items with increasing `seq`. The loop never ends either.
- **Why this matters:** the actor runs commands and ticks only between `sync()` calls (`run`, L366-388). While it loops:
  - `Cmd::Lock` waits in the queue and the "Lock now" button hangs;
  - `on_tick` never runs, so auto-lock never fires;
  - `unlock()` never returns, because it awaits `connect()`, then `sync()`.

  The account, the open SQLCipher handle and the mailbox key stay in memory for as long as the relay wants.
- **Fix:**
  - In the batch loop, ignore any item with `item.seq <= after` and stop when `last == after`.
  - Allow at most N batches per sync (e.g. 16), then return and let the next push or tick continue.
  - Check the auto-lock deadline inside `sync`, `retry_failed` and `connect`.
  - Better: make Lock pre-emptive. Run relay I/O as a cancellable future in the `select!` alongside `rx.recv()`, so a Lock or tick can drop it.
  - Add a test with a fake relay that replays stale `seq` values.

**P4-2 (High): background events count as user activity, so a contact or the relay can keep the vault unlocked indefinitely.** `app/src/App.tsx:127-134`, `app/src/screens/Chats.tsx:87-96`, `service.rs:435-437`
- **What happens:** every `veil://changed` event makes the UI call `ipc.contacts()` and `ipc.me()`. A `messages` event with the chat open also triggers `ipc.messages()` and `ipc.markRead()`. All of these reset `last_activity`; only `Cmd::State` is exempt.
- **What emits those events:**
  - every incoming message (`process`, L1069);
  - every successful reconnect (`connect`, L425);
  - every dropped connection (`disconnected`, L411).
- **Scenario:** a contact sends one message every 4 minutes, or the relay accepts the connection and drops it every 4 minutes. The device then never locks.
- **Docs that overclaim:** ADR-0011 ("auto-lock after 5 minutes idle") and Settings ("locks itself after 5 minutes without use").
- **Fix:**
  - Count only user-initiated commands as activity. Add an explicit `touch` command fired from real UI input (pointer, key or focus events), or an `activity: bool` flag on commands that UI refreshes set to false.
  - Add a test: with no user commands, a stream of incoming messages still locks the vault after `AUTO_LOCK`. Use a test-configurable `AUTO_LOCK`.

**P4-3 (High): setup is not crash-safe, and after a partial setup or a reinstall the app can never be set up again.** `service.rs:521-534`, `keystore.rs:211-235`
- **What happens:** `keystore::store` runs before the Argon2 `vault::create` (seconds on mobile), `Db::open`, `Account::create` and the settings writes. "Setup complete" is defined only by the presence of `vault.hdr`.
- **Failure 1, any later step fails or the app is killed mid-setup:**
  - on Android and Linux, `device.secret` already exists and the next setup fails at `create_new` with `Storage`;
  - on Windows, `store` returns `AlreadySetUp`;
  - a leftover `veil.db` under the old key makes `Db::open` report "Wrong passphrase" during setup.

  The state stays `New` forever, and no reset command exists.
- **Failure 2, Windows reinstall:** the NSIS uninstall, or the user deleting `%APPDATA%`, leaves the Credential Manager entry behind. Every setup after that fails with "Veil is already set up". This is the path the Unlock screen recommends ("start over with a new identity"), and it cannot work.
- **Smaller issue:** `vault.hdr` is written with `std::fs::write`, with no temp file, rename or fsync. A torn write leaves the state `Locked` with an undecodable header.
- **Fix:**
  - In setup, when no header exists, treat any existing device secret and DB as debris: overwrite the keyring entry, delete `device.secret`, `veil.db` and its `-journal`.
  - Write the header with temp file, fsync, rename, then fsync the directory.
  - Add a `reset` command behind an explicit confirmation, so "start over" actually works.
  - Test: inject a failure after `keystore::store`, then confirm a second setup succeeds.

**P4-4 (High): Android backs up both vault factors off the device by default.** Generated manifest (no `gen/android` committed; `release.yml:100` runs `tauri android init --ci`)
- **What happens:** the Tauri 2.12 template manifest (checked in the CLI binary strings) has no `android:allowBackup="false"` and no `dataExtractionRules`. `app_data_dir` on Android is `activity.dataDir` (`tauri-2.12.4/.../PathPlugin.kt:57`), which is in Auto Backup's default scope. So `device.secret`, `vault.hdr` and `veil.db` all go to Google Drive backup, and on Android 12+ to device-to-device transfer.
- **Effect:** for anyone with access to the backup, the vault comes down to the passphrase alone, contrary to INV-REST-2 and the keystore.rs comment ("protected by the OS app sandbox"). INVARIANTS calls Android "partial" but never mentions backups.
- **Fix:**
  - Commit `gen/android`, or patch the manifest in CI, with `android:allowBackup="false"` and `android:dataExtractionRules` / `fullBackupContent` excluding everything in the `root`, `file` and `database` domains for both cloud backup and device transfer.
  - Alternatively, put `device.secret` under `noBackupFilesDir`.
  - State this in INV-REST-2.

**P4-5 (High): the release signing key is exposed to every branch push and to all build-time third-party code, and unreviewed branches produce release-signed APKs.** `.github/workflows/release.yml:18-26, 96-141`
- **Branch pushes get the key:** `push: branches: ["**"]` runs the android job, and the Sign step gets `ANDROID_KEYSTORE_*` from repo-level secrets.
  - Anyone with push access can change `release.yml` on a branch and dump the keystore.
  - Every branch build uploads a production-signed APK as an artifact, downloadable by any GitHub user for 7 days on a public repo. Those APKs update real installs in place.
- **Signing happens next to untrusted code:** signing runs in the same job, right after `pnpm install` plus `tauri android build`, i.e. npm scripts, cargo build scripts and Gradle plugins. That code can append to `$GITHUB_PATH` or `$GITHUB_ENV` to shadow `base64` or `apksigner` in the Sign step, and read the keystore.
- **Fix:**
  - Run signing only on `refs/tags/v*`, in a separate job with `environment: release` (protected, required reviewers, secrets scoped to the environment).
  - That job should download the unsigned APK artifact and run no project code.
  - Branch builds should upload unsigned APKs, or ones signed with a throwaway key.

---

### Medium

**P4-6 (Medium): message and contact loss when storage fails or the app crashes between the core commit and the app-table write.** `service.rs:1017-1022, 1039-1094, 830-862`
- **Messages:** `Account::open` commits the ratchet in its own transaction (core `account.rs:659-670`) before `INSERT INTO messages`. If the insert fails (disk full) or the app crashes, `sync` treats it as transient (`Err(Storage)`, no ack). The retry then fails as a duplicate, gets mapped to `Protocol`, and is acked. The message is gone, which contradicts the comment at L1018.
- **NewContact:** the same applies: core creates the contact and deletes its invite, but the `contacts` row may be missing. All later messages from that contact are then dropped silently at L1062.
- **Pairing:** in `accept_invite`, a crash after `redeem_invite` and before `upsert_contact` has the same effect.
- **Fix:**
  - Do the core commit and the app-table writes in one SQLite transaction (SAVEPOINT on the shared connection, with `SqlBackend::apply` nested inside).
  - Or, in `process`, create the missing `contacts` row on demand whenever core reports a known contact.
- **Also due:** the backend-conformance test for SqlBackend that the Phase 2 review (H2) asked for is not shipped.

**P4-7 (Medium): the shipped app's dependency tree is outside every supply-chain gate.** `app/src-tauri/Cargo.toml:231` (its own `[workspace]`), `release.yml:102,171`
- `cargo deny`, `cargo audit`, `cargo vet` and clippy in `ci.yml` cover only the root workspace. The Tauri tree (`app/src-tauri/Cargo.lock`, several hundred crates) is never checked.
- `pnpm audit` is not run anywhere, although INV-SUP-2 lists it.
- Release builds call `tauri build` without `--locked`, so lock drift is silently resolved in CI (against INV-SUP-1).
- ADR-0011's "the only OpenSSL in the tree, enforced by `deny.toml`" holds only for the root workspace.
- **Fix:**
  - Run deny, audit and vet with `--manifest-path app/src-tauri/Cargo.toml`, plus `pnpm audit --prod`, in CI.
  - Build with `pnpm tauri build -- --locked` and `pnpm tauri android build ... -- --locked`.

**P4-8 (Medium): Android saves plaintext screenshots outside the vault.** `MainActivity` has no `FLAG_SECURE`, so the recents snapshot of an open chat is written to disk by the OS (non-negotiable 6). Screenshot blocking was not among the features cut in ADR-0011. **Fix:** set `WindowManager.LayoutParams.FLAG_SECURE` in the generated `MainActivity` (same commit-`gen/android` change as P4-4).

**P4-9 (Medium): docs overclaim or are missing.**
- **No Phase 4 test report:** `docs/TEST_REPORT.md` has no Phase 4 section with real command output (CLAUDE.md process).
- **THREAT_MODEL L69 overclaims:** it says the relay learns who you talk to "Not directly… unlinkable tokens; timing correlation possible". The v1 client deposits on its own authenticated connection (`service.rs:842, 951`), and mailbox rotation is cut. The relay therefore sees exact pairs of static mailboxes plus IPs. Onboarding's "Who you talk to: the relay sees random mailbox ids" is misleading for the same reason.
- **Auto-lock claims:** ADR-0011 and Settings claim an auto-lock that P4-1 and P4-2 defeat.
- **INV-UI-1:** cites an "ESLint rule" and `pnpm -C app test`/`e2e`. No ESLint is present, `package.json` has no test script, and the app has zero tests.
- **Fix:** add the Phase 4 TEST_REPORT section, and correct THREAT_MODEL, the onboarding text and the INVARIANTS rows to match the code.

---

### Low

**P4-10 (Low): an invite can be burned by a failure.** `service.rs:817-848`: `TakeInvite` deletes the invite at the relay before `take_token`, `redeem_invite` and `Deposit`. Any failure after that point (for example a relay timeout) burns the invite. **Fix:** obtain the token before `TakeInvite`, and show a specific "ask for a new invite" error.

**P4-11 (Low): contact names can be spoofed.** `clean_name` (L267) filters only `is_control()` (category Cc). Bidi overrides and zero-width characters (Cf) pass. An attacker-chosen `display_name` from NewContact can therefore imitate an existing contact's name. **Fix:** also strip `Cf`, and the U+202A–202E and U+2066–2069 ranges.

**P4-12 (Low): IPv6 relay addresses fail.** `relay.rs:196` builds `wss://{host}/` with the brackets removed, so `[::1]:8443` gives the invalid URL `wss://::1/`. Also, `split_host_port` accepts unbalanced brackets. **Fix:** keep the brackets for IPv6 hosts in the URL, and require them to be balanced.

**P4-13 (Low): webview hygiene.**
- After a lock, `App` keeps `contacts` (120-character plaintext previews) in React state. **Fix:** clear them on `locked`.
- `Chat.send` has no in-flight guard, so pressing Enter twice sends twice. **Fix:** add `isPending`.
- `ipc.messages(...).then` and `ipc.lock().then` have no rejection handlers.
- The `ipc.ts` header refers to a `commands.rs` that does not exist.

**P4-14 (Low): workflow nits.**
- `inputs.tag` is not validated; a value starting with `-` is parsed by `gh release create` as a flag. **Fix:** check against `^v[0-9][0-9A-Za-z.\-]*$`.
- `choco install protoc` has no checksum.
- Failed deposits that are permanently rejected (for example `Unauthorized`) are retried on every reconnect forever (`retry_failed`, L968). **Fix:** cap the retries.

**P4-15 (Low): Phase 3 round-4 spot-check.**
- **Real, and the four tests pass:** P3R4-4 (the factor is clamped to ≥ 1), P3R4-5 (put counter at byte 41, `MAX_EXTRA_PUTS`, schema v4), P3R4-7 (M7/M8 tests).
- **Residual race in P3R4-10:** `would_allow` and `allow` take separate locks, and the result of `allow` is ignored (`server.rs:980-986`), so concurrent requests can exceed the bucket. **Fix:** do the check-and-take for both buckets under one lock, and act on the result of `allow`.
- **Wording:** TEST_REPORT says "Docker loads the rule when it starts". The drop-in only checks (`ExecStartPre=nft list table`); `Wants=` starts the unit, but does not reload the table if the unit is still active.
- **Not yet verified:** the `firewall-unit` CI job is still "first run pending".

---

### Verified good
- **Pin verifier:** TLS 1.3 only (`with_protocol_versions(&[TLS13])`), no CA fallback, constant-time pin compare. CertificateVerify is checked by webpki over the same cert, so a parser differential cannot pick a different SPKI from any cert webpki accepts.
- **Relay framing:** frames are size-limited and strictly decoded, the push queue is bounded, pending calls time out, and every response is type-checked by its caller.
- **IPC surface:** only view types. No paths, keys or ciphertext cross. Errors are content-free strings.
- **CSP:** strict, with no inline or remote sources, `freezePrototype` on, no Tauri plugins, and capabilities limited to `core:event:default`.
- **No HTML injection in the webview:** all text is rendered as React text nodes, and the QR code is drawn as SVG rectangles.
- **Encryption at rest:** SQLCipher with `temp_store=MEMORY` and log level `NONE`, and a plaintext-canary test over the data directory.
- **RNG wiring:** every core call receives `OsRng` (the item the Phase 2 review asked to check).
- **Identity changes:** addresses are key hashes, so a changed key becomes a new, unverified contact and is never auto-accepted.
- **Invite single use:** enforced at the relay, in core (invite record deleted) and in the app's `invites` table.
- **Locking drops all session state:** the account, the DB `Rc` and the mailbox key.

## Final gate, round 2 (2026-10-19)

**Reviewer:** independent code-reviewer agent. Scope: verification of commit `087a72a` (fixes for P4-1 to P4-15) and new findings.

VERDICT: PASS WITH CONDITIONS

I found no Critical or High issues in the shipped scope. All five round-1 Highs are fixed in code, and the regression tests for P4-1, P4-2 and P4-3 pass. The fixes introduced one Medium regression (P4R2-1) and left one Medium edge case (P4R2-2). P4-5 depends on GitHub repository settings that I cannot see from the repo (P4R2-3).

What I ran:
- `cargo test -p veil-client --locked`: 4 unit, 3 in `lock_and_setup`, 1 in `pair_and_message`, all pass.
- `cargo test -p veil-relay --locked`: 25 lib, 24 relay, 1 logs, all pass.
- `cargo clippy -p veil-client -p veil-relay --all-targets --locked -- -D warnings`: clean.

I did not edit any files.

### Round-1 findings

| # | Status | Note |
|---|---|---|
| P4-1 | Fixed | Every relay round trip goes through `interruptible()`, and it is correct. Notify is enabled before the pending flag is checked, so a lock cannot slip in between. The auto-lock deadline is also a select branch. `sync` skips items with `seq <= last`, stops when nothing advances, and runs at most 16 batches before continuing on the next tick. `lock_now` clears the pending flag. The only way the flag sticks is if the `lock()` future is dropped before its command is sent, which Tauri does not do (no fix needed). `setup`'s relay calls are not interruptible, but they are bounded by the connect and call timeouts and no session exists yet. The actor runs one command at a time (`handle` is awaited inside the select arm), so nothing can interleave inside a savepoint. |
| P4-2 | Fixed | Only setup, unlock, touch, send, create and accept invite, verify and rename count as activity. The UI sends `touch` on pointer, key, wheel and touch input, at most every 20 s. Refreshes, `mark_read` and `me` do not count. |
| P4-3 | Fixed | `setup` checks `state()==New` before `wipe()`, so an existing vault is never wiped. Debris is wiped, the header is written via temp file + fsync + rename + directory fsync, and the device secret via temp file + rename. On Windows, `set_secret` overwrites any leftover credential and `delete_credential` treats `NoEntry` as success. Reset sits behind a two-step confirmation. Nit: `wipe()` does not remove `*.tmp` leftovers. |
| P4-4 | Fixed (pending CI) | `harden.py` sets `allowBackup=false` and excludes every domain in both cloud backup and device transfer; `aapt2` checks the built APK's manifest. The first CI run is still pending. |
| P4-5 | Partially | The workflow side is right: build jobs have no secrets, and signing runs in `environment: release` with no checkout. It is only safe if the `release` environment and tags are restricted in the repo settings and the old repo-level secrets are deleted, none of which the repo can show (P4R2-3). |
| P4-6 | Partially | Using savepoints is correct: the core's overlay is cleared on commit and it reads from the backend, so a rollback leaves no stale in-memory state. However, the change to pairing created P4R2-1, a failed RELEASE can leave a savepoint open (P4R2-2), and there is still no SqlBackend conformance or crash test. INV-STATE-1 says so honestly. |
| P4-7 | Partially | `cargo deny` and `cargo audit` now cover `app/src-tauri`, `pnpm audit --prod` runs, and builds use `--locked`. `cargo vet` still does not cover the app tree; INVARIANTS says so. It is unconfirmed that `-- --locked` actually reaches cargo for `tauri android build`. |
| P4-8 | Fixed (unverified on device) | `harden.py` sets FLAG_SECURE before `super.onCreate`. CI does not check that it reached the APK. |
| P4-9 | Fixed | THREAT_MODEL "who you talk to", the onboarding text, ADR-0011, INV-UI-1, INV-SUP-2 and the Settings text are all now accurate. TEST_REPORT states what was not verified. |
| P4-10 | Fixed | The token is now taken before `TakeInvite`. |
| P4-11 | Fixed | Cf, bidi and variation-selector characters are now stripped from names. |
| P4-12 | Fixed | IPv6 hosts are bracketed in the URL, unbalanced brackets are refused, and there are tests. |
| P4-13 | Fixed | App state is cleared on lock (event and Settings), sends have an in-flight guard, rejections are handled, and the header comment is corrected. |
| P4-14 | Partially | The tag is validated and message retries are capped at 20. Still open: `choco install protoc` has no checksum, and introduction retries have no cap (see P4R2-1). |
| P4-15 | Fixed | Both rate buckets are checked and taken under both locks, and the result of `allow` is acted on. No deadlock risk: the only other places those two mutexes are taken (`prune_limiters`, `source_keys_tracked` and the refund path) take them one at a time. |

### New findings

**P4R2-1 (Medium): first messages after pairing can be silently lost** `[HIGH]`
- **Where:** `crates/client/src/service.rs:1033`, `:1146`, `:1199-1206`.
- **What happens:** `accept_invite` now commits the contact and stores the introduction for retry, even when sending the introduction fails. The contact then shows up in the UI. Nothing stops `send` before the introduction is out: `deliver()` deposits the message straight away, and `retry_failed` sends the messages even when that contact's introduction just failed in the same pass.
- **Why the message is lost:** the inviter's core cannot place a message from someone who is not a contact yet. It finds the invite, decrypts, sees the body is not a `ContactIntro` and returns `InviteInvalid` (`crates/core/src/account.rs:672-688`). The client maps that to `Protocol` and acks it, so the relay deletes it.
- **Scenario:** a brief network drop at pairing, then the user types "hi". The sender sees "sent"; the recipient never gets it.
- **This is a regression:** before the fix, a failed introduction failed the whole `accept_invite`, so the user had no contact to write to.
- **Fix:** in `deliver()`, check the contact's `intro` column first.
  ```rust
  if intro_pending(contact) && !self.deliver_intro(contact).await {
      mark_failed(message);
      return false;
  }
  ```
  Then cap introduction retries the same way as messages.

**P4R2-2 (Medium): a failed RELEASE can leave a transaction open, losing acked messages** `[MEDIUM]`
- **Where:** `service.rs:1042-1049` and `db.rs:137-155`.
- **What happens:** if the end statement fails, the code just returns `Err` via `?`. On disk-full, IO error or busy, SQLite does not always roll back on its own, so the outermost savepoint can stay open.
- **Effect:** every later `SAVEPOINT veil_op … RELEASE veil_op` only releases inside that open transaction and never commits. `sync` keeps acking messages to the relay, and they are lost when the app locks or crashes. Disk-full is exactly the scenario P4-6 was about.
- **Fix:** in `atomically` (always the outermost), on any error after the savepoint opened, run `if !conn.is_autocommit() { conn.execute_batch("ROLLBACK") }` and return `Storage`. Add a SqlBackend test that nests `apply` inside an outer savepoint and checks both commit and rollback.

**P4R2-3 (Condition, would be High if unmet): signing-key isolation depends on repository settings**
- **Where:** `release.yml:196-243`.
- **What happens:** anyone with push access can add `environment: release` to a job on a branch, or dispatch the workflow with `inputs.tag` from a branch. They can also push a `v*` tag on an unreviewed commit. Any of these reaches the key or produces a signed release unless the repo settings stop it.
- **Fix:** in the repo settings:
  - restrict the `release` environment's deployment refs to `v*` tags and require reviewers;
  - add a tag ruleset for `v*`;
  - delete the old repo-level `ANDROID_KEYSTORE_*` secrets.

  Then document these settings in ARCHITECTURE §7 or the README. Nothing in the docs states them today.

**P4R2-4 (Low): the signed APK is probably no longer 16 KB page-aligned** `[MEDIUM]`
- **Where:** `release.yml:230`.
- **What happens:** the old `-P 16` flag was dropped. `zipalign` rewrites the archive, so uncompressed `.so` files probably end up only 4-byte aligned.
- **Effect:** depending on how the template packages native libraries (not checked), the APK may fail to install or load. This would affect 16 KB-page devices in particular.
- **Fix:** restore `-P 16` (or `-p`) and add `zipalign -c -P 16 4 out/Veil-android-arm64.apk` as a check.

**P4R2-5 (Low): the Windows build can carry on after a failed command**
- **Where:** `release.yml:166-187`.
- **What happens:** in pwsh steps only the last native exit code counts, so a failed `pnpm install` or `choco install` does not stop the step.
- **Fix:** set `$PSNativeCommandUseErrorActionPreference = $true`, or check `$LASTEXITCODE` after each command.

### Docs
THREAT_MODEL, INVARIANTS (REST-2, UI-1, SUP-2, STATE-1) and ADR-0011 now match the code. TEST_REPORT says what it did not verify (no stale-`seq` fake-relay test, no crash-injection test, CI runs pending, no device testing). I could not check its mutation-testing claims without re-running them.

### Conditions for PASS
1. Fix P4R2-1.
2. Fix P4R2-2.
3. Confirm and document the P4R2-3 repository settings before the first `v*` tag.

Before the first release, also confirm the first CI runs of the `aapt2` manifest check and of `app-supply-chain`, and check the APK's alignment (P4R2-4).

## Unlock options gate, round 1: PIN or password, biometric unlock, Purge PIN (2026-10-25)

**Reviewer:** independent code-reviewer agent. Scope: `git diff 9a4da71..dc4a7a6`.

VERDICT: FAIL

Scope: `git diff 9a4da71..dc4a7a6`, 23 files. I read every changed source file. I also checked the vendored Tauri 2.12.4 source: the IPC ACL check in `webview/mod.rs` L2051-2110, and `path/{mod,android}.rs` with Tauri's Android `PathPlugin.kt` for `app_data_dir`. `cargo test -p veil-client -p veil-core --locked` passed: client 7 / 3 / 1 / 4, core 76 / 3 / 22 (+1 ignored). I edited nothing. The gate fails because of two High findings (U-1, U-2).

### Findings

**U-1 High [HIGH on scope, MEDIUM on runtime effect]: on Android, `wipe()` now deletes the whole app sandbox, and setup calls it.**
`crates/client/src/service.rs:746` (wipe), `:799` (`self.wipe()?` in setup), `:870` (purge).
- `dir` is `app.path().app_data_dir()`. On Android, Tauri resolves that to `activity.dataDir` (`/data/user/0/org.veil.app`), because there is no `<bundle id>` suffix without an override.
- The new `read_dir` + `remove_dir_all` therefore deletes `app_webview/` (the running WebView's profile), `shared_prefs/`, `cache/`, `code_cache/`, `files/`, `no_backup/` and any `lib` link. Before this change, wipe removed five named files.
- Scenario 1: first-run setup on Android. Chromium is writing into `app_webview/` at the same moment, so `remove_dir_all` hits ENOTEMPTY or EBUSY. `failed` is set, setup returns `Storage`, and setup can fail on every attempt.
- Scenario 2: Start over or Purge. The running WebView's storage is deleted from under it, which can leave a blank or crashed WebView. That is visible to an observer.
- The integration tests use a tempdir, so they cannot catch either case.
- Fix: delete an explicit list of Veil's own files (header, `veil.db{,-wal,-shm,-journal}`, `device.secret`, `unlock.cfg`, `attempts`, `purge.tag`, `bio.wrap`, `bio.sealed`, plus their `.tmp` files). Leave WebView and system state to `finish_purge`. Longer term, move the vault into its own subdirectory with a migration.

**U-2 High: the crypto-erasure claim is false on Android.**
`docs/ARCHITECTURE.md:227`, INV-REST-6, and the Settings banner (`Settings.tsx:105`).
- The ADR says deleting the device secret and the header makes "leftover flash blocks unreadable".
- On Android, `device.secret` is a plain file; `keystore.rs` itself says "Not hardware-backed".
- Unlinking a file does not erase flash, and file-based encryption keys outlive the file. A physical image of a phone in the after-first-unlock state can recover the old `device.secret`, header and database blocks. A 6-digit PIN then falls to an offline search of 10^6 Argon2id runs, which parallelises easily.
- Only the biometric Keystore key really gets destroyed.
- Fix:
  - Now: correct the ADR, INV-REST-6 and the UI text ("deletes Veil's files; a forensic copy of the phone's storage may still recover them, especially with a PIN").
  - Proper fix: wrap the device secret with a non-biometric Android Keystore key and delete that key on purge (the existing follow-up for INV-REST-2).

**U-3 Medium: the Purge PIN is ignored during an attempt delay.**
`service.rs:850`, and `Onboarding.tsx` (`disabled={busy || wait > 0 ...}`).
- `unlock` returns `RetryLater` before it evaluates the purge tag, and the UI disables the field.
- Scenario: a coercer makes the owner enter six wrong codes. The duress code then cannot be used for 30 s, and up to 1 h after more failures.
- Fix: while a delay is active, still run Argon2id and check only the purge tag. Throw away the KEK result and answer `RetryLater` either way. This tells the caller nothing about the passphrase.

**U-4 Medium: after a purge, the device does not behave like a wrong attempt, and the docs overclaim.**
`service.rs:923` (unlock_info), `lib.rs` `finish_purge`, `Onboarding.tsx` Unlock.
1. If the fingerprint button is showing, pressing it returns "Biometric unlock is not available on this device", and the button then disappears. `unlock.cfg` is gone, so `bio_sealed` returns `None`.
2. `attempts` is deleted, so the wait banner a real wrong attempt would trigger never appears.
3. The next app start shows Setup with the default theme.
4. On Android, see U-1.
5. The purge path does a disk wipe, a Keystore deletion and `clear_all_browsing_data` before it answers. A wrong attempt instead does two fsyncs. Small timing difference.

The UI's "Anyone watching sees only 'Wrong PIN'" holds only for that one moment. Fix:
- Have the actor keep the last `UnlockInfo` in memory after a purge and serve it until the process exits.
- Make `unlock_biometric` after a purge fail with the same `Cancelled` or `Failed` result a real failure gives.
- Optionally keep a decoy `attempts` count.
- Document that Veil looks newly installed from the next launch.

**U-5 Medium: a crash during `change_secret` can lock the owner out.**
`service.rs:976` and after (header written before `unlock.cfg`), `ui.tsx:127`.
- Scenario: the owner switches from PIN to password. The process dies after the header write but before `store_config`.
- On restart, the config still says PIN, so `SecretField` strips every non-digit. The new password cannot be typed and the only way out is "Start over".
- Neither write order is safe in both directions.
- Fix: on the lock screen, do not filter characters (keep `inputMode="numeric"` only as a hint), and/or add a "Use keyboard" switch. Alternatively, keep `kind` in the same atomic write as the header.

**U-6 Low: `purge_set` and `purge.tag` can disagree after a crash.**
`service.rs:974` and `:994` (random tag written, then the database flag).
- A crash between the two writes leaves Settings saying "Purge PIN is set" while no tag is live, so the owner relies on a duress code that does nothing.
- Fix: in `clear_purge` and `change_secret`, write `purge_set=0` first and then replace the tag. In `set_purge`, keep tag first, then flag.

**U-7 Low: the attempt delay depends on the wall clock.**
`unlock.rs:113`.
- Setting the clock forward skips the delay.
- A failure recorded while the clock was far ahead (wrong RTC date, user correction) gives a wait of `last + delay - now`. That can be days or years, and only biometrics or Start over get the owner back in.
- Fix: `if last > now { last = now }`, and cap the result at `delay_for(n)`. Mention the clock bypass in INV-REST-8.

**U-8 Low: off-by-one in the delay docs.**
`unlock.rs:102`. `delay_for(6)=30`, so six wrong tries are free, not five. The test loops `0..6`. The ADR, INV-REST-8 and the doc comment say 5. Fix: use `checked_sub(FREE_ATTEMPTS)`, or change the docs to 6.

**U-9 Low: biometric repair after a failed re-enable.**
`lib.rs` `biometric_enable`, `service.rs:998`.
- `bio_prepare` overwrites `bio.wrap`, and Kotlin `newKey()` deletes the old Keystore key before the prompt.
- If `biometric_commit` then fails, the config still says biometric is on. The old `bio.sealed` decrypts to `FAILED` (not `KEY_GONE`), so biometrics never auto-disable.
- A failed seal also leaves the new Keystore key behind.
- Fix: on any error after prepare, call `biometric_disable()` and `native::delete_key()`. In `bio_prepare`, set `biometric=false` and remove `bio.sealed` first.

**U-10 Low: Kotlin secret handling and errors.**
`VeilNativePlugin.kt:126`, `:136-154`.
- `secret` is not zeroed when the prompt fails or is cancelled.
- The base64 `String`s (`SealArgs.secret`, the resolved `secret`) and the serde_json copies on the Rust side cannot be wiped.
- Every `onAuthenticationError` is mapped to `CANCELLED`, so biometric lockout shows nothing (the UI hides "Cancelled").
- Fix: zero `secret` in `onAuthenticationError`. Map `ERROR_LOCKOUT` and `ERROR_LOCKOUT_PERMANENT` to `FAILED` with a message. Note the unwipeable copies under INV-REST-4.
- The Kotlin code has not run on a device; TEST_REPORT says so honestly.

**U-11 Low: the screenshot toggle was not requested and is not documented.**
`lib.rs` `set_screenshots_allowed`, Kotlin `ALLOW_SCREENSHOTS`.
- It lifts `FLAG_SECURE`, which exposes the app to screenshots and the recent-apps thumbnail. It is not in ADR-0012 or INVARIANTS.
- The command also works while Veil is locked.
- Fix: get owner sign-off, record it in ADR-0012, and require an unlocked session in Rust.

**U-12 Low: biometrics weaken the duress model, and this is not documented.**
- The lock screen prompts for a fingerprint as soon as it opens, and a coercer can force a finger without ever meeting the Purge PIN.
- Fix: state this in ADR-0012 and in the Purge PIN banner ("turn off fingerprint unlock if you rely on the Purge PIN").

**U-13 Low: the purge path ignores wipe errors.**
`service.rs:870`. It reports `Purged` even if both the header unlink and the device-secret removal failed (for example a Windows file lock or AV handle). The vault would then still open, while the UI says "wrong PIN". Fix: delete the device secret and header first and retry, then the rest. Write an error-free log marker only if nothing else is possible.

**Nit:** `vault.rs` around L628. The doc comment "Known-answer test against an independent Python oracle" is now attached to `purge_tag_one_kdf_run_decides` instead of `known_answer_unlock`.

### Verified good
- **Purge tag:**
  - It uses the same `Argon2id || device_secret` input as the KEK, with a separate HKDF label (`veil/v1/purge-tag`), so offline it is no weaker an oracle than the header.
  - It is compared in constant time (`subtle`), and the passphrase is always checked first.
  - `purge_tag` refuses an input that opens the vault.
  - Changing the PIN or password re-salts the header; the old tag is replaced before the new header is written, so a crash cannot leave a live tag that matches the new secret.
  - A random tag is stored when no Purge PIN is set.
  - The `Debug` output is redacted.
- **Secret wrap:**
  - 24-byte random nonce; AAD binds the label and the vault id.
  - Exact length check before parsing, version byte checked, `split_at_checked`, no indexing.
  - Errors are mapped so they say nothing; the bit-flip test covers the whole blob.
- **Where Purge can trigger:** only from the lock screen. Settings checks use `vault::unlock`, and `unlock` returns early while a session is open.
- **Delay paths:** `verify_current` counts failures, so Settings cannot be used to guess faster. The actor runs one command at a time, so there is no counter race.
- **Webview cannot reach the native plugin:**
  - Tauri 2.12.4 rejects any `plugin:` IPC call without an ACL entry (`webview/mod.rs` L2080-2109).
  - `capabilities/default.json` grants only `core:event:default`, and the runtime-built `veil-native` plugin has no permission manifest.
  - The biometric secret and sealed blob stay in Rust; IPC returns only `()`, flags and content-free error strings.
- **Keystore key settings:**
  - AES-256-GCM key requiring user authentication on every use (timeout 0 with `AUTH_BIOMETRIC_STRONG`, or `-1` before Android 11).
  - Invalidated when new biometrics are enrolled; `BIOMETRIC_STRONG` with a `CryptoObject`.
  - `KeyPermanentlyInvalidatedException` deletes the key and returns `KEY_GONE`, after which Rust turns biometrics off.
- **Rust zeroization:** the secret, the decoded base64 and the IPC string fields are `Zeroizing`.
- **UI:**
  - Biometric auto-prompt is guarded by a ref, the countdown timer is cleaned up, and the password field is cleared on failure.
  - Labelled inputs, native radios in `Segmented`, `role="switch"` with the description linked, and 44 px targets via `--tap-min`.
- **Docs:** TEST_REPORT and INV-REST-7 honestly say the Kotlin code has not run on a device.

## Unlock options gate, round 2 (2026-10-25)

**Reviewer:** independent code-reviewer agent. Scope: `git diff dc4a7a6..e21fee9`.

VERDICT: FAIL

**Scope:** `git diff dc4a7a6..e21fee9` (19 files). I read every changed source file and checked the vendored `tauri-2.12.4` (`app.rs` L2607/L2688, `plugin/mobile.rs` L332-358 and the Android `run_command`). `cargo test -p veil-client --locked --offline` passes: 8 / 3 / 1 / 4. I edited nothing. The gate fails on UR2-1, a High data-loss regression in the new device-secret file format.

### Round 1 findings

| # | Status | Evidence |
|---|---|---|
| U-1 | Fixed | `wipe()` deletes only `DATA_FILES` and their `.tmp` files (`service.rs:785-803`). The vault now lives in `vault/` (`lib.rs:278`). The test checks that `app_webview/` survives. |
| U-2 | Fixed on Android, with a regression (UR2-1) | `DeviceGuard` seals the secret with `veil.device.v1` and `remove()` calls `destroy()`. Windows and Linux are documented honestly. Caveat: a 0.1-preview plain secret that was upgraded in place can still sit on flash (UR2-7). |
| U-3 | Partially | Rust checks the purge tag before `_ if waiting`. But `Onboarding.tsx:209` (`if (!pass \|\| wait > 0) return;`) and `:241` (`disabled={... wait > 0}`) were not changed, so the Purge PIN still cannot be sent during a delay (UR2-3). |
| U-4 | Partially | A `Decoy` serves `unlock`, `unlock_info`, `bio_sealed` and `bio_disable`. But `state()` ignores it, and setup and reset never clear it (UR2-2). |
| U-5 | Partially | The lock-screen `SecretField` is non-strict (`strict` only for `new-password`). It still sets `inputMode="numeric"`, so Android shows a digits-only pad and the write order (header, then `unlock.cfg`) is unchanged (UR2-5). |
| U-6 | Fixed | `clear_purge` and `change_secret` write the flag, then the tag. `set_purge` writes the tag, then the flag. |
| U-7 | Fixed | `remaining()` clamps `last` to `now`. The test covers `remaining(5, 1e7, 100) == 30`. |
| U-8 | Fixed | `checked_sub(FREE_ATTEMPTS)`. Tests and docs now say "5 free". |
| U-9 | Fixed | `bio_prepare` calls `bio_files_off()` first, and `biometric_enable` runs `biometric_disable` + `delete_key` on any error. |
| U-10 | Partially | Lockout maps to `LOCKOUT`, and `onEnd` zeroes the secret on error or cancel. Remaining: the `fa == null` branch of `prompt()` never calls `onEnd`; the unwipeable JVM/serde base64 copies are not noted under INV-REST-4, and the new `deviceSeal`/`deviceOpen` add more of them. |
| U-11 | Fixed | `set_screenshots_allowed` requires `AppState::Unlocked`, and ADR-0012 records the owner request. |
| U-12 | Fixed | ADR-0012 paragraph, plus a Settings hint when biometrics are available. |
| U-13 | Partially | The header and device secret go first with 3 retries, but the retries are back-to-back (no use against an AV lock) and purge still ignores the result (`service.rs:912`). On Windows, `gone(keystore::FILE)` is always true and the `keystore::remove` error is dropped (`:789`), so a failed Credential Manager delete is never reported, for Reset either. |
| Nit (vault doc comment) | Fixed | Moved to `known_answer_unlock`. |

### New findings

**UR2-1 High [HIGH]: a plain device secret whose first byte is 0x02 is read as a sealed blob, and the vault becomes unopenable.**
`crates/client/src/keystore.rs:115`.
- `if let Some((&SEALED_V1, sealed)) = raw.split_first()` runs before the 32-byte plain check. Plain secrets are 32 random bytes, so 1 in 256 start with 0x02.
- What happens then: without a guard, `ok_or(Storage)` fails; with a guard, `open()` gets a 31-byte blob and fails.
- Scenarios:
  - Every Linux/macOS vault has a 1/256 chance of failing on its first unlock with `Storage`; only Start over gets the owner back in.
  - 1/256 of Android 0.1-preview installs are bricked at the upgrade. The plain file is never resealed, and the user cannot repair a file in the sandbox.
  - Integration tests (no guard) are flaky at about 0.4% per setup.
- Windows is not affected.
- Fix: decide by length first. `if raw.len() == 32 { plain path } else if let Some((&SEALED_V1, s)) = raw.split_first() { sealed path }`. An AES-GCM sealed file is 1+12+32+16 = 61 bytes, so it can never be 32. Add a test with `secret[0] = 2` for both `None` and a guard.

**UR2-2 Medium [HIGH]: the decoy is out of step with `state()` and outlives a new vault.**
`service.rs:585` (`state()`), `:711` (Reset), `:812` (setup).
1. `state()` returns `New` while the decoy says "locked". Any webview reload (Android activity recreation, or anything after `clear_all_browsing_data`) calls `app_state` and shows the welcome screen while the coercer is watching.
2. After a purge, "Start over…" leads to setup, and the decoy is still `Some`. As soon as the new vault locks, every `unlock` goes to the decoy branch. The owner's correct PIN is rejected, the old kind and fake delays are shown, and the only way out is another Start over, which wipes the new vault. That is a data-loss loop until the process restarts.
- Fix:
  - In `state()`: `else if self.decoy.is_some() { AppState::Locked }`.
  - In the `Cmd::Reset` handler and in `setup()`: `self.decoy = None;`.
  - Test: purge, reset, setup, lock, unlock with the new secret.

**UR2-3 Medium [HIGH]: the U-3 fix cannot be reached, and the docs overclaim.**
`Onboarding.tsx:209`, `:241`, plus ADR-0012 ("The Purge PIN is checked even during a retry delay") and INV-REST-6 ("works during a retry delay").
- Only the Rust test exercises this path; the UI never submits while `wait > 0`.
- Fix: allow submit during a wait (keep the banner), and treat `RetryLater` as "still waiting".
- Related: the decoy starts at `failures+1, last=now`. A real attempt during a delay returns `RetryLater` and leaves the countdown alone, but a purge makes it jump (for example from 12 s to 60 s). When `waiting`, copy the stored `(failures, last)` unchanged.

**UR2-4 Medium [HIGH]: a crash in the middle of the migration strands the vault.**
`lib.rs:278-288`.
- `DATA_FILES` puts `vault.hdr` first.
- Scenario: the process is killed, or a rename fails, after the header has moved. On the next start `vault/vault.hdr` exists, so the migration is skipped. `device.secret`, `veil.db` and `unlock.cfg` stay in the old folder, and every unlock fails with `Storage`. Start over then wipes only `vault/`.
- Fix:
  - Move every file that is in `base` and missing in `dir` on each start (idempotent), and move `vault.hdr` last.
  - Optionally fsync the directory.

**UR2-5 Low [MEDIUM]: U-5 is still open on Android.**
`ui.tsx`: `inputMode={pin ? "numeric" : "text"}` stays on the lock screen. On Android this shows Gboard's number pad, which has no letter keys.
- Scenario: a crash between the header write and the config write (`service.rs` `change_secret`) while switching from PIN to password leaves a password that cannot be typed.
- Fix: in `change_secret`, write the config with `kind = Password` before the header, then write the final kind after it. A text keyboard can type both kinds, so either crash point is safe.

**UR2-6 Low [MEDIUM]: a Keystore destroy failure is silent.**
`DeviceGuard::destroy` returns `()`.
- If `deleteEntry` fails while unlinking the file succeeds, the key stays on the phone, and flash remnants plus the phone are exactly the coercion case.
- Fix: return `bool` and fold it into `failed` in `wipe()`.
- Also add a short sleep between the U-13 retries.

**UR2-7 Low (docs): preview upgrades leave the old plain secret on flash.**
ADR-0012's crypto-erasure claim does not hold for 0.1-preview installs. The plain `device.secret` inode is replaced on the first unlock, but its blocks may persist. State this in ADR-0012 and INV-REST-6.

**UR2-8 Low: the actor can hang or die inside Tauri's blocking call.**
`native.rs` `KeystoreGuard`.
- No deadlock: plugins are initialised in `build()` (`app.rs:2607`) before the setup closure runs (`:2688`), so `native::guard` gets a handle. Keystore calls happen only from webview-triggered actor commands. No main-thread code waits on the actor, and the Kotlin `device*` handlers resolve synchronously on the UI thread.
- Residual risk: `run_mobile_plugin` does `rx.recv().unwrap()` (`mobile.rs:349`). If the `run_on_android_context` closure is dropped (activity destroyed), the actor thread panics and the client is dead until restart. If the handler is never called, the actor hangs.
- Fix: use `run_mobile_plugin_async` with a timeout from a dedicated small runtime, or document the risk.

**Nits**
- `PurgeForm` uses `native?.screenshotSetting` as an "is Android" proxy, and shows the desktop wording while `native` is still `null`. Use an explicit `platform` field.
- Kotlin: `deviceKey()` swallows every exception from the StrongBox attempt, which is acceptable, but log nothing.

### Verified good
- Guard trait: `MAX_SEALED` is checked before calling into the platform, the sealed file is useless without the key, an upgrade failure leaves the old file working, and Windows ignores the guard.
- Device key: no user authentication, StrongBox with TEE fallback, and `deviceOpen` maps a missing key to `KEY_GONE`, which Rust turns into `Storage` (no wipe).
- During a delay the response carries no passphrase signal. Both paths run one Argon2id, and the remaining HKDF/AEAD difference is microseconds.
- Purge decoy biometrics: 60 zero bytes, then `promptWithoutKey`, then `KEY_GONE`, so biometrics turn off just as after a changed fingerprint set. This is documented.
- `bio_files_off` before prepare and `biometric_enable` cleanup close U-9 completely.
- `SecretField`: new PINs drop non-digits; existing secrets accept any characters with `maxLength` 1024.

**Recommended action: B.** Fix UR2-1 (High) and UR2-2 to UR2-4 (Medium), then re-review. Lows can follow.

## Unlock options gate, round 3 (2026-10-25)

**Reviewer:** independent code-reviewer agent. Scope: `git diff HEAD~2..HEAD` at cb33be0.

VERDICT: PASS WITH CONDITIONS

**Scope:** `git diff HEAD~2..HEAD` (cb33be0), excluding docs/REVIEW_REPORT.md. I read the changed code in keystore.rs, service.rs (`state`, `handle`, `wipe`, `setup`, `unlock`, decoy, `change_secret`, bio functions), lib.rs (`data_dir`, `unlock`, `finish_purge`), native.rs, VeilNativePlugin.kt, Onboarding.tsx, Settings.tsx and the docs. `cargo test -p veil-client --locked --offline` passes: 9 / 3 / 1 / 5 / 0. I couldn't build the Android target (disk is 99% full), so the native.rs `call()` changes have not been compiled. I edited nothing.

There are no Critical or High findings. The condition is UR3-1 (Medium): fix it before release, or record it as a known limitation in ADR-0012.

### Status

| # | Status | Evidence |
|---|---|---|
| UR2-1 | Fixed | `keystore.rs:124` checks `raw.len() != 32` first, and `store` refuses a 31-byte seal, so a sealed file is never 32 bytes. Android AES-GCM output is 1+60 = 61 bytes. New test `plain_secret_starting_with_format_byte` covers both with and without a guard. No other length is ambiguous. The `== 31` check in `load` can never trigger but does no harm. |
| UR2-2 | Fixed | `state()` returns `Locked` while a decoy exists (`service.rs:588`). Reset clears the decoy (`:713`). Setup can't run while a decoy exists, because `state() != New` returns `AlreadySetUp`. Covered by `start_over_after_purge_gives_a_working_vault`. |
| UR2-3 | Partially | Submitting during a wait now works (`Onboarding.tsx:209,242`), and the decoy keeps `(failures, last)`. But the error text is a tell after the wait ends; see UR3-1. |
| UR2-4 | Fixed | `data_dir` is idempotent and moves the header last (`lib.rs:280-296`). An interrupted move is finished on the next start. |
| UR2-5 | Fixed (different approach) | `change_secret` writes `kind = Password` before the header when the kind changes (`service.rs:1060-1064`). New PINs are still checked: `SecretField` with `kind={kind}` and `new-password`, plus `unlock::validate`. Residual risk is in UR3-3. |
| UR2-6 | Fixed | `destroy() -> bool`, `remove` returns `Err` if it fails, `wipe` folds that into `keys_gone`, and there is a 200 ms sleep between retries. |
| UR2-7 | Fixed | ADR-0012 and INV-REST-6 now say that preview upgrades may leave the old plain secret in flash. |
| UR2-8 | Fixed | `call()` runs on a helper thread with a 10 s `recv_timeout`. A panic in the helper only drops `tx`, so the actor gets `None`. Residual risk is in UR3-4. |
| Nit: platform proxy | Fixed | `NativeInfo.android` is used, and the null case shows no platform wording (`Settings.tsx:105`). |
| Nit: Kotlin swallows StrongBox errors | Not fixed | `deviceKey()` is unchanged. This is acceptable. |
| U-3 | Partially | Same as UR2-3. |
| U-4 | Fixed | The decoy now covers `state`, `unlock`, `unlock_info`, `bio_sealed` and `bio_disable`. Lock and auto-lock don't touch it. `unlock_bio` can't be reached because the 60 zero bytes end in `KEY_GONE`. |
| U-5 | Fixed | See UR2-5. |
| U-10 | Fixed | The `fa == null` branch now calls `onEnd()`, and INV-REST-4 lists the base64 copies in the JVM and serde_json that can't be wiped. |
| U-13 | Fixed | The retries have a delay, and Windows and Keystore delete failures now produce `Err`. Purge still ignores the result (`let _ = self.wipe()`). That is the right choice, because a visible error would tell a coercer something. |

### Regression check (answers to task 2)

- **keystore length-first parsing:** no ambiguity found. A 1-byte file (`[2]`) fails with `Storage`, which is correct.
- **Decoy with setup, reset, lock, auto-lock and biometric:** consistent. `remaining()` gives the same value for the decoy and the real path, including the clock-backwards clamp.
- **wipe and setup ("can setup become impossible forever?"):** only if `deviceDestroy` keeps returning false. I checked AOSP `KeyStore.delete`: it treats `KEY_NOT_FOUND` as success, so a fresh install is fine. A broken Keystore daemon would already make `deviceSeal` fail, so setup was impossible on such a device before this change too.
- **data_dir:** partial runs are handled. Remaining edge case in UR3-5.
- **Kotlin deviceDestroy:** correct. A missing alias counts as gone. Minor point in UR3-2.

### New findings

**UR3-1 Medium [HIGH]: a purge during a wait shows a different error than a wrong attempt during a wait.**
`app/src-tauri/src/lib.rs:86-88` and `Onboarding.tsx:220,240`.
- Scenario: a wait is running and the victim enters the Purge PIN. Rust returns `WrongPassphrase`, so the UI stores "Wrong PIN or password". The banner is hidden while `wait > 0` (`error && wait <= 0`), but appears once the countdown reaches 0.
- Any other entry during the wait stores `RetryLater`, which shows "Too many attempts. Wait a moment and try again." after the countdown.
- So a coercer who knows Veil can tell that a purge happened. This contradicts ADR-0012 / INV-REST-6 ("lock screen unchanged").
- Fix: return the waiting state in the outcome, for example `UnlockOutcome::Purged { during_wait: bool }`, set from `waiting` in `service.rs` around line 921. Then in lib.rs: `Err(err(if during_wait { ClientError::RetryLater } else { ClientError::WrongPassphrase }))`.
- Add an integration assertion that the error matches what a non-purge attempt during the wait gets.

**UR3-2 Low [MEDIUM]: a failing Keystore makes purge slow, and that is visible.**
`service.rs:790-800` with `native.rs` `call()`.
- If `deviceDestroy` hangs, `wipe` takes 3 × 10 s plus 0.4 s, compared with about 1 s for a wrong attempt, and the actor is blocked for that time.
- Also, `keystore::remove` returns before deleting `device.secret` when `destroy()` fails. The file is only deleted later, in the `DATA_FILES` loop, so the "device secret first" order is broken in this case.
- Fix:
  - In `remove`, delete the file first, then call `destroy()`, and combine the two results.
  - In `wipe`, stop retrying `destroy` after a timeout. Only a `false` reply is worth retrying.

**UR3-3 Low [HIGH]: if the header write fails, the kind stays "Password".**
`service.rs:1060-1065`.
- This is an `Err`, not a crash: `write_atomic(HEADER)` fails after the interim `store_config(Password)` succeeded.
- The vault still opens with the old PIN, but Settings and the lock screen now say "Password". `set_purge` then requires a Purge PIN of 12 or more characters. This is safe but confusing, and it stays that way.
- Fix: if the header write fails, put the original config back, for example `if let Err(e) = write_atomic(..) { c.kind = old_kind; let _ = unlock::store_config(&self.dir, c); return Err(e); }`.

**UR3-4 Low [MEDIUM]: a lost plugin response leaks a thread, and the device secret is no longer in a `Zeroizing` buffer.**
`native.rs:98-112`, `:120`.
- After a timeout, the helper thread stays blocked in Tauri's `rx.recv()` for as long as the pending call is registered. That is one thread per lost call; the number is bounded by user actions.
- `json!({"secret": B64.encode(secret)})` replaced `SealArg { secret: Zeroizing<String> }`, so the device secret now passes through a plain `String`. INV-REST-4 now lists these copies as not wipeable, but this one could easily be avoided.
- Fix: keep `SealArg` and convert it with `serde_json::to_value(&arg)`. Even better, make `call` generic over `A: Serialize + Send + 'static` and pass the `Zeroizing` struct itself.

**UR3-5 Low [MEDIUM]: old copies left in the base folder are never moved or deleted.**
`lib.rs:292`.
- If a file exists both in the base folder and in `vault/`, the base copy is left in place forever. Start over and Purge only clear `vault/`.
- This can only happen after a partial migration by the unreleased round-2 build, followed by Start over and a new setup. Without a header those files can't be decrypted, but they are still debris.
- Fix: once `vault/vault.hdr` exists, delete any remaining base copies of `DATA_FILES` (best effort), or have `wipe` also clear `dir.parent()/DATA_FILES`.

### Good
- The length-first parsing is simple and comes with a test for the exact 1/256 case.
- Keeping the decoy's `(failures, last)` during a wait makes the countdown identical to a real attempt's.
- The new test (Start over after a purge) reproduces UR2-2's data-loss loop from start to finish.
- Moving the header last in `data_dir` makes the migration safe after a crash, and reruns are idempotent.

**Recommended action: B.** Fix UR3-1, then merge. The Low findings can go into a follow-up.
