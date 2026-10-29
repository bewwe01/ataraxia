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

## Milestone 1 review, round 1

**Scope:** commit 66005d3 (`git diff 900c68d 66005d3`), 16 files, +1561/−80. This round covers the client actor (`crates/client/src/service.rs`, `db.rs`), core `forget_contact`, the Tauri commands, `ipc.ts`, the Chats/Contacts/Settings screens, the docs, and the new tests. I checked each finding against the code, including the relay's `UpdateTokens`/`Deposit` paths, the core's `transact`/`Content::validate`, and the libsignal store keys.

**Commands run:** `cargo test -p veil-client --test contacts_and_privacy` passed 4/4. `cargo test -p veil-client --lib db::` passed 3/3. `cargo clippy -p veil-client --all-targets -- -D warnings` is clean.

**Verdict: FAIL.** There is one High finding (M1-1), and the gate rule is to fix every Critical/High and re-review. Several Medium findings break promises that ADR-0013 or the invariants state explicitly (M1-2, M1-3, M1-4, M1-5, M1-6, M1-7), and some invariants are marked "tested" when the tests do not prove them (M1-8).

---

### M1-1 — High — `app/src/screens/Chats.tsx:174-181`: the expiry timer overflows with the 4-week setting and spins the UI in a render loop

**Description.** The effect calls `window.setTimeout(..., Math.max(0, next - Date.now()) + 50)`. With the "4 weeks" timer (`2_419_200 s`, one of the options the UI offers), the delay is about 2.419e9 ms. That is larger than the 2^31−1 ms (about 24.8 days) a WebIDL `long` can hold. All three webviews (WebView2, WebKitGTK, Android WebView) wrap or clamp that value, so the callback fires at once. The callback always returns a **new** array (`prev.filter(...)`), even when nothing expired. That changes `messages`, the effect runs again, and it schedules another immediate timeout, with no end.

**Failure scenario.** Set a contact's timer to 4 weeks and send or receive one message, then keep the chat open. The webview re-renders continuously, about every 4 ms, for the first ~3 days of the message's life. This burns CPU and battery and makes the UI janky, especially on Android.

**Fix.** Clamp the delay, and return the same state object when nothing expired:
```ts
const delay = Math.min(Math.max(0, next - Date.now()) + 50, 2_147_483_647);
const t = window.setTimeout(() => {
  const now = Date.now();
  setMessages((prev) => {
    const kept = prev.filter((m) => m.expiresAtMs === null || m.expiresAtMs > now);
    return kept.length === prev.length ? prev : kept;
  });
}, delay);
```

### M1-2 — Medium — `crates/client/src/service.rs:1772-1803` (`retry_failed`), `1729` (`deliver`), `1784`: messages, timer updates and intros are still sent to a blocked contact

**Description.** ADR-0013 says of a blocked contact that "we do not send to them", and `send`/`set_timer`/`send_ephemeral` do refuse. But `retry_failed` picks up every `failed`/`sending` row that still has an envelope, and every contact with `intro IS NOT NULL`. It never looks at `contacts.blocked`, and neither does `deliver()`.

**Failure scenario.** While offline, Alice writes "where are you" to Bob (status `failed`, envelope kept). She then blocks Bob. When she reconnects, `connect()` → `retry_failed()` delivers the message to Bob. A pending `TimerUpdate` or a pending introduction goes out the same way.

**Fix.**
- Add `JOIN contacts c ON c.id = m.contact ... AND c.blocked = 0` to the `retry_failed` message query, and `AND blocked = 0` to the intro query.
- Also check `blocked` inside `deliver()`: return `false` without counting an attempt.
- Alternatively, clear `envelope` and set status `failed` on that contact's pending rows when blocking, inside the same `atomically` block.
- Add a test: queue a message while the relay is down, block, reconnect, and assert the peer never receives it.

### M1-3 — Medium — `crates/client/src/service.rs:2410-2420` (`unblock`): any rejection except `RateLimited` (including transient ones the relay can fake) still completes the unblock

**Description.** `Err(ClientError::Rejected(code)) if code != ErrorCode::RateLimited => {}` treats `QuotaExceeded` (their mailbox is full), `Internal`, `Conflict` and `Unspecified` as permanent. The code then sets `blocked = 0, my_token = <new token>`. The `MailboxUpdate` is never stored or retried, so the contact never learns the new token. The old token was already withdrawn at block time.

**Failure scenario.** Either the contact's mailbox is full, or the hostile relay answers `Internal`/`QuotaExceeded` to that one deposit. The UI then shows "unblocked", but the contact can never reach us again, and nothing tells either user. They have to work out that they need to re-invite.

**Fix.**
- Treat only `Unauthorized`/`NotFound` (token or mailbox gone) as final. For any other error, queue the token removal and return the error, so the contact stays blocked and the UI shows "Could not unblock".
- Better: store the sealed `MailboxUpdate` like the `TimerUpdate` notice, as an outgoing row with an envelope (for example `kind = 'mailbox'`, hidden from `messages()`), so `retry_failed` re-delivers it until it gets through.

### M1-4 — Medium — `crates/client/src/service.rs:2052-2063` (`set_privacy`), `2100-2133` (`send_receipts`): turning read receipts on sends "read" for messages read while receipts were off

**Description.** When receipts are enabled, `set_privacy` sets `receipt = 1` on old incoming rows. That suppresses delivery receipts only. `send_receipts(Read)` selects `receipt < 2`, so the next `mark_read` sends read receipts for up to 256 old messages per call (4 envelopes). This includes messages the user read while receipts were off and messages that arrived before they were turned on. The integration test shows it: message "one" arrives with receipts off, and once both turn receipts on, Bob's "one" becomes `read`. The test just doesn't assert on "one".

**Failure scenario.** A user keeps receipts off so that a contact doesn't learn which messages they read. They turn receipts on a month later and open the chat. The contact's whole backlog flips to "Read" at once. This is information the user chose to withhold, and it defeats the purpose of the setting (INV-CONT-2's spirit, and the ADR's "does not send … for older messages").

**Fix.**
- When enabling, run `UPDATE messages SET receipt = 2 WHERE mine = 0 AND receipt < 2`. Alternatively, while receipts are off, have `mark_read` set `receipt = 2` for that contact's rows.
- Assert on message "one" in `receipts_and_typing_are_opt_in`: it must stay `sent`.

### M1-5 — Medium — `app/src/screens/Chats.tsx:150-163` with `app/src/App.tsx:83-87`: read receipts go out for messages the user has not seen

**Description.** `markRead(contact.id)` runs whenever `version` changes. `version` goes up on **any** `messages` event, for any contact. That includes incoming messages, the expiry sweeper's events and receipt-status changes. `mark_read` now sends read receipts (`service.rs:1385-1390`). The app never checks whether the window is visible or focused.

**Failure scenario.** The desktop window is minimized, or the app is backgrounded on Android before auto-lock, with Bob's chat open. Bob's new message arrives and is immediately reported as "Read", although the user never saw it. This is a false "read" signal leaking presence.

**Fix.**
- In `Chat`, call `markRead` only when `document.visibilityState === "visible" && document.hasFocus()`.
- Add a `visibilitychange`/`focus` listener that calls it when the user comes back.
- Optionally pass `read: boolean` to `mark_read` so the unread count can still be cleared without sending a receipt.

### M1-6 — Medium — `crates/client/src/service.rs:2100-2147` (`send_receipts`, `send_delivery_receipts`): when the peer's relay rejects us, every sync seals and sends a new receipt envelope, with no end

**Description.** Receipts are marked as sent only when the deposit succeeds. When a contact has blocked or deleted us, their relay answers `Rejected` every time. The rows stay at `receipt = 0`, so after **every** sync (each push, each reconnect) `send_delivery_receipts` seals a new envelope and deposits it again. `mark_read` does the same for read receipts. `send_ephemeral` re-seals on each attempt (unlike `deliver`, which reuses one stored envelope and stops at `MAX_ATTEMPTS`). So every attempt also moves the Signal sending chain forward. This contradicts ADR-0013's "best effort, never stored or retried".

**Failure scenario.** Bob blocks Alice while Alice has unreceipted messages from Bob (receipts on). From then on, every message anyone sends Alice triggers a sync, and with it another rejected deposit to Bob's mailbox. The relay sees a steady stream of failed deposits tied to Alice's syncs (metadata). Alice's chain toward Bob drifts forward without limit. Past libsignal's forward-jump limit, Bob could no longer decrypt Alice's messages after an unblock.

**Fix.** Treat a final rejection like a send: on `Err(ClientError::Rejected(c)) if c != ErrorCode::RateLimited`, mark the chunk's `receipt = level` anyway. Only `Unreachable`/`Locked`/`RateLimited` should leave rows for a later attempt. Optionally also cap attempts per row.

### M1-7 — Medium — `crates/client/src/service.rs:1988-1999` (`receive` `TimerUpdate`), `2178-2221` (`set_timer`): timer updates are applied in arrival order, so the two sides can end up with different timers

**Description.** An incoming `TimerUpdate` overwrites `timer_secs` with no ordering check. Our own pending timer updates are retried in id order, and only on reconnect. There are two ways this goes wrong:
- **Superseded update retried later.** A failed update is retried after a newer one already went through, so the peer ends up with the older value.
- **Simultaneous changes.** Both users change the timer at the same time, and each side applies the other's value, so they swap.

`Text.expire_timer_secs` from the peer does not repair the local setting either.

**Failure scenario.** Alice sets 1 hour. The deposit fails (say, `RateLimited`) and the row stays `failed`. She immediately sets 5 minutes, which is delivered. Later a reconnect retries the 1-hour update. Bob now shows 1 hour and his messages carry 1 hour, while Alice's UI says 5 minutes. Bob's messages outlive the timer Alice chose on both phones.

**Fix.**
- In `set_timer`, clear the envelope of older pending `kind = 'timer'` rows for that contact, inside the same `atomically` block, so they are never retried.
- On receive, apply a `TimerUpdate` only if its `sent_at_ms` is newer than the last one applied (store `timer_set_ms` on the contact). Equivalently, apply only when it is newer than our own last local change.

### M1-8 — Medium — `crates/client/tests/contacts_and_privacy.rs`, `docs/INVARIANTS.md` (INV-REST-9, INV-CONT-1), ADR-0013 invite cleanup: the tests do not prove what the docs say they prove (CLAUDE.md rule 9)

**Description.**
- **INV-REST-9 ("deleted from the local database").** `disappearing_messages` checks expiry through `messages()`, and that query already hides expired rows (`expires_at_ms > now`). The test therefore passes even if `expire_messages()` never deletes anything. Nothing checks that the row is physically gone, nor the "unsent message that expires is deleted unsent" path.
- **INV-CONT-1 ("their token removal survives going offline").** This is marked **tested**, but no test blocks or deletes while offline and then checks that the removal is flushed on reconnect.
- **Expired-invite cleanup (feature 6).** There is no test that an expired invite's token is withdrawn at the relay, or that the core prekeys are swept.
- **Key warning dismissal.** `lookalike_name_gets_a_key_warning` says "so does dismissing" but never calls `dismiss_key_warning`.

**Failure scenario.** A regression that breaks the sweeper, the offline removal queue or invite cleanup would leave every test green while the invariants table still claims "tested".

**Fix.** Add these tests:
- **Expiry.** Make the expiry check raw. Add a `#[cfg(test)]`/`pub(crate)` row count, or open the DB in a unit test and assert `SELECT count(*) FROM messages WHERE ...` is 0 after a tick. Also cover a `failed` message with an envelope that expires.
- **Offline removal.** Stop the relay, block, restart the relay on the same store, then assert a deposit with the old token is rejected.
- **Invite cleanup.** Create an invite with a short TTL (inject the TTL or the clock), let it expire, then assert `Deposit` with its token is rejected and the core prekeys are gone.
- **Dismiss.** Assert that `dismiss_key_warning` clears the flag.

Mark INV-CONT-1 **partial** until the offline test exists.

### M1-9 — Low — `crates/client/src/service.rs:2380-2427` (`unblock`) and `1653-1672` (`upsert_contact`): a blocked contact can get a live token back, and the unblock path loses track of the previous token

**Description.** If a blocked contact is re-paired (they redeem a fresh invite of ours, or we accept theirs), the `ON CONFLICT ... DO UPDATE SET my_token = excluded.my_token` stores a newly registered token. The row stays `blocked = 1`. The relay then accepts their deposits again, and the client silently drops them, so they can fill our mailbox quota. `unblock` overwrites `my_token` without queueing the old value for removal. Nothing goes wrong in the normal block→unblock flow (the old token was withdrawn at block time), but it does after such a re-pair.

**Fix.**
- In `upsert_contact`, when the existing row is blocked, queue the new `my_token` for removal (or refuse the re-pair while blocked).
- In `unblock`, call `queue_token_removal(old_my_token)` before overwriting it (removal is idempotent at the relay).

### M1-10 — Low — `crates/client/src/service.rs:1529-1595` (`accept_invite`) vs `1939-1956`, `docs/INVARIANTS.md` INV-ID-2: the key-change warning only works for the side that created the invite

**Description.** `key_warning` is computed only in `Opened::NewContact`, from the intro's display name. On the accepting side, the new contact is always named `Contact XXXX` (from the fingerprint), so it never clashes. In the common impostor case, the attacker sends *us* an invite link claiming to be Bob. We accept, get no warning, and typically rename the contact "Bob". Names are compared after case-folding and whitespace collapsing only, so lookalike letters from other scripts (for example a Cyrillic "о") also get past it. INV-ID-2 currently reads as if any new contact with an existing name is flagged.

**Fix.**
- Document the limitation in INV-ID-2 and ADR-0013.
- Optionally run the same clash check in `rename()` when the user gives a recently paired, unverified contact an existing contact's name, and set `key_warning`.

### M1-11 — Low — `crates/client/src/service.rs:1985` and `2225-2247` (`expire_messages`): the unread count survives expired messages

**Description.** `unread` is incremented on receipt and only reset by `mark_read`. When unread messages expire, the badge stays. The list then shows "No messages yet" next to an unread count of, say, 3, which also hints that disappearing messages came and went.

**Fix.** In `expire_messages`, decrement `unread` by the number of expired unread incoming rows. Alternatively, derive `unread` from the rows instead of storing a counter.

### M1-12 — Low — `crates/client/src/service.rs:1486-1527` (`create_invite`) vs ADR-0013 "closes the gap noted in ADR-0011": a token whose `PutInvite` failed is never withdrawn

**Description.** `take_token()` hands out an already registered token. If core `create_invite` or `PutInvite` then fails, no `invites` row is written, so `cleanup_invites` never queues that token. It stays registered at the relay until the mailbox is gone.

**Fix.** On any error after `take_token()`, call `queue_token_removal(&token)`. Alternatively, insert the `invites` row first and delete it on failure.

### M1-13 — Low — `app/src/screens/Contacts.tsx:186-205`: the delete confirmation `alertdialog` drops keyboard and screen-reader focus

**Description.** Clicking "Delete contact" replaces that button with the `role="alertdialog"` banner. The focused element disappears and focus falls back to `<body>`. An `alertdialog` should move focus into itself. Keyboard and screen-reader users land at the top of the page.

**Fix.** Add `autoFocus` to the "Cancel" button. When the dialog closes, return focus to the "Delete contact" button through a ref.

### M1-14 — Info — `crates/client/src/service.rs:2028-2034` (`MailboxUpdate`): a contact can point our deposits at any mailbox

**Description.** Any contact, at any time, can send a `MailboxUpdate` that sends our future envelopes (sealed to them) to a mailbox of their choice, using a token they hold for it (for example a third party's). Confidentiality is unaffected. The only effect is that the relay sees us depositing to that mailbox. The contact could already deposit there directly, so this is not a meaningful amplification.

**Fix.** None required. Optionally accept a `MailboxUpdate` only after we sent one or after we were blocked. At minimum, document the behaviour in THREAT_MODEL §4.

### M1-15 — Info — ADR-0013 / UI hint text: disappearing messages with a peer still on preview-2

**Description.** A preview-2 peer ignores `TimerUpdate` and sends `Text` without `expire_timer_secs`. Its messages are kept forever on both sides, and our messages stay on its device. Meanwhile our UI shows the timer chip and the hint "They are deleted from both phones".

**Fix.** Document this, and optionally apply the stricter local `timer_secs` to incoming `Text` that carries no timer.

---

### Good
- **Deletion is atomic.** `delete_contact` runs `forget_contact`, the token-removal queue and the row delete in one `atomically` savepoint. The core `transact` nests correctly (no in-memory cache to diverge). `forgotten_contact_is_a_stranger_until_a_new_invite` really proves the core side.
- **No relay I/O inside savepoints.** Every `atomically` block is local-only.
- **Hostile-contact input is validated in the core.** Receipt ids must be 16 bytes and at most 256, timers at most 4 weeks, `MailboxUpdate` fields exactly 32 bytes. Receipts are scoped to `contact = ?1 AND mine = 1`, so a contact cannot mark other contacts' messages, nor timer notices (`msg_id` is NULL).
- **Token removal is persisted and idempotent** at the relay (`update_tokens` ignores unknown hashes).
- **The migration is sound for preview-2 databases.** It runs in one transaction with the `user_version` bump, the test covers an existing database and re-opening, and `secure_delete` is set on every open.
- **Auto-lock accounting is correct.** Only user-initiated commands count (`MarkRead` and `Privacy` correctly do not), and the typing throttle and 15 s staleness work as described.
- **UI rules are followed.** Read and delivered statuses use different icon shapes with sr-only labels. The typing dots respect `data-motion`/`prefers-reduced-motion`. The UI uses only tokens, and IPC goes only through `ipc.ts`.

### Required before re-review
Fix M1-1. Fix M1-2 to M1-7, or record an accepted rationale for each in ADR-0013. Fix M1-8, or downgrade the invariant statuses to **partial**. The Low findings can follow in a later change.

### Action options
Recommended: **B. Fix blocking only** (M1-1 to M1-8), then re-run the gate. Alternatives: A (everything, Low included), C (pick by id), D (report only).

## Milestone 1 review, round 2

**Scope:** commit 18fb4a6 (`git diff 66005d3 18fb4a6`, 8 files, +576/−94). Where the fixes touch other milestone code, I re-checked it against `git diff 900c68d 18fb4a6`. Every claim below was checked in the code, not the commit message.

**Commands run:**
- `cargo test -p veil-client --test contacts_and_privacy`: 7/7 passed in 12.5 s.
- The same test binary, three copies at once plus two busy-loop CPU hogs on a 4-core machine: 3 × 7/7 passed, about 15.6 s each.
- `cargo test -p veil-client --lib`: 10/10 passed.
- `cargo clippy -p veil-client --all-targets -- -D warnings`: clean.
- Release history (`gh run list --workflow release.yml`, `gh api …/releases`): see "Edited migration 1" below.

**Verdict: PASS WITH CONDITIONS.** M1-1 (High) is fixed. M1-2 to M1-6, M1-8, M1-9, M1-12 and M1-13 are fixed. M1-10, M1-14 and M1-15 are documented. M1-7 and M1-11 are only partly fixed (M1R2-2, M1R2-3). There are no new Critical or High findings. The condition is one new Medium: M1R2-1, where an older stored `mailbox` update can be retried after a newer one and cut the contact off. Fix it, with a test, before the milestone is released.

### Round-1 findings

| ID | Sev. | Status | Checked against the code |
|---|---|---|---|
| M1-1 | High | **Fixed** | `Chats.tsx` clamps the delay to 2 147 483 647 ms and returns `prev` when nothing expired, so the effect does not re-run and the loop is gone. |
| M1-2 | Med | **Fixed** | `deliver()` joins on `c.blocked = 0` (service.rs:1788). `retry_failed` filters both messages and intros on `blocked = 0`. `send_ephemeral` already did. `block_while_offline` covers this. |
| M1-3 | Med | **Fixed**, new issue M1R2-1 | `unblock` stores the sealed `MailboxUpdate` as a hidden `kind='mailbox'` row and returns Ok. `messages()` shows only `text`/`timer`, `contact_view` shows only `text`, and receipts only match `kind='text'` or non-NULL `msg_id`. Retry has two gaps: older rows are not superseded (M1R2-1), and retries happen only on reconnect (M1R2-4). |
| M1-4 | Med | **Fixed** | Turning receipts on sets `receipt = 2` for every incoming row. The test now asserts that "one" stays `sent`; the pre-fix code would have failed it. |
| M1-5 | Med | **Fixed** (UI, untested) | `markRead` only runs when the window is visible and `hasFocus()`, and again on `visibilitychange`/`focus`. The listeners are removed on cleanup. Still to confirm on an Android device: `visibilityState` must turn `hidden` when the app goes to the background. |
| M1-6 | Med | **Fixed** | A final `Rejected` (anything except `RateLimited`) marks the chunk as sent, so it is not sealed and sent again on every sync. `QuotaExceeded` (their mailbox is full) also counts as final, so those receipts are lost. That fits ADR-0013's "best effort". |
| M1-7 | Med | **Partly fixed** | Fixed: a superseded retry. `set_timer` clears the envelopes of older `timer` rows, and receive only applies a change newer than `timer_peer_ms`. Not fixed: simultaneous changes still swap (M1R2-2). |
| M1-8 | Med | **Fixed** | `messages()` no longer filters expired rows, so the expiry tests now see the sweeper. New tests: `expired_unsent_message_is_never_sent`, `block_while_offline` and `expired_invites_release_their_tokens`, plus a dismissal check. The core prekey sweep is covered by `account.rs:1389` and `session.rs:384`. |
| M1-9 | Low | **Fixed** | `upsert_contact` queues the new token for removal when the contact is still blocked. `unblock` queues the old `my_token`. |
| M1-10 | Low | **Documented** | INV-ID-2 and ADR-0013 now state the limits: the warning is name-based, only on the inviting side, and lookalike letters get past it. |
| M1-11 | Low | **Partly fixed** | `unread = min(unread, remaining incoming texts)` only works once *all* incoming texts are gone (M1R2-3). |
| M1-12 | Low | **Fixed** | `create_invite` queues the token for removal on any error after `take_token`. |
| M1-13 | Low | **Fixed** | "Cancel" has `autoFocus`, and focus goes back to "Delete contact" through a ref. |
| M1-14 | Info | **Documented** | Recorded as accepted in ADR-0013. |
| M1-15 | Info | **Fixed and documented** | An incoming `Text` with no timer gets our local timer. |

### Questions asked for this round

**Edited migration 1.** It is unreleased.
- The newest successful release run built 75a3baf (2026-10-26), whose `db.rs` has no `MIGRATIONS`. Releases v0.1.0-preview.1 to 3 are older still.
- The one other recent run, d697de0 on branch `outsiders`, failed. That commit is not in this clone, so I could not inspect it.
- So no released build has `user_version = 1`.
- A developer database created by a local build of 66005d3 would be at version 1 without `timer_peer_ms`. Every incoming `TimerUpdate` would then fail with a storage error. Delete such databases; no code change is needed.

**`Client::start_with_invite_ttl`.**
- It is `#[doc(hidden)] pub`, like the existing `start_with_auto_lock`. Only the integration test calls it.
- Rust code in the same process is trusted and the webview cannot reach it, so there is no realistic risk. Note that it passes `guard = None`, so it must never be used by the app.

**Receipts treated as sent on a final rejection.** Correct. The hostile relay could drop them anyway, so it gains nothing.

**The new tests.**
- They prove what INVARIANTS.md now says. INV-CONT-1 is "removal flushed on reconnect after an offline block", not "across a restart", but the queue lives in the database, so the written argument covers restarts.
- The proxy correctly cuts live connections (watch channel) and refuses new ones.
- Timing margins:
  - `online(…, 40 s)` covers reconnect backoff for offline periods up to about 30 s. These tests stay offline for at most about 10 s.
  - `expired_invites_release_their_tokens` allows 24 s for a 4 s TTL, a 5 s tick and 1/s token updates.
  - All passed under load.
- One weakness: `block_while_offline` proves a negative ("queued before the block" never arrives) with a fixed 500 ms sleep. A mutation would be caught on an idle machine but could slip through on a slow one. Acceptable for now.

---

### M1R2-1 — Medium [HIGH] — `crates/client/src/service.rs:2458-2505` (`unblock`), `2095` (receive `MailboxUpdate`): an older pending `mailbox` row is retried after a newer one and points the contact at a withdrawn token

**Description.**
- Nothing supersedes earlier `kind='mailbox'` rows: not `unblock`, not `set_blocked(true)`. `retry_failed` re-sends every pending row once the contact is unblocked.
- The receiving side applies each `MailboxUpdate` in arrival order, with no ordering check.
- Each new unblock withdraws the token carried by the previous one (`queue_token_removal(old)`).

**Failure scenario.**
1. Alice unblocks Bob while her connection is down. The token comes from the local spare pool. Row A (token T1) stays pending.
2. She blocks Bob again, which withdraws T1. She then unblocks him while online: row B (T2) is delivered at once.
3. On her next reconnect, `retry_failed` delivers row A.
4. Bob switches to the withdrawn T1. All his deposits to Alice now fail with `Unauthorized`. Alice's UI says "unblocked", and nothing repairs this short of another block and unblock or a new invite.

**Fix.**
1. In both the block and unblock `atomically` blocks, drop older pending updates:
   ```rust
   s.db.conn().execute(
       "UPDATE messages SET envelope = NULL WHERE contact = ?1 AND mine = 1 AND kind = 'mailbox' AND envelope IS NOT NULL",
       [contact],
   )?;
   ```
   In `unblock`, run this before the `INSERT`.
2. Optionally, order on receive as well: store `mailbox_peer_ms` and apply only when `sent_at_ms` is newer, as is done for `timer_peer_ms`.
3. Add a test: proxy cut, unblock, block, restore, unblock, reconnect again; then Bob → Alice must still deliver.

### M1R2-2 — Low [HIGH] — `crates/client/src/service.rs:2052` (receive `TimerUpdate`) and `set_timer`: simultaneous timer changes still swap (rest of M1-7)

**Description.** `timer_peer_ms` only orders the *peer's* changes against each other. A local change does not update it, and an incoming change is not compared with it.

**Failure scenario.** Alice sets 5 min and Bob sets 1 week within the same few seconds. Each applies the other's update, so Alice ends up on 1 week and Bob on 5 min. Each side's messages then carry a different timer.

**Fix.**
- In `set_timer`, also record the local change time: `UPDATE contacts SET timer_secs = ?2, timer_peer_ms = max(timer_peer_ms, ?3)` with `?3 = now_ms()`.
- On receive, keep the `timer_peer_ms < sent` guard. The later change by wall clock then wins on both sides.
- Mention the clock dependency in ADR-0013.

### M1R2-3 — Low [HIGH] — `crates/client/src/service.rs:2314-2319` (`expire_messages`): the unread badge still outlives expired messages when older messages remain (rest of M1-11)

**Description.** `min(unread, count of remaining incoming texts)` only shrinks the badge when fewer incoming texts are left than the count.

**Failure scenario.**
1. Alice and Bob have 20 old messages with no timer.
2. Bob turns on a 5-minute timer and sends 3 messages while Alice is away. They expire.
3. Alice's badge still shows 3 over an empty stretch of the chat. M1-11 is exactly this case.

**Fix.** Before the `DELETE`, for each affected contact, compute how many of the newest `unread` incoming text rows are expired, and subtract that. Unread rows are always the newest incoming ones. For example, in Rust, per contact:
```rust
let n: i64 = conn.query_row(
    "SELECT count(*) FROM (SELECT expires_at_ms FROM messages WHERE contact = ?1 AND mine = 0 AND kind = 'text'
     ORDER BY id DESC LIMIT (SELECT unread FROM contacts WHERE id = ?1)) WHERE expires_at_ms <= ?2",
    params![c, now], |r| r.get(0))?;
conn.execute("UPDATE contacts SET unread = max(0, unread - ?2) WHERE id = ?1", params![c, n])?;
```

### M1R2-4 — Low [HIGH] — `crates/client/src/service.rs:810` (only `connect()` calls `retry_failed`): a failed `MailboxUpdate` waits for the next reconnect, and is silently abandoned after `MAX_ATTEMPTS`

**Description.**
- `unblock` returns Ok even when the immediate `deliver` failed.
- The row is hidden, and it is retried only when the connection is re-established. On a stable desktop connection that can be days.
- After 20 failed attempts it is never retried, and nothing tells the user.

**Failure scenario.** Alice unblocks Bob while online, and the relay answers `RateLimited` (or Bob's mailbox is `QuotaExceeded`). Alice stays connected all day. Bob keeps using the withdrawn token and every message he sends fails, while Alice's UI says "unblocked".

**Fix.**
- Retry pending rows on `on_tick` while online, throttled (for example when the oldest pending row's last attempt is more than 60 s old). Alternatively, retry only `kind IN ('mailbox','timer')` on tick.
- Expose a pending-unblock state in `ContactView`, for example `unblock_pending: bool` from `EXISTS(… kind='mailbox' AND envelope IS NOT NULL)`, so the UI can say "Unblocking…" or "Could not reach them".

### M1R2-5 — Nit — `docs/ARCHITECTURE.md` ADR-0013 (disappearing messages), `crates/client/src/service.rs:1401`

**Description.**
- The ADR still says "queries also hide expired rows in between". `messages()` (service.rs:1413) no longer does: the webview hides them, and Rust deletes them within 5 s.
- `contacts()` orders conversations by `max(m.at_ms)` over *all* rows. A hidden `mailbox` row therefore moves an unblocked contact to the top of the chat list, with an older last-message preview.

**Fix.**
- Change the ADR sentence to: "the message list hides them on time in the UI".
- In `contacts()`, join `ON m.contact = c.id AND m.kind IN ('text','timer')`.

---

### Good
- **Blocking is now airtight on the send side.** All four send paths check `blocked`: `deliver`, `retry_failed` messages, `retry_failed` intros and `send_ephemeral`. A mutation-checked test covers the offline case.
- **Storing the unblock update reuses existing machinery.** The `mailbox` row follows the envelope and attempts logic already used for messages. It never reaches `messages()`, previews or receipts, and it carries no expiry, so the sweeper cannot drop it.
- **`create_invite` is split cleanly** into `take_token` and `publish_invite`, with removal on any error, which closes the M1-12 gap without duplicating code.
- **The expiry tests now observe the sweeper itself**, because the list no longer filters expired rows. The test harness (cuttable proxy, tunable relay quotas, invite-TTL hook) is reusable and held up under CPU contention.
- **The UI fixes are minimal and correct.** The timer is clamped and the effect no longer loops, read state follows visibility and focus with clean listener teardown, and focus is handled correctly in the delete dialog.

### Required before release
- Fix M1R2-1 and add its test.
- M1R2-2 to M1R2-5 can follow in a later change, or be recorded as accepted in ADR-0013.
- Confirm M1-5 on an Android device: `visibilityState` must turn `hidden` in the background.

### Action options
Recommended: **B. Fix blocking only** (M1R2-1). Alternatives:
- **A.** Fix everything, M1R2-1 to M1R2-5.
- **C.** Pick findings by id.
- **D.** Keep the report only, no fixes.

## Milestone 2 review, round 1

**Scope:** `git diff 91135dd 6d0f275` (commit 6d0f275), 20 files excluding `veil-TODO.md`, about 1,600 changed lines.
**Verdict:** PASS WITH CONDITIONS. There are no Critical or High findings. M2-1 to M2-4 (Medium) must be fixed before the next round; the Low findings may be fixed now or tracked.

**Commands run:**
- `cargo test -p veil-client --test messaging --test contacts_and_privacy`: 8 + 3 passed.
- `pnpm -C app typecheck`: clean.
- `pnpm -C app lint`: "12 files clean".

**Attack paths checked and found closed:**
- **Received edits and deletes:** they cannot touch our messages or another conversation. `receive` matches `contact = ?1 AND mine = 0 AND kind = 'text'` with a 48 h `at_ms` window.
- **Received reactions:** they are scoped to the conversation, and `PRIMARY KEY (message, mine)` caps them at one per side.
- **Size and character limits:** the core enforces 16-byte `reply_to`/target ids, the emoji limit of 8 characters / 32 bytes with no control or bidi characters, and `MAX_BODY_LEN`. `account.rs:392/414` validates every opened content.
- **Blocked contacts:** content from them is dropped before `receive`. `queue_control` refuses to queue for them, and `deliver`/`retry_failed` filter on `c.blocked = 0`.
- **Transactions:** there is no relay I/O inside `atomically`. Sealing happens inside the savepoint, so the ratchet state and the control row commit together, and `deliver` runs after.
- **Cascades:** `PRAGMA foreign_keys = ON` (`db.rs:120`) makes reactions cascade on delete-for-me, expiry and contact deletion.
- **Search:** `LIKE … ESCAPE '\'` escapes `%`, `_` and `\` correctly.
- **Migration 2:** it is plain `ADD COLUMN … DEFAULT` plus a new table, applied in a transaction with the version bump, and it skips correctly on a `user_version = 1` database.
- **Panics:** there are no panic paths on untrusted input. `parse_hex` caps input at 2,048 characters and returns `None` on a split UTF-8 sequence; `snippet` and `excerpt` do no indexing.
- **Camera on Android:** permission is requested through wry's `onPermissionRequest` (`RESOURCE_VIDEO_CAPTURE` maps to `CAMERA`). Microphone is not declared, so it stays denied.
- **jsQR 1.4.0:** Apache-2.0 (compatible with AGPL-3.0), no runtime dependencies, no install scripts, and the bundle has no `fetch`, `XMLHttpRequest`, `WebSocket`, `eval` or `new Function`. The lockfile pins its integrity hash.

### Findings

**M2-1 Medium: editing (or reacting to) one of our own messages that has not gone out yet leaves the two sides out of sync**
`crates/client/src/service.rs:2171-2197` (`edit_message`), same pattern in `react` at 2123.

`edit_message` rewrites only the local `body`. The stored `envelope` still holds the original text. It then queues an `Edit` control row and delivers it straight away.

Failure scenario:
1. A message ends up `failed` with its envelope still stored. This happens after a transient relay error, or permanently after `MAX_ATTEMPTS = 20`, when `retry_failed` stops picking it up.
2. The UI still offers Edit, because `withinEditWindow` only checks `mine && actionable && < 24 h`.
3. The `Edit` is deposited first. The receiver has no target yet, so it drops the edit silently.
4. If the original is retried later, the receiver gets the old text. If it never is, the receiver gets nothing.
5. Either way the sender sees "edited" with the new text, and the two sides disagree about what was said. A reaction on our own unsent message is lost the same way.

Fix (`delete_for_everyone` already has the right shape):
- In `edit_message`, if `envelope IS NOT NULL` on the target, re-seal the original `Text` with the new body, keeping the same `content.id`, `reply_to` and `expire_timer_secs`. Replace the row's `envelope` inside the same `atomically` block and do not queue an `Edit`.
- Alternatively, refuse with a clear error ("not sent yet") until the original is out.
- For `react`, refuse (or defer) when the target is ours and still has an envelope.
- Add a test: send while the relay is down, edit, reconnect, and assert the receiver sees only the new text.

**M2-2 Medium: a hostile contact can reuse message ids, which multiplies rows in the chat list**
`crates/client/src/service.rs:1633` (`messages`) and `2059` (`message`); `receive` `Body::Text` at 2545.

Incoming `Text` rows are inserted with the sender-chosen `content.id`, and nothing checks for uniqueness: `messages_by_msg_id` is not `UNIQUE`. The quote is resolved with `LEFT JOIN messages q ON q.contact = m.contact AND q.msg_id = m.reply_to`.

Failure scenario:
1. A malicious contact sends K texts all with id Y, then J texts with `reply_to = Y` (or reuses one of our own ids).
2. Every reply row is returned K times, so the result has K×J rows. `ORDER BY m.id DESC LIMIT 500` counts joined rows, so 23 + 23 crafted messages fill the 500-row window. The real history disappears from the chat view.
3. The list contains duplicate `m.id` values, so React keys collide and bubbles are mis-reconciled.
4. `message()` (`query_row`) and the received-reaction lookup pick an arbitrary one of the matching rows.

The damage stays inside that conversation, but it is attacker-controlled amplification. Legitimate retries cannot cause it, because libsignal rejects a duplicated envelope.

Fix:
- In `receive` `Body::Text`, drop the text (return `Ok(())`) when a row with `(contact, msg_id)` already exists.
- Resolve the quote with one row: `LEFT JOIN messages q ON q.id = (SELECT id FROM messages WHERE contact = m.contact AND msg_id = m.reply_to AND kind = 'text' ORDER BY id LIMIT 1)`.
- Optionally, in a migration 3, add a partial `UNIQUE INDEX … ON messages(contact, mine, msg_id) WHERE msg_id IS NOT NULL` once duplicates are cleaned up.
- Add a test that injects crafted content (see M2-9).

**M2-3 Medium: hidden control rows ignore disappearing timers and are never cleaned up**
`crates/client/src/service.rs:2083-2106` (`queue_control`).

Control rows are inserted without `expires_at_ms` and are never deleted after delivery.

Failure scenario:
1. In a chat with a 5-minute timer, the user edits a message while offline.
2. The `Edit` envelope carries the full new text. The original message expires and is swept, but the control row survives the sweeper.
3. The `Edit` is deposited at the relay after the timer ran out. The peer drops it, but the relay still receives it.

This is the same class as the M1 guarantee `expired_unsent_message_is_never_sent` (INV-REST-9), now broken for edits.

Separately, every reaction, edit and delete leaves a permanent `kind = 'control'` row with `at_ms`. That is unbounded growth and indefinite activity metadata, even in disappearing conversations.

Fix:
- Pass the target's `expires_at_ms` into `queue_control` and store it on the control row. The existing sweeper (`DELETE FROM messages WHERE expires_at_ms <= ?`) then removes it, with or without an envelope.
- Delete control rows once delivered: in `deliver`, `DELETE FROM messages WHERE id = ?1 AND kind = 'control'` instead of marking them `sent`.
- Extend `expired_unsent_message_is_never_sent` with an edit queued offline.

**M2-4 Medium: the message action dialog has no focus trap and does not return focus**
`app/src/screens/Chats.tsx:189-227` (`MessageActions`), close paths at 486-507.

DESIGN.md §6 requires a focus trap for `.dialog`. The dialog sets `aria-modal="true"`, but:
- Tab moves out into the chat behind it, which is not `inert`.
- Escape only works while focus is inside the scrim.
- On close, react, delete, Cancel or Escape, focus falls to `<body>`, because the bubble that opened the dialog is never refocused. The repo already does this for the contact delete confirm (`Contacts.tsx:105-111`).

Failure scenario: a keyboard or screen-reader user reacts to a message and loses their position at the top of the document after every action. They can also tab into the composer while the "modal" is open.

Fix:
- Store the opener (`document.activeElement`) in `openActions`, and call `.focus()` on it in `onClose`/`onDone`. After a delete the bubble is gone, so focus the composer instead.
- Mark the chat behind the dialog `inert` (or wrap Tab between the first and last focusable elements of the dialog).
- Move the Escape handler to a `keydown` listener on `document` while the dialog is mounted.

**M2-5 Low: the Android permission check in release.yml does not check "exactly"**
`.github/workflows/release.yml:149-151`.

The comment says "exactly the ones Veil uses, nothing a dependency slipped in", but the step only asserts that CAMERA is present. A dependency or Tauri template change that adds, for example, `RECORD_AUDIO`, `ACCESS_FINE_LOCATION` or `READ_CONTACTS` passes silently.

Fix: compare against an allowlist, for example `printf '%s\n' android.permission.CAMERA android.permission.INTERNET | sort > want.txt && diff -u want.txt perms.txt`. Fill the list from the current build's output once.

**M2-6 Low: a search hit outside the loaded 500 messages breaks auto-scroll for the rest of the chat session**
`app/src/screens/Chats.tsx:273-285`.

When `msg-${found}` is not in the DOM (older than the 500 rows `messages()` returns), `found` is never cleared. The effect returns before `end.current?.scrollIntoView`, so new messages no longer scroll into view, and the user gets no hint that the hit is not shown.

Fix: once messages have loaded and the element is missing, call `setFound(undefined)` and show a hint ("This message is too old to show here"). Longer term, load a window around the hit.

**M2-7 Low: the Scanner starts its interval after it has been torn down**
`app/src/components/Scanner.tsx:62-63`.

If the component unmounts while `await v.play()` is pending, `stop()` has already run and the tracks are stopped (good). The `setInterval` created afterwards is then never cleared: a no-op timer every 200 ms leaks for the life of the page.

Fix: add `if (stopped) return;` after the `await`.

**M2-8 Low: a missing quote is attributed to the contact**
`crates/client/src/service.rs:761`; `Chats.tsx` quote rendering.

When the quoted row is gone (for example, our own message deleted for me), `mine` defaults to `false`. The UI then shows "{contact name}: Original message not available", attributing the gone message to them.

Fix: make `ReplyView.mine` an `Option<bool>` (`None` when `qid` is `None`), and render no author line in that case.

**M2-9 Low: the tests do not fully back what INVARIANTS.md claims**
`docs/INVARIANTS.md` rows INV-REST-10 and INV-MSG-8; `crates/client/src/db.rs:252`.
- **INV-REST-10** is marked **tested** and says search "never returns … expired messages", but `messaging::local_search` never exercises an expired row. Either add a case (timer set, wait until expiry or set `expires_at_ms` in the past, assert no hit) or mark the row partial.
- **INV-MSG-8** honestly relies on a written argument for crafted Edit/Delete/Reaction content. Add a harness helper that seals arbitrary `Content` from Bob's `Account` and asserts the following. The same helper covers M2-2.
  - An `Edit`/`Delete` naming one of Alice's own msg_ids changes nothing.
  - An `Edit`/`Delete` naming Bob's message from another conversation (Carol's) changes nothing.
  - A `Reaction` targeting a Carol-conversation id is ignored.
  - Duplicate ids do not multiply rows.
- **Migration test:** `migrates_an_old_database_once` starts at version 0. Nothing covers the actual preview.4 path, a `user_version = 1` database with M1 rows upgrading to 2 (columns added, `reactions` table present, cascade works).

**M2-10 Low: "my reaction" is shown by colour alone**
`app/src/screens/Chats.tsx:197, 433`; `base.css:378`; `app.css:61`.

The `.mine` state on reaction chips and the emoji row is shown only by the accent border and background. `aria-pressed` helps assistive technology, but sighted users who cannot tell the colours apart get no cue. This breaks CLAUDE.md's "no colour-only state".

Fix: add a non-colour marker to the `.mine` state, such as a small check glyph or a heavier border style. Propose the token change in design/DESIGN.md as well.

**M2-11 Info: notes, no action required**
- The safety QR is acceptable under rule 2. It encodes libsignal's scannable fingerprint (hashes of public identity keys), not key material, and FLAG_SECURE covers it on screen. The `#[serde(skip)]` on `SafetyView.code` is only cosmetic, though: the same string is recoverable from `qrModules`. Reword the doc comment so it does not suggest a secrecy property.
- `delete_for_everyone` decides "unsent" from `envelope IS NOT NULL`. If the relay accepted a deposit but the response was lost, the peer has the message and no `Delete` is sent. This is rare and covered by the "best effort" wording in ADR-0014.
- A received `Edit` with an empty body is accepted by the core and blanks the sender's own bubble. It is harmless, but `receive` could ignore empty edits for consistency with `edit_message`.
- SQLite `LIKE` folds case for ASCII only, so "Ä" does not find "ä". Worth one line in ADR-0014.

### Good
- The receive-side scoping is right and simple. Edits and deletes are limited to `mine = 0` within the same conversation and a 48 h window; reactions are limited to the conversation. Our messages cannot be changed remotely.
- Reactions, edits and deletes are sealed inside the savepoint and delivered after commit. They reuse the M1 delivery, retry and block machinery, so blocking and offline behaviour carry over unchanged.
- Delete-for-everyone handles the unsent case, overwrites the text, and drops reactions. Delete-for-me relies on the FK cascade together with `secure_delete`.
- The search query is correct: wildcards and the escape character are escaped, it is bounded (2–100 characters, 100 hits), and deleted and expired rows are excluded. The excerpt is trimmed in Rust, so only a short snippet reaches the webview.
- Verify-by-scanning delegates the comparison to libsignal's `ScannableFingerprint::compare`. A mismatch changes nothing and is shown as an alert, and the test covers another contact's code, a non-Veil code, a one-digit flip and the real code.
- In the camera flow, frames are decoded on an off-DOM canvas, tracks are stopped as soon as a code is read and on unmount, there is no clipboard use, and the Android permission is declared as optional hardware. jsQR was a well-chosen, dependency-free addition.
- All IPC goes through `ipc.ts`; all new text is rendered as React text nodes; the icon buttons have labels; and the emoji targets use `--tap-min`.

### Action options
Recommended: **B. Fix blocking only** (M2-1 to M2-4), then re-review. A, C and D (fix all, fix specific findings, or review only) are also available.

## Milestone 2 review, round 2

**Scope:** `git diff 6d0f275 5ae4a29` (the round-1 fixes), checked against the whole milestone (`git diff 91135dd 5ae4a29 -- crates app .github docs design`). Out of scope: `veil-TODO.md`, `app/src/media.ts` and `app/android/VeilNativePlugin.kt` (milestone 3).

**Verdict: PASS WITH CONDITIONS.** Every Medium finding from round 1 (M2-1 to M2-4) is fixed and covered by a test. There are no Critical, High or Medium findings in this round. There are four new Low findings and one Info. M2R2-2 should be fixed before milestone 3 adds the microphone; the rest can be fixed now or tracked.

**Commands run:**
- The working tree had uncommitted milestone 3 work that appeared while I was reviewing (`crates/client/src/service/attachments.rs`, plus changes to `service.rs`, `db.rs` and `lib.rs`). With those files, `cargo clippy -p veil-client --lib` fails with 3 errors, all in `attachments.rs`. So I ran every command on a clean detached worktree of 5ae4a29, and removed the worktree afterwards.
- `cargo test -p veil-client --lib --test messaging --test contacts_and_privacy`: 11 + 6 + 8 passed.
- `cargo clippy -p veil-client --lib -- -D warnings`, which builds without `test-hooks`: clean.
- `cargo clippy -p veil-client --all-targets -- -D warnings`: clean.
- `cargo fmt --all --check`: clean.
- `pnpm -C app typecheck`: clean.
- `pnpm -C app lint`: "12 files clean".
- `cargo tree -e features -i veil-client --manifest-path app/src-tauri/Cargo.toml`: only the `default` feature is enabled for the app. `test-hooks` appears only under `[dev-dependencies]` in the core workspace. `Cargo.lock` and `app/src-tauri/Cargo.lock` were not changed by 5ae4a29.

### Round-1 findings

| ID | Severity | Status | Verified against |
|---|---|---|---|
| M2-1 | Medium | **Fixed** | `edit_message` (`service.rs:2252`): when the target still has an envelope, it calls `reseal_text` instead of sending an `Edit`. `reseal_text` (`:2284`) seals one new `Text` with the same id, `reply_to`, `at_ms` and timer, and replaces the row's envelope and body inside one savepoint, so the seal and the update commit or roll back together. `react` refuses with `NotSentYet` when the target is ours and not sent yet (`:2198`). The actor processes commands one at a time (`run` loop at `:935`), so nothing can deliver or retry between the pending check and the re-seal. Old and new timer give the same value: `send` sets `expires = at + timer·1000`. Test: `messaging::editing_an_unsent_message` (it would fail on the round-1 code, which delivered an `Edit` with `edited = true`). One rare case is left; see M2R2-1. |
| M2-2 | Medium | **Fixed** | `receive` drops a `Text` whose `(contact, msg_id)` is already stored (`:2676`). The core enforces 16-byte random ids (`content.rs:274`), so the only legitimate repeat is M2R2-1. The quote is now resolved through `q.id = (SELECT … ORDER BY x.id LIMIT 1)` in both `messages()` and `message()`. Test: `crafted_content_from_a_contact_stays_in_its_lane` (one row for the repeated id; three replies, each quoted once; no row id twice). The optional `UNIQUE` index was not added; that is acceptable now that inserts check first. |
| M2-3 | Medium | **Fixed** (the test covers part of it, see M2R2-5) | `queue_control` stores the target's `expires_at_ms`, so the sweeper deletes the row with or without its envelope. `deliver` deletes a `kind = 'control'` row after a successful deposit. Interactions checked: `retry_failed` collects ids first, and a row deleted later just gets "no row" in `deliver`. The sweeper's unread adjustment counts only `mine = 0 AND kind = 'text'`, and contact ordering and `last_text` filter on `kind IN ('text','timer')`/`'text'`, so control rows do not affect either. |
| M2-4 | Medium | **Fixed** (one gap left, M2R2-3) | `Chats.tsx`: a `document` keydown handler covers Escape from anywhere and wraps Tab between the dialog's first and last buttons. The opener is stored in `openActions` and refocused by `closeActions` (`:406`); Reply and Edit focus the composer. No other Escape listener exists in `app/src` that could also fire. |
| M2-5 | Low | **Partially fixed**, see M2R2-2 | The release workflow now compares the APK's permissions with an allowlist (`comm -23`). The shell is correct: the `if` takes the pipeline's status, `grep .` succeeds only when there is output, and both files are sorted under the same locale. However, the list pre-approves permissions Veil does not declare, and the grep only sees `android.permission.*` names. |
| M2-6 | Low | **Fixed** | `loaded`/`tooOld`: a hit outside the loaded window shows an info banner and clears `found`, so auto-scroll resumes. `Chat` is keyed by `contact.id` plus focus (`App.tsx:104`), so `loaded` cannot carry over from another chat. |
| M2-7 | Low | **Fixed** | `if (stopped) return;` after `await v.play()`. |
| M2-8 | Low | **Fixed** | `ReplyView.mine: Option<bool>`, which is NULL when the join finds no row. `ipc.ts` now has `boolean \| null`, and the UI shows no author in that case. The test was updated to `Some(true)`/`Some(false)`. |
| M2-9 | Low | **Fixed** | There is now a crafted-content harness (`test-hooks`: `raw_send`, `msg_id`), an expired-search case, and `db::tests::migrates_a_version_1_database` (columns, `reactions` table, cascade). INV-MSG-8 slightly overclaims; see M2R2-4. |
| M2-10 | Low | **Fixed** | The user's own reaction now gets a check glyph (`#i-check` exists in `public/icons.svg`, and `Icon` is `aria-hidden`) and a 2px border on `.reaction.mine` and `.emoji-btn.mine`. Recorded in DESIGN.md. |
| M2-11 | Info | **Addressed** | The `SafetyView.code` doc comment is reworded, empty received edits are ignored (`Body::Edit(e) if !e.body.trim().is_empty()`), and the ASCII-only `LIKE` case folding is noted in ADR-0014. |

### New findings

**M2R2-1 Low: re-sealing after a deposit whose reply was lost leaves the two sides with different text, and the receiver drops the new version silently**
`crates/client/src/service.rs:2252` (`edit_message` pending branch), `:2284` (`reseal_text`), `:2676` (`receive` repeated-id drop).

"Pending" means `envelope IS NOT NULL`. That is also the state after a deposit the relay accepted but whose reply never arrived. This happens on a dropped connection, or when `interruptible` cancels `call` because of an auto-lock during a deposit.

Failure scenario:
1. Alice's text "first draft" reaches Bob's mailbox, but `deliver` records `failed` and keeps the envelope.
2. Before the next retry (`RETRY_EVERY` = 1 min) Alice edits it to "final words". `reseal_text` seals a new envelope with the **same content id**, and it is delivered.
3. Bob's client opens it. The text is valid (new ratchet counter), but `receive` sees the id is already stored and returns `Ok(())`.
4. Bob keeps "first draft". Alice sees "final words" with no "edited" mark. Nothing on either side shows the difference.

Before this fix, the same lost reply led to an `Edit` that Bob applied. Without an edit, a retry of the *same* envelope is harmless, because libsignal rejects the duplicate.

Fix: in `receive` `Body::Text`, when the id is already stored, do not drop it unconditionally. If the existing row is that contact's own live text (`mine = 0 AND kind = 'text' AND deleted = 0 AND at_ms > now - PEER_EDIT_WINDOW_MS`) and the body differs, apply it as an edit (`UPDATE … SET body = ?, edited = 1`). Otherwise drop it. This inserts no row, so the M2-2 protection still holds, and the scope is the same one a crafted `Edit` already has. Add a case to `crafted_content_from_a_contact_stays_in_its_lane`: a repeated id with a new body updates their own row and never ours.

**M2R2-2 Low: the Android permission allowlist pre-approves the microphone and misses non-`android.permission` names**
`.github/workflows/release.yml:152-156`.

- The allowlist includes `RECORD_AUDIO`, `MODIFY_AUDIO_SETTINGS`, `FOREGROUND_SERVICE*`, `WAKE_LOCK`, `RECEIVE_BOOT_COMPLETED`, `POST_NOTIFICATIONS` and `ACCESS_NETWORK_STATE`, "reserved" for milestones 3 and 4. At 5ae4a29 the APK declares only INTERNET, CAMERA (`harden.py:56`) and the biometric permissions. Round 1 established that the microphone stays denied in the webview only because RECORD_AUDIO is not in the manifest. A dependency or template change that adds RECORD_AUDIO now passes CI, and RECORD_AUDIO was the very example in M2-5.
- `grep -o 'android.permission.[A-Z_]*'` only sees names in the `android.permission.` namespace. A dependency that adds `com.google.android.gms.permission.AD_ID` (Play Services' advertising id) or `com.google.android.c2dm.permission.RECEIVE` is never compared with the list.
- The same grep also matches `android:permission="android.permission.BIND_…"` attributes on services. This fails closed, so it can cause a spurious failure but never a silent pass.

Fix:
- Allowlist only what this commit declares: `INTERNET CAMERA USE_BIOMETRIC USE_FINGERPRINT`. Add each further entry in the PR that declares it.
- Read the real `<uses-permission>` set: `"$BT/aapt2" dump permissions out/*.apk | sed -n "s/^uses-permission[^:]*: name='\([^']*\)'.*/\1/p" | sort -u > perms.txt`. This covers `uses-permission-sdk-23` and every namespace. Allowlist full names, including `${applicationId}.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` if AndroidX declares it.

**M2R2-3 Low: after "Delete for me", focus goes to a bubble that is about to disappear, then drops to `<body>`** [MEDIUM confidence]
`app/src/screens/Chats.tsx:244` (Delete for me), `:406` (`closeActions`), `:550` (`onDone`).

`onDone` calls `closeActions()` without `focusComposer`. `closeActions` refocuses the opener when `back.isConnected` after `setTimeout(0)`. The deleted row only leaves the DOM after the change event bumps `version` and a second `ipc.messages` round trip completes, so at that moment the bubble is normally still in the DOM.

Failure scenario: a keyboard or screen-reader user deletes a message for themselves. Focus goes to the old bubble, which is unmounted moments later, and focus falls to `<body>`. This is the case round 1 said should focus the composer. (Delete for everyone keeps a placeholder bubble, so it is fine.)

Fix: report the removal from the dialog, for example `onDone(err?: string, removed = false)`. Call `run(() => ipc.deleteForMe(m.id), …, true)`, and in `Chat` call `closeActions(removed)`, which focuses the composer.

**M2R2-4 Low (docs): INV-MSG-8 is marked "tested", but neither time window is tested**
`docs/INVARIANTS.md:62`.

The invariant promises edits and deletes "only their own messages from the last 48 h" (received) and "our own edits and deletes only within 24 h". The tests cover the conversation and authorship scoping, which is now mutation-checked. But no test exercises `PEER_EDIT_WINDOW_MS` or `EDIT_WINDOW_MS`: the two `TooLate` assertions (`messaging.rs:134, 158`) fail because of `!mine`, not age.

Fix (either one):
- Add a `test-hooks` helper that back-dates a row's `at_ms`, and assert `TooLate` for our own message older than 24 h, and that a crafted `Edit`/`Delete` for their message older than 48 h changes nothing.
- Or keep "tested" for the scoping only and state that the time windows rest on the `at_ms` conditions (written argument).

**M2R2-5 Info**
- **INV-REST-9 test gap:** the docs state it honestly. `edits_and_search_respect_disappearing_messages` passes even if `queue_control` ignored `expires_at_ms`, because Bob's copy expires too and he drops a late `Edit`. Now that `test-hooks` exists, a cheap way to cover it is a `pending_rows(contact)` hook asserting the control row is gone after expiry. That would turn the written argument into a test.
- **Leftover control rows:** a control row for a non-disappearing message that reaches `MAX_ATTEMPTS` stays forever with its envelope and `at_ms`, the same as a failed text. This is bounded by user actions, and no change is needed in this milestone. A later cleanup could delete control rows with `attempts >= MAX_ATTEMPTS` older than the edit window, since they can no longer apply.
- **Blocked contacts:** `edit_message`'s pending branch does not check `blocked`, while `queue_control` does. The UI hides Edit for blocked contacts. `deliver` filters `c.blocked = 0`, and the re-sealed envelope only replaces one that was already queued, so nothing new can go out. For consistency, return `ClientError::Blocked` before `reseal_text`.

### Questions from the brief, answered
- **Ratchet and state in `reseal_text`:** consistent. The seal and the envelope update share one savepoint, and the rollback on `n == 0` restores the store. The skipped counter of the discarded envelope is handled by libsignal's skipped message keys, and out-of-order delivery among queued messages works the same way. Only one envelope per content id is stored. Racing with `deliver` or `retry_failed` is impossible because the actor runs one command at a time. The only failure path is the lost reply in M2R2-1.
- **Can dropping repeated ids lose a legitimate message?** Only in M2R2-1. Ids are 16 random bytes enforced by the core, ordinary retries resend the same envelope (which libsignal drops), and no other path re-seals with an old id.
- **`test-hooks` in release builds:** it cannot leak. The app is a separate workspace whose dependency on `veil-client` has no features. Dev-dependencies of a path dependency are never built, and `cargo tree` confirms only `default` is enabled. No workflow uses `--all-features`. The library builds and passes clippy without the feature.
- **release.yml shell:** it is correct, and the current APK will not fail it spuriously. The problems are scope, covered in M2R2-2.

### Good
- The M2-1 fix is the right design. The unsent message is re-sealed with its original id, quote, timestamp and timer inside the same savepoint as the store update, so the peer only ever sees one version and the sender does not show a false "edited". Refusing reactions until the message is sent is simple and honest in the UI ("Wait until this message is sent").
- The control-row lifecycle is now clear: a row expires with its target, is deleted with `secure_delete` after delivery, and leaves the unread counts, contact ordering and last-message preview untouched.
- The `test-hooks` crafted-content harness is a real gain. It exercises the hostile-contact paths end to end through a real relay, and the mutation checks recorded in INVARIANTS.md hold up when I check them against the code.
- The quote subquery returns exactly one row per message, and the receive-side drop fixes the cause. Together they fix M2-2 without a schema migration.
- The dialog now has the full keyboard contract (trap, global Escape, focus return). The "my reaction" state has a non-colour cue that is recorded in DESIGN.md. The migration test now covers the real version-1 upgrade path.

### Action options
Recommended: **D. Review only**, or **C. Fix specific findings** for M2R2-2 (before milestone 3 adds the microphone) and M2R2-1. The remaining findings can be tracked in `veil-TODO.md`.

## Milestone 3 review, round 1

**Scope:** `git diff 5ae4a29 53e4f76` (commits 009ef1d and 53e4f76), plus `app/src/media.ts` and `app/android/VeilNativePlugin.kt` `saveFile` (from e6118f1). I checked the code against ADR-0015, PROTOCOL §9, INV-ATT-1..4 and CLAUDE.md's non-negotiables. I also read the code these changes depend on: the relay blob store (`crates/relay/src/store.rs` `put_chunk`/`get_chunk`, `server.rs` blob handlers), core `attachment.rs` and `content.rs` validation, and Tauri 2.12.4's IPC transport (`~/.cargo/registry/src/*/tauri-2.12.4/scripts/ipc-protocol.js`, `src/ipc/mod.rs`, `src/ipc/protocol.rs`).

**Verdict: FAIL.** 1 Critical, 1 High, 3 Medium, 7 Low, 1 Info. The crypto and the hostile-relay and hostile-contact handling in Rust are sound. The blocking problems are on the app side:
- Sending any attachment fails on Android, which is the shipped target (M3-1).
- The webview probably writes plaintext photos to disk (M3-2).

**Commands run** (on a temporary detached worktree of 53e4f76 with its own target dir; both removed afterwards):
- `cargo test -p veil-client --locked --test attachments --test messaging`: attachments 4 passed, messaging 7 passed.
- `cargo test -p veil-client --lib --locked`: 12 passed.
- `cargo clippy -p veil-client --all-targets --locked -- -D warnings`: clean.
- `cargo clippy -p veil-client --lib --locked -- -D warnings` (without `test-hooks`): clean.
- `cargo fmt --all --check`: clean.
- `pnpm typecheck`: clean. `pnpm lint`: "13 files clean".
- Not run: `app/src-tauri` clippy (needs the webkit system libraries), the release workflow on a real APK, and anything on an Android device.

### Milestone 2 round-2 fixes (in 009ef1d)

| ID | Status |
|---|---|
| M2R2-1 | **Fixed.** In `receive` `Body::Text`, a repeated id with a new body updates only `mine = 0 AND kind = 'text' AND deleted = 0 AND at_ms > now-48h` rows and never adds a row. Tested in `crafted_content_from_a_contact_stays_in_its_lane`: their repeat edits, a repeat of our id does nothing. `Body::Attachment` repeats are dropped and never treated as edits. |
| M2R2-2 | **Fixed.** `aapt2 dump permissions` plus the `sed` covers `uses-permission-sdk-23` and every namespace. The allowlist contains exactly what is declared (INTERNET, CAMERA, RECORD_AUDIO and MODIFY_AUDIO_SETTINGS from `harden.py`, the AndroidX biometric permissions, and `org.veil.app.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`, which matches `identifier: org.veil.app`). If aapt2 fails, `perms.txt` is empty and the trailing `grep -qx android.permission.CAMERA` fails the job, so it fails closed. I could not run it against a real APK. |
| M2R2-3 | **Fixed.** "Delete for me" passes `removed = true`, and `closeActions(true)` focuses the composer. |
| M2R2-4 | **Fixed.** `edit_and_delete_time_windows` uses the `backdate` hook to cover both windows (24 h for ours, 48 h for theirs). |
| M2R2-5 | **Fixed.** `hidden_rows` asserts that the queued edit is gone after expiry. `edit_message`'s pending branch now returns `Blocked`. |

### Findings

**M3-1 Critical [HIGH]: sending a photo, file or voice note always fails on Android**
`app/src-tauri/src/lib.rs:304` (`send_attachment`), `app/src/ipc.ts` (`callRaw`).

The command only accepts `tauri::ipc::InvokeBody::Raw`. Tauri 2.12.4 never delivers a raw body on Android:
- `ipc-protocol.js:20` says `canUseCustomProtocol = osName !== 'android'`, so every call goes through `postMessage`.
- `process-ipc-message-fn.js` turns the `Uint8Array` into a JSON array.
- `protocol.rs` `handle_ipc_message` builds `body: message.payload.into()`, which is `InvokeBody::Json`.
- The Tauri docs at `src/ipc/mod.rs:55` say: "On Android, InvokeBody::Raw is not supported. The enum will always contain InvokeBody::Json."

Failure scenario: on the release APK, every pick, photo or voice note returns `BadInput` ("Could not send…"). No test runs this path on Android. Desktop works.

The reverse direction is fine: `attachment_data` returns a raw `Response`, which goes through a Channel fetch that Android allows.

Fix:
- Use a transport that works on Android. Preferred: chunked commands such as `attachment_begin(meta) -> handle`, `attachment_part(handle, base64 ≤ 1 MiB)` and `attachment_commit(handle)`. Bound the total at `MAX_FILE`, and wipe partial buffers on abort and on lock.
- Alternatively, on Android only, send one JSON body with the file as a base64 string. This is what Tauri recommends, but it means a ~33 MB string per send.
- Do not accept the JSON number-array form: that is about 100 MB of JSON for a 25 MB file.
- Add an e2e or unit test that drives `send_attachment` with the JSON body shape Android produces.

**M3-2 High [MEDIUM confidence: needs on-device confirmation]: the Android WebView can write plaintext photos and files to disk through Blob storage**
`app/src/components/Attachment.tsx:20-43` (`useFileUrl`), `:116` (every `ImageAttachment` requests the full file), `:68-69` (`saveFile` desktop path).

Chromium's `BlobMemoryController` keeps blobs in memory only up to `max_blob_in_memory_space`. On Android that is 1 % of RAM (about 30–80 MB). Above `memory_limit_before_paging`, it moves blob data into files under the profile's `blob_storage/` directory, here `app_webview/Default/blob_storage`. Large new blobs may also use the FILE transport directly. WebView profiles are not off-the-record, so file paging is enabled.

Failure scenario:
- A conversation with dozens of photos mounts one full-resolution `new Blob([buf])` per image. On a 3–4 GB phone, the live blob bytes go over the limit, especially with a 25 MB GIF (GIFs are inline images and are not re-encoded).
- Chromium then writes the decrypted photos in plaintext to the app's data directory, outside SQLCipher.
- This breaks non-negotiable 6 and INV-ATT-4 ("stored only inside SQLCipher").
- M3-3 makes it worse, because every refresh creates a new set of blobs.

Fix:
- In the list, render only the inline thumbnail (≤ 8 KiB). Fetch the full image only in `PhotoViewer`, and keep at most one full-size blob alive at a time.
- For voice notes, create the blob on Play and revoke it on pause, end or unmount.
- Cap inline images at a few MB; larger GIFs show as a file.
- Add a device test or written argument in INVARIANTS (INV-REST-1, INV-ATT-4): open a chat with many large images, then scan `app_webview/` for a canary.
- Clear `blob_storage` at lock as defence in depth.

**M3-3 Medium [HIGH]: any message event re-downloads every shown file and restarts a playing voice note**
`app/src/components/Attachment.tsx:41` (`[m.id, ok, a]`), `:159-173` (VoiceNote effect), `app/src/App.tsx:84-87`.

- Every `messages` change event, for any contact, bumps `version`. That includes progress events every 16 chunks of any transfer, receipts and new messages.
- `Chat` then reloads, and every `AttachmentView` is a new object. The `a` dependency changes, so the effect revokes the URL, sets it to null (the thumbnail flashes) and calls `attachment_data` again.
- Each call is an actor command that reads up to 25 MB from SQLCipher and copies it over IPC.
- In `VoiceNote`, the new `url` creates a new `Audio` and calls `play()` from the start.

Failure scenario: while you listen to a voice note, a message arrives or another transfer reports progress, and playback jumps back to 0:00. A chat with 20 photos re-reads all 20 full files about every 1 MB of any background transfer, which delays the user's own commands behind them.

Fix:
- Depend on primitives only: `[m.id, ok, a?.mime]`.
- Keep the `Audio` element across URL changes. Call `play()` only from `toggle()`, never in the effect.
- Combine with M3-2: fetch only on view or play.

**M3-4 Medium [HIGH]: one failing transfer blocks all others for minutes, and a contact can stall the user's uploads**
`crates/client/src/service/attachments.rs:246` (`ORDER BY message LIMIT 1`), `:285`, `:290-317` (`transfer_failed`), `service.rs:1038` (`wake_transfers` every 5 s tick).

- `transfer_step` always picks the oldest pending transfer.
- A failed request (for example `BlobGet` → `NotFound` for a blob id that does not exist) sets `transfers = false`. The next tick (5 s) picks the same row again. Only after 30 attempts does the row become `failed`.
- So each bad transfer holds the queue for at least 150 s, and the `Attachment` message is sealed only after its upload.

Failure scenario: a hostile (or just buggy) contact sends 50 `Attachment` messages with random blob ids. Their rows come before any later upload of ours. Every photo the user sends to anyone sits in "Encrypting and uploading · 0%" for about 2 hours. Expired blobs (30 days) cause the same stall by accident.

Fix:
- Treat `Rejected(NotFound)` on download as final: mark it `failed` at once.
- Add a `next_attempt_ms` column with backoff, and select `WHERE next_attempt_ms <= now ORDER BY state = 'download', attempts, message`, so uploads go first and a failing row does not hold the head of the queue.
- Test: a crafted `Attachment` with a missing blob, followed by an upload that must finish promptly.

**M3-5 Medium [HIGH]: the client checks against a hostile relay or contact are untested, and two invariants over-claim**
`crates/client/tests/attachments.rs`, `docs/INVARIANTS.md:49-50`.

These checks have no test:
- `download_step`: `total_chunks` mismatch, short non-last chunk, oversize chunk (`attachments.rs:509-513`).
- `receive_attachment`: `padded_size` mismatch (`:602`) and `too_large`.
- The path where a forged hash ends in `failed` and is never shown.
- Repeated attachment ids.

Mutating any of these lines would leave the suite green. Also:
- INV-ATT-3 says "uploads/downloads" are tested, but only an upload resume is.
- INV-ATT-4 says files are "stored only inside SQLCipher", but no test scans the data dir for an attachment canary (`pair_and_message.rs` scans only for text).

Fix:
- Use `raw_send` to send crafted `Attachment`s: wrong sha, `padded_size ≠ padded_size(size)`, `size > MAX_FILE`, a repeated id. Assert there is no row, or `failed`/`too_large`, and that `attachment_data` returns an error.
- Add a `Proxy` mode that rewrites `BlobChunk` frames (total, length, bytes).
- Add a download-resume test (cut the connection mid-download).
- After the round trip, scan the data and temp dirs for the file's canary bytes.
- Either add these or reduce the claims to match.

**M3-6 Low [HIGH]: transfer bookkeeping is not atomic, and a download at `next == total` asks for a chunk that does not exist**
`attachments.rs:386-393` (upload: delete chunk, then update `next_chunk`), `:516-527` and `:564-570` (download: delete chunks, then update state), `:497-500`.

Failure scenario:
- A crash or `SQLITE_FULL` between the two statements in `upload_step` leaves `next_chunk` pointing at a chunk that was deleted. Every later step fails, and after 30 attempts the upload is `failed`.
- In download, if `finish_download` errors after `next_chunk = total`, the next step sends `BlobGet(chunk_index = total)`, gets `NotFound` 30 times, and then fails.

Neither path leaks anything, but both waste attempts and leave the transfer for a manual retry.

Fix:
- Do each step's writes in one savepoint (no relay I/O inside), or update `next_chunk` before deleting the chunk.
- In `download_step`, if `t.next >= t.total`, call `finish_download` directly.

**M3-7 Low [HIGH]: a dead upload token is retried 30 times**
`attachments.rs:341-359`, `:381-384`, relay `store.rs` `put_chunk` (`MAX_EXTRA_PUTS = 16`, 24 h token TTL, an incomplete blob expires with its token).

Failure scenario: the phone stays locked or offline for more than 24 h with an upload pending, or 16 replies are lost. Every remaining `BlobPut` then returns `Unauthorized` or `Quota`. The client reuses the stored token for 30 attempts (about 2.5 min) and then shows "Not sent". A new token cannot finish the old blob id either (`Conflict`).

Fix: on `Unauthorized` or `Quota` for a non-final chunk, call the existing `retry_attachment` path once automatically (fresh key, blob id and token; no nonce reuse) instead of counting attempts.

**M3-8 Low [MEDIUM]: photo metadata stripping covers fewer formats than users will expect, and the WebP fallback mislabels the type**
`app/src/media.ts:60-75`.

- Only JPEG, PNG and WebP are re-encoded.
- HEIC/HEIF (the default on many Samsung phones and on iPhone), AVIF, TIFF, and any photo whose `File.type` is empty are sent unchanged as files, with EXIF and GPS.
- GIF is sent unchanged as an image.

ADR-0015 does say "other files are sent unchanged", but the UI gives no hint. Separately, WebKit (Linux/macOS desktop) falls back from `toBlob("image/webp")` to PNG, yet the mime is hard-coded as `image/webp`.

Fix:
- Re-encode every `image/*` that `createImageBitmap` can decode, except SVG and animated GIF.
- Use `out.type` as the mime.
- When an image is sent as a file, say so: "Sent as a file; its location data is kept".

**M3-9 Low [HIGH]: the microphone stays on after the 5-minute limit, and on setup errors**
`app/src/media.ts:97-131`.

- `autoStop` stops the `MediaRecorder` only. The stream tracks, the `AudioContext` and the 100 ms sampler keep running, and the bar shows times past "5:00 / 5:00", until the user taps.
- If `new MediaRecorder(...)` or `new AudioContext()` throws after `getUserMedia`, the stream is never stopped, and the mic indicator stays on until the page reloads.

Fix:
- In `autoStop`, call `release()` and notify the UI so it shows the stopped state with Send/Discard.
- Wrap everything after `getUserMedia` in `try { … } catch (e) { for (const t of stream.getTracks()) t.stop(); throw e; }`.

**M3-10 Low [HIGH]: Android save keeps one global `pendingSave`, so a double tap can save the wrong file**
`app/android/VeilNativePlugin.kt:346-367`, `Attachment.tsx:215` and `:262` (no in-flight guard).

Failure scenario: the user taps Save on file A, then quickly on file B. The second call replaces `pendingSave`. The first picker's result writes B's bytes under the location and name the user chose for A. The second call then gets "Cancelled".

Fix:
- Reject `saveFile` while a save is pending (`invoke.reject("Busy", "FAILED")`), or key the bytes by invoke.
- Disable the Save buttons while a save is in flight.

**M3-11 Low: accessibility and design issues in the new UI**
- `Attachment.tsx:248-268`: `PhotoViewer` is `aria-modal` but does not trap Tab and does not return focus to the photo button on close. The `MessageActions` dialog already does both; reuse that pattern.
- `Chats.tsx:605`: the recording bar is `role="status" aria-live="polite"` and contains the running timer, so screen readers announce it every second. Put the live region on a static "Recording" label and keep the timer outside it, or use `aria-live="off"`.
- `app.css:78-84`: raw `#000`/`#fff` break "only design tokens" in CLAUDE.md. Add viewer tokens to `tokens.css`.

**M3-12 Low [HIGH]: no total storage limit for automatic downloads**
`attachments.rs:599-631`.

Every attachment of 25 MB or less from any contact is downloaded automatically and stored in full. Only the relay's per-mailbox upload-token rate limits how fast a contact can do this.

Failure scenario: a hostile contact sends many 25 MB files over a few days. The vault grows by gigabytes, and the phone runs out of storage, which also breaks writes to the database.

Fix: add a per-contact (or total) quota for files not yet opened. Above it, store the row as "tap to download" (state `available`, started by a command) instead of `download`.

**M3-13 Info**
- **Plaintext copies in memory are not wiped:** the Tauri request body, `data.to_vec()` in `send_attachment`, the `Response` vec in `attachment_data`, the JSON serialisation of `SaveArg`, and the Kotlin `String`/args. This is memory only and not at rest; note it in the threat model.
- **Desktop save** depends on the webview's default download handling, because there is no `on_download` handler. WebView2 and WebKitGTK save to Downloads without a dialog. WKWebView may ignore the click. A Rust save dialog would make it explicit.
- **Speed:** a transfer sends one 64 KiB chunk and waits for the reply before the next. At 300 ms RTT, 25 MB takes about 2 min, and auto-lock pauses it, as documented.
- **`blob:` in the CSP is safe:** blob URLs can only be created by same-origin scripts, `script-src 'self'` still blocks inline script in any blob document, and no code navigates to a blob.

### Good
- **Hostile-relay handling on download is right:** the chunk count must equal the authenticated `total_chunks`, every non-final chunk must be full-size, the last one is bounded, the SHA-256 is checked before decrypting (constant-time, in the core), and a failure ends in `failed` and is never shown. A replayed or swapped blob cannot pass the hash.
- **No nonce or key reuse:** a resumed upload re-sends stored ciphertext, and a retry re-encrypts under a fresh key, nonce prefix and blob id. Relay I/O is never inside `atomically`. The seal and the `state = 'sent'` update commit together.
- **The run loop is designed well:** a `biased` select with commands first, transfers only when nothing else is ready, `wants_transfer` respects `idle_expired`, and every chunk request goes through `interruptible`, so lock and auto-lock pre-empt transfers.
- **Contact input is cleaned at the boundary:** the core validates sizes, key lengths, mime and name, and the client re-checks `padded_size(size)`, cleans names (no paths, no control or bidi characters), keeps SVG out of inline images, and clamps voice duration.
- **Deletion removes the file:** delete-for-everyone, a received delete, expiry and contact deletion all remove it (cascade with `foreign_keys = ON`, `secure_delete = ON`).
- **The M2 round-2 fixes are clean and tested.** The release permission allowlist is now exact and fails closed.

### Action options
Recommended: **A. Fix all**, or at minimum **B. Fix blocking only** (M3-1, M3-2, then M3-3 to M3-5), then re-review.

## Milestone 3 review, round 2

**Scope:** fix commit 4311055 (`git show 4311055`), checked against the round-1 findings M3-1 to M3-13. I read these files in full at HEAD:
- `app/src-tauri/src/lib.rs`: `Uploads` and the `attachment_*` commands
- `app/src/ipc.ts`: `sendAttachment`
- `app/src/components/Attachment.tsx`
- `app/src/media.ts`
- `crates/client/src/service/attachments.rs`
- `crates/client/tests/attachments.rs`
- `app/src/screens/Chats.tsx`: the send paths
- `VeilNativePlugin.kt`: `saveFile`
- the documentation changes: ADR-0015, INV-ATT-3/4/5, THREAT_MODEL §5.6

I also read the relay's `put_chunk`/`get_chunk` and BlobUploadToken handling, to check the client's error classification.

**Verdict: PASS WITH CONDITIONS.** 0 Critical, 0 High, 2 Medium, 4 Low, 3 Info. All 13 round-1 findings are fixed or partly fixed. The conditions before a release:
- Fix M3R2-1 and M3R2-2.
- Run the INV-ATT-5 device check, which is still owed.

**Commands run** (in `/home/user/ataraxia` at HEAD 4311055, shared target dirs):
- `cargo test -p veil-client --locked`: lib 14 passed; attachments 9; contacts_and_privacy 8; lock_and_setup 3; messaging 7; notifications 3; pair_and_message 2; unlock_options 5. All passed on the first run.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: clean.
- `cargo fmt --all --check`: clean.
- `(cd app/src-tauri && cargo test --locked)`: 3 passed (`a_file_arrives_in_parts`, `unknown_fields_and_stale_parts_are_refused`, `too_large_drops_the_upload`).
- `(cd app/src-tauri && cargo clippy --all-targets --locked -- -D warnings)`: clean.
- `pnpm -C app typecheck`: clean. `pnpm -C app lint`: "13 files clean".
- Not run: anything on an Android device, the release workflow, and the design checks (they need `pnpm install` from the network).

### Round-1 findings

| ID | Status | Evidence |
|---|---|---|
| M3-1 | **Fixed** (new issue: M3R2-1) | The file now goes over in JSON-only base64 parts: `attachment_begin` / `attachment_part` / `attachment_commit` (`lib.rs:300-414`). Bounds: each part ≤ 2 MiB of base64 (`MAX_PART_CHARS`); the total is checked against `MAX_FILE` before growing, and an oversize upload is dropped. The buffer is `Zeroizing`, and it is grown by hand into a new `Zeroizing` vec, so no reallocation leaves an unwiped copy. Stale ids are refused (`filter(\|u\| u.id == upload)`, and `take` checks the id). The slot is cleared on `ChangeKind::Locked` (`lib.rs:598-601`), which also covers Reset and Purge while unlocked, because both go through `lock_now`. A mutex poisoned by a panic is recovered rather than unwrapped. Unit tests drive it with the JSON shape the UI sends. |
| M3-2 | **Partly fixed** | The list fetches a photo only while it is on screen and only up to 2 MB. The viewer holds one photo of at most 8 MB. A voice note's blob lives from Play to its end. Android Save goes through the native plugin, with no blob. INV-ATT-5 records the argument honestly as "argued, not device-tested". It assumes voice notes are ~1.2 MB, but a contact can send a 25 MB one (M3R2-2). |
| M3-3 | **Fixed** | `useFileUrl` depends on `[m.id, ok, mime]` only. `VoiceNote` creates its `Audio` only in `toggle()`, so a list refresh neither refetches nor restarts playback. |
| M3-4 | **Fixed** | `next_attempt_ms` backoff (2 s doubling, at most 5 min). Selection is `ORDER BY state = 'download', attempts, message`, so uploads go first and a failing row cannot hold the head of the queue. `NotFound` on a download and `Protocol` (wrong chunk shape) give up at once. |
| M3-6 | **Fixed** | Each upload and download step writes in one `atomically` block with no relay I/O inside. `download_step` with `next >= total` calls `finish_download` directly. |
| M3-7 | **Fixed** (weak test: M3R2-4) | `Unauthorized`, `QuotaExceeded` or `Conflict` on an upload leads to `restart_upload(automatic)`. That re-encrypts under a fresh key, nonce prefix and blob id, clears the token, and is capped at `MAX_RESTARTS = 2`; a user retry resets the count. `RateLimited` on the token request is retried without counting, which is correct. The lost last-chunk reply is still recognised through `blob_complete`. |
| M3-5 | **Fixed** | New tests: `crafted_attachments_never_show_a_wrong_file` (forged hash, bad padding, wrong chunk count, too large, repeated id), `missing_blobs_do_not_hold_up_uploads`, `download_resumes_after_the_connection_drops`, `an_expired_upload_token_starts_a_fresh_upload`, `a_contact_cannot_fill_the_phone`, and a recursive plaintext scan of both data folders after the round trip. The hostile-relay chunk shapes are unit-tested on `chunk_fits`, which is the exact predicate `download_step` applies. INV-ATT-4 now says exactly that, so it no longer over-claims. |
| M3-8 | **Fixed** (residuals: M3R2-3) | Every `image/*` except SVG and GIF is decoded and re-encoded. The mime comes from `out.type`. Images sent unchanged get a note. |
| M3-9 | **Fixed** | `autoStop` → `halt()` stops the recorder and releases the tracks, the `AudioContext` and the sampler, then runs `onLimit`. Everything after `getUserMedia` is wrapped in try/catch, which stops the tracks on error. `elapsed` is clamped. |
| M3-10 | **Fixed** | Kotlin rejects `saveFile` while `pendingSave != null`. JS has a module-level `saving` guard, and the Save buttons are disabled while busy. |
| M3-11 | **Fixed** | `useDialogKeys` is shared by the viewer and the action dialog. The viewer returns focus to its opener. The live region is a static "Recording" / "stopped at the limit" label, with the timer outside it. Viewer and QR colours are now `--media-backdrop`, `--on-media` and `--qr-paper` in both `tokens.css` files. |
| M3-12 | **Partly fixed** (M3R2-5) | Per contact, files download by themselves up to 100 MB per rolling 24 h; above that they arrive as `available` and download on a tap. The retry path accepts `available` only for received rows (`m.mine = 0`) and resets attempts and backoff. This limits the rate, not the total. |
| M3-13 | **Addressed** | THREAT_MODEL §5.6 now names the IPC, webview and plugin copies of files. Desktop save is unchanged: it still uses the webview's download handling, with no `on_download` handler. |

**Migration 3 edited in place: acceptable.** No release contains it (v0.1.0-preview.4 predates M2), so no user's vault is at `user_version = 3` without the two new columns. The only exposure is a developer vault built from 009ef1d or 53e4f76. There, the selection query in `transfer_step` fails, and the `.ok().flatten()` hides the error, so transfers silently never run. Tell anyone testing M3 builds to recreate their vault. Do not edit migrations in place once anything has been tagged.

### Findings

**M3R2-1 Medium [HIGH]: two sends in flight wipe each other, and the first file is lost without a word**
`app/src-tauri/src/lib.rs:412` (`attachment_abort` takes no id), `app/src/ipc.ts:187-208`, `app/src/screens/Chats.tsx:247`.

The shell keeps one upload slot. `sending` is per-`Chat` state, and `Chat` is keyed by contact (`App.tsx:106`), so it does not serialise across chats.

Failure scenario:
1. The user sends a 20 MB file in chat A. That is about 20 parts, several seconds of base64 encoding on a phone.
2. The user goes back and sends a photo in chat B. `attachment_begin` for B replaces A's upload.
3. A's next part gets `BadInput`. A's `catch` calls `attachment_abort()`, which clears **B's** upload, so B fails too ("Could not send this file").
4. A failed before `attachment_commit`, so no message row exists. Its `Chat` has unmounted, so no error is shown either. The user's first file simply never appears.

Nothing leaks: the ids prevent mixing bytes from the two uploads.

Fix:
- Make `attachment_abort(upload: u64)` drop only its own upload:
  ```rust
  #[tauri::command]
  fn attachment_abort(uploads: State<'_, Uploads>, upload: u64) { drop(uploads.take(upload)); }
  ```
  and in `ipc.ts` call `call("attachment_abort", { upload })`.
- Serialise sends in `ipc.ts` with a module-level queue, so a second send waits instead of replacing the first:
  ```ts
  let queue: Promise<unknown> = Promise.resolve();
  function sendAttachment(contact: number, a: OutgoingAttachment) {
    const run = queue.then(() => sendOne(contact, a), () => sendOne(contact, a));
    queue = run.catch(() => undefined);
    return run;
  }
  ```
- Add a unit test: begin(A), begin(B), abort(A), then B's parts and `take` still work.

**M3R2-2 Medium [MEDIUM: Chromium limits per device not verified]: a contact's oversized "voice note" breaks the INV-ATT-5 argument**
`crates/client/src/service/attachments.rs:646` (`kind_for(&mime, a.voice_duration_ms.is_some() && …)`, with no size bound for voice), `app/src/components/Attachment.tsx:255` and `:333`, `docs/INVARIANTS.md:51`.

INV-ATT-5 counts "one playing voice note (≤ 5 min at 32 kbit/s, about 1.2 MB)". That bound comes from our own recorder, not from what we accept. On receive, any `audio/*` with `voice_duration_ms` set becomes `kind = voice`, up to `MAX_FILE`. The duration is clamped; the size is not.

Failure scenario:
1. A hostile contact, or a modified client, sends a 25 MB `audio/webm` with `voice_duration_ms = 1000`.
2. It downloads by itself (it is within the 100 MB allowance).
3. The user taps Play. `toggle()` makes `new Blob([25 MB])`.
4. On a 2–3 GB phone (1 % of RAM is 20–30 MB, minus Chromium's 5 MB minimum page file), that blob is over the limit before paging. Chromium then pages it, or moves it by file, into `app_webview/…/blob_storage`. That is plaintext outside SQLCipher (rule 6, INV-ATT-4).

A related caveat for the written argument: `URL.revokeObjectURL` does not free blob data. The browser keeps it until the renderer garbage-collects the `Blob`. Fast scrolling through many ≤ 2 MB photos can therefore hold more than the "on-screen" set for a while.

Fix:
- Bound voice by size where it is classified. In `receive_attachment` and `send_attachment`, a voice note larger than `MAX_VOICE_BYTES` (for example 4 MiB, generous for 5 min of Opus) is a `file`:
  ```rust
  const MAX_VOICE_BYTES: u64 = 4 * 1024 * 1024;
  let voice = a.voice_duration_ms.is_some() && mime.starts_with("audio/") && a.size <= MAX_VOICE_BYTES;
  ```
  With that, the Android Save path takes it and no blob is made.
- Mirror the bound in `AttachmentBody`: `a.kind === "voice" && a.size <= VOICE_MAX`.
- Restate INV-ATT-5 in terms of what Veil accepts (claimed sizes, checked against the decrypted length), not what honest senders produce.
- Add the GC caveat to the argument, and include a fast-scroll pass in the device check.

**M3R2-3 Low [HIGH]: GIFs are told "Sent as a file" but show as photos, and images with an empty type get no note**
`app/src/media.ts:61` and `:89`, `crates/client/src/service/attachments.rs:155`.

- `prepareFile` sends a GIF unchanged with `kind: "file"` and the note "Sent as a file, so any location or camera details in it were kept". But `send_attachment` ignores the UI's kind except for voice: `kind_for("image/gif", false)` returns `"image"`. Both sides therefore show it inline (up to 2 MB) or in the viewer (up to 8 MB).
- ADR-0015 says GIFs are sent as files, which is also wrong.
- A picked image with an empty `File.type` (some file managers do this) is neither re-encoded nor given a note.

Fix (pick one):
- Make GIF a file: when `input.kind == "file"`, use `"file"` (`kind_for` only promotes when the UI asked for an image). Drop `image/gif` from `INLINE_IMAGES` if you want GIFs never inline on receive either.
- Or keep GIFs inline and change the note to "Sent unchanged…" and correct the ADR.

For the empty type, also try `createImageBitmap` when `file.type === ""`.

**M3R2-4 Low [MEDIUM]: `an_expired_upload_token_starts_a_fresh_upload` can pass without testing a restart**
`crates/client/tests/attachments.rs:585`.

The test cuts the connection once `progress > 0` on a 1 MB file (16 chunks, polled every 50 ms). It never checks that the upload was still in progress at the cut, so a fast machine can finish the upload first and the test passes anyway. It also never checks that a fresh key or blob id was used, which INV-ATT-3 claims. Mutating the `Unauthorized | QuotaExceeded | Conflict` arm in `transfer_step` could leave the suite green.

Fix:
- Use a larger file (≥ 4 MB).
- After `online(false)`, assert `status == "sending"` and `progress < 1.0`, as `download_resumes_after_the_connection_drops` does.
- Add a test hook that reads `restarts` or `blob_id`, and assert that it changed.

**M3R2-5 Low [HIGH]: the automatic-download allowance limits the rate, not the total**
`attachments.rs:650-662`.

A hostile contact stays under 100 MB per rolling 24 h indefinitely: about 3 GB a month per contact, never opened, with several hostile contacts adding up. That is slower than round 1's scenario but still fills a phone over weeks. ADR-0015's "a contact cannot fill the phone" over-claims.

Fix: also cap the total of automatically downloaded, never-opened files. For example, `SUM(size) WHERE mine = 0 AND state = 'ready' AND opened = 0` at 500 MB across all contacts; above it the state is `available`. Or reword the ADR to "limits the rate".

**M3R2-6 Info: the integration tests do not exercise ordering or backoff**
`missing_blobs_do_not_hold_up_uploads` uses `NotFound`, which now gives up at once. Removing `next_attempt_ms <= ?1` or the `state = 'download'` ordering would still pass it. Only `backoff_ms` is unit-tested. Add a case where a download fails with a retryable error (a `Proxy` mode that drops `BlobGet` replies) and an upload started afterwards still finishes promptly.

**M3R2-7 Info: plaintext copies outside the zeroizing buffer**
Each part's JSON string and serde_json's intermediate `Value` are not wiped. Neither are the JS `bin` and base64 strings. This is memory only, and now covered by THREAT_MODEL §5.6.

**M3R2-8 Info: the upload commands work while locked**
`attachment_begin` and `attachment_part` do not check the lock state, so the webview can fill the 25 MB buffer while locked. This is harmless: commit fails while locked, and the next Locked event (or a new begin) drops the buffer. If a stuck `saveResult` ever left `pendingSave` set, Android Save would refuse until restart; this is not seen in practice.

### What is good
- **The upload buffer is careful.** Bounds are checked before growth, growth is by hand into zeroizing storage, stale ids are refused, the buffer is cleared on lock, and the Tauri unit tests use the exact JSON the UI sends.
- **The transfer engine is now robust against both a hostile contact and a hostile relay.** Uploads go first. Failing rows back off and never hold the head of the queue. Permanent failures end at once. Steps are atomic. Restarts always use a fresh key, nonce prefix and blob id, never the old key.
- **The new hostile-contact tests are real.** Forged hash, inconsistent sizes, more chunks claimed than the blob has, too large, and a repeated id each end without a wrong file. `attachment_data` refuses them. The plaintext scan covers both data folders.
- **The documentation is honest.** INV-ATT-4 and INV-ATT-5 state exactly what is tested versus argued, and INV-ATT-5 lists the device check still owed.
- **The media fixes are clean.** The microphone is released on every path, the photo mime comes from the encoder, and the recording live region is fixed.

### Action options
Recommended: **B. Fix blocking only**: M3R2-1 and M3R2-2, then run the INV-ATT-5 device check before tagging. M3R2-3 to M3R2-5 can follow in a later PR.

## Milestone 4 review, round 1

**Scope:** commit eaacb66 (`git show eaacb66`), checked against ADR-0016, INV-REST-4/5 and CLAUDE.md's rules 3, 6, 7 and 8. Files read:
- `crates/client/src/service/watcher.rs`, in full
- the watcher wiring in `crates/client/src/service.rs`: `lock_now`, `open_session`, `unlock` (Purge and Key paths), Reset, the `run` select, `on_tick`, `Notify`/`SetNotify`, and the `Incoming` emits in `process_inner` and `receive_attachment`
- `crates/client/tests/notifications.rs`
- `app/src-tauri/src/lib.rs`: `alert`, `notify_settings`, `set_notify`, `set_background`, and the notify callback
- `app/src-tauri/src/native.rs`
- `app/android/VeilNativePlugin.kt` (`VeilNotify`, `VeilService`, `notifyMessage`, the `resumed` flag)
- `app/android/harden.py`
- the permission allowlist in `.github/workflows/release.yml`
- the notification group in `Settings.tsx`, and `App.tsx`

I also read the relay's `Authenticate`, `subscribe` and `notify`, the client's `Relay::connect` reader task, and the Tauri 2.12.4 Android `Plugin` lifecycle hooks.

**Verdict: PASS WITH CONDITIONS.** 0 Critical, 0 High, 0 Medium, 4 Low, 3 Info. The core security properties hold (details under "What is good"):
- No name, contact-derived text or content reaches any notification or log.
- The locked-state key is dropped and zeroized on every path.
- The watcher cannot fetch or acknowledge.
- A watcher and an unlocked session are never live at once.

The conditions:
- The Kotlin is compiled only by the release workflow and has not run on a device. Before release, check on a device the notification text, its lock-screen appearance, the denied-permission behaviour and the background service.
- Fix M4-1 to M4-3, which are behaviour and UX problems on Android.

**Commands run:** the same runs as Part A, at HEAD (which contains eaacb66). `notifications` 3 passed (`unlocked_incoming_names_the_conversation_only`, `locked_veil_hears_that_something_arrived`, `notifications_off_means_nothing_while_locked`). Workspace and `app/src-tauri` clippy clean, typecheck and lint clean. Kotlin was reviewed by reading only.

### Checks asked for

- **Content in notifications or logs: none.**
  - The only data that crosses into Kotlin is `NotifyArg { certain: bool }` (`native.rs`).
  - The texts are constants: "Veil" / "New message" / "You may have new messages", and for the service "Connected, to tell you when something arrives".
  - `alert(&handle, contact.is_some())` passes a boolean. The contact id goes only to the webview's `veil://changed` event, as before, and `App.tsx` ignores `incoming`.
  - No `tracing` call, `Log.*` or `println` was added in watcher.rs, lib.rs or the plugin.
- **Key dropped and zeroized on every path: yes.**
  - `Watcher` owns an `ed25519_dalek::SigningKey`; `ed25519-dalek` 3.0.0 has `zeroize` in its default features, so it zeroizes on drop.
  - Unlock (password or biometric): `open_session` sets `self.watcher = None` first.
  - Reset: `lock_now(); self.watcher = None`.
  - Purge PIN: `lock_now(); self.watcher = None; wipe()`.
  - Auto-lock and manual lock go through `lock_now`, which builds the watcher only if notifications are on.
  - Failed unlock or `RetryLater`: the watcher is kept. That is correct, as Veil is still locked.
  - Process exit drops the actor.
  - The clone handed to the connect task is dropped when the task ends or is aborted; `Watcher::drop` aborts it.
  - `pin` and `mailbox` (`[u8; 32]`) and `relay_addr` are not zeroized. They are not secrets, and ADR-0016 lists them.
- **Watcher changes server state: only benignly.**
  - It sends `Challenge` and `Authenticate`, then only reads pushes. It never sends `Fetch` or `Ack`.
  - `notifications::locked_veil_hears_that_something_arrived` shows the messages are all there after unlock.
  - The relay's `Authenticate` does `touch_mailbox`, which extends the mailbox's idle expiry, and subscribes the connection. Both are harmless.
- **Watcher and session both live: no.** The watcher is created only inside `lock_now` from the session being dropped, and removed before a new session is built. The dropped `Relay` closes its socket, because its reader task ends when `out_tx` drops.
- **Panic paths: none.**
  - Untrusted pushes are only counted, and rate-limited to one notice a minute.
  - `Instant` arithmetic uses `checked_add(..).unwrap_or_else(Instant::now)`.
  - `spawn_local` runs inside the actor's `LocalSet` (`service.rs:447`).
  - A completed `JoinHandle` cannot be polled twice: its `Ready` wins the `select!` round and `connecting` is cleared.
- **Android:**
  - `VeilService` is `exported="false"`.
  - The PendingIntent is `FLAG_IMMUTABLE | FLAG_UPDATE_CURRENT` on the explicit launch intent.
  - The service type is `remoteMessaging`, with `FOREGROUND_SERVICE` and `FOREGROUND_SERVICE_REMOTE_MESSAGING` declared, and API 34+ calls `startForeground` with the matching type.
  - Channels: Messages at `IMPORTANCE_DEFAULT`, Connection at `IMPORTANCE_MIN` with no badge.
  - With POST_NOTIFICATIONS denied, `allowed()` is false and nothing is posted; the service still runs with a hidden notification.
  - The allowlist names exactly the three new permissions.

### Findings

**M4-1 Low [MEDIUM]: the background-connection notification can claim "Connected" when nothing is connected**
`app/android/VeilNativePlugin.kt:125` (`START_STICKY`), and the `VeilService` class.

The Rust core (the client actor and watcher) runs only once the Tauri activity has started. If Android kills the process and later restarts the sticky service on its own, only `VeilService` runs. ADR-0016 also says "After a restart nothing is in memory".

Failure scenario: after a low-memory kill, the ongoing notification "Connected, to tell you when something arrives" is back, but no relay connection or watcher exists. The user trusts that they will be told about messages, and they will not be. The same can apply after the user swipes Veil away, depending on how wry tears down.

Fix: return `START_NOT_STICKY`, so the service lives only while the app process that started it lives. Or reword the text so it promises nothing ("Veil is running in the background"). Have the plugin stop the service in `onDestroy` when the activity finishes.

**M4-2 Low [HIGH]: turning notifications off leaves the background service running**
`app/src/screens/Settings.tsx:314`, `app/src-tauri/src/lib.rs:575-581`.

Turning "Message notifications" off only disables the background toggle. `set_notify(false)` does not stop `VeilService`.

Failure scenario: the user turns notifications off. Veil keeps a foreground service, an ongoing notification and the battery cost. While unlocked it also keeps a relay connection, for no benefit.

Fix: in `set_notify`, when `!enabled`, also call `native::set_background(&app, false).await` (ignoring `Unavailable` on desktop). Or reset the stored `background` preference in Kotlin.

**M4-3 Low [HIGH]: notifications are on by default but the permission is never asked for, and "Allow notifications" can do nothing**
`lib.rs:575-581`, `VeilNativePlugin.kt:202`.

On Android 13+, notifications default to on, but `request_notifications` runs only from `set_notify(true)`. A new user who never opens Settings gets no notifications and sees no warning. ADR-0016 says "Android 13+ asks for the notification permission when notifications are turned on", which is not true for the default. Also, after the user denies twice, `requestPermissions` shows nothing, so the banner's "Allow notifications" button silently does nothing.

Fix:
- Ask once after setup or the first unlock if `enabled && !systemAllowed`.
- In `requestNotifications`, when `!shouldShowRequestPermissionRationale` and the permission was already asked (keep a pref), open `Settings.ACTION_APP_NOTIFICATION_SETTINGS` with `EXTRA_APP_PACKAGE`.

**M4-4 Low [HIGH]: no test that the locked-state watcher is gone after unlock, reset or purge**
`crates/client/tests/notifications.rs`.

The tests cover the locked notice and notifications off. Nothing checks that the watcher stops after the paths INV-REST-4 and ADR-0016 name. Deleting `self.watcher = None` from `open_session`, Reset or Purge would leave the suite green. That would leave a live signing key and connection, and "may have" notices after unlock or after a purge.

Fix: add a `#[cfg(feature = "test-hooks")] watcher_live() -> bool` hook. Assert it is false after unlock, after `reset`, after a purge-PIN unlock, and with notifications off. Also assert that no `Incoming(None)` arrives after unlock while the contact keeps sending.

**M4-5 Info: lock-screen visibility is PUBLIC**
`VeilNativePlugin.kt:83` and `:183`.

The notification carries no content, so this complies with rule 6 and matches ADR-0016 ("the same on the lock screen"). It does show anyone holding the locked phone that Veil is installed and got something. For at-risk users, consider a setting for `VISIBILITY_SECRET` (and the channel's `lockscreenVisibility`).

**M4-6 Info: `Incoming` fires before the transaction commits**
`Incoming` is emitted inside `process`'s transaction, before the commit (`service.rs` text branch, `attachments.rs:676`). A later failure that rolls back yields a notification for a message that is not stored. This is harmless, and `Messages` already behaved this way. Separately, `onPause` also fires behind Veil's own system dialogs (biometric prompt, save picker, permission request), so a "New message" can be posted while the user is in Veil.

**M4-7 Info: costs ADR-0016 does not list**
- While locked with notifications on, the relay sees an authenticated connection and keeps the mailbox alive (`touch_mailbox`). Before, a locked device was offline to the relay.
- After a Purge PIN, the decoy state never shows "may have new messages", whereas a real locked vault with notifications on does. An observer who knew the earlier behaviour could tell the two apart.

Add both to ADR-0016's costs.

### What is good
- **The design keeps the locked state minimal.** Only the relay sign-in is kept (no message keys, no database). The watcher never fetches or acknowledges, notices are rate-limited to one a minute, and the connect runs in a background task that the lock and the actor never wait on. The trade-off is written down in ADR-0016 and INV-REST-4.
- **Key lifetime is handled at every state change.** Unlock, Reset, Purge and exit all drop it, and the watcher is never built while unlocked.
- **The notification texts are fixed in Kotlin**, and the Rust→Kotlin interface carries only a boolean. That makes INV-REST-5 easy to argue.
- **Android hygiene is right:** the service is not exported, the PendingIntent is immutable, the foreground-service type and permission are correct for API 34+, a revoked permission is caught as a `SecurityException`, the notification is posted only when not resumed and cleared on resume, and the release allowlist is updated in the same change.
- **The tests cover the core cases:** typing and own sends do not notify, the locked notice carries no contact and is rate-limited, nothing is acknowledged while locked, and with notifications off nothing happens.

### Action options
Recommended: **B. Fix blocking only**: M4-1 to M4-3, plus M4-4 as the test for the key-lifetime claim. Then do the on-device check of the Kotlin before tagging.

## Preview.6 changes review, round 1

**Scope:** commit `4f9b90c` ("Add swipe to reply, three reactions, key-change merge, Erase everything"), 20 files, +999/−195. Covers ADR-0017 and the INV-ID-2, INV-REST-6 and INV-MSG-8 rows. I read the whole diff plus the code it relies on: `atomically`, `forget_contact`, `queue_token_removal`/`flush_token_removals`, `verify_current`, `wipe`, `lock_now`/`interruptible`, the Purge PIN unlock path, `retry_failed`/`retry_attachment`/`restart_upload`, the intro clash check, `useDialogKeys`, and the `.reaction` rules in `base.css`. I edited no files.

**Verdict: FAIL.** There is one High (P6-1). Under the CLAUDE.md gate every Critical/High must be fixed and re-reviewed. The other findings are Medium or below.

### Commands run

| Command | Result |
|---|---|
| `cargo test -p veil-client --locked` | **pass**: unit 15, attachments 10, contacts_and_privacy 9, lock_and_setup 3, messaging 7, notifications 4, pair_and_message 2, unlock_options 6; 0 failed, no flaky reruns needed |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | **pass** (exit 0, no warnings) |
| `(cd app/src-tauri && cargo clippy --all-targets --locked -- -D warnings)` | **pass** |
| `pnpm -C app typecheck` | **pass** (`tsc --noEmit`) |
| `pnpm -C app lint` | **pass** ("14 files clean") |
| `pnpm -C app test` | **not run**: `app/package.json` has no `test` script (`ERR_PNPM_RECURSIVE_EXEC_FIRST_FAIL`). This was already the case before this commit, but CLAUDE.md's command table lists it |

### Findings

**P6-1 — High — [HIGH confidence] "It's them" merges every contact with the same name, not just "the earlier conversation"**
`crates/client/src/service.rs:3626-3639` (`accept_key_change`); the confirmation text is in `app/src/screens/Chats.tsx:81`.
- **What happens:** `olds` is every other contact whose *current* `name_key` equals the warned contact's. That includes contacts the user earlier chose to "Keep apart", blocked contacts, verified contacts and other warned impostors. Every one of them has its history moved into the accepted contact and is then deleted. The confirmation says "Move your earlier conversation with {name} here and remove the old contact?" (one contact) and never says which contact or how many.
- **Scenario A (impostor):**
  1. Alice has Bob.
  2. An attacker pairs as "Bob" and gets the warning. Alice taps "Keep apart"; the attacker's messages stay in their own chat.
  3. Bob gets a new phone and pairs, and is warned. Alice verifies and taps "It's them".
  4. The attacker's messages (`mine = 0`) now sit in the verified Bob conversation, shown as Bob's earlier messages, and the attacker contact is gone. Text an impostor wrote ends up attributed to a verified identity. That goes against what INV-ID-2 and ADR-0017 ("nothing merges without the user") mean: the user agreed to one merge, not this one.
- **Scenario B (two real people):** two different "Alex" contacts that were kept apart. Accepting a key change for one irreversibly deletes the other (session forgotten, token withdrawn) and mixes the two histories.
- **Renamed contacts:** because matching uses the names as they are at accept time, a user who renamed either contact gets "success" with nothing moved, and the warning is cleared.
- **Tests:** none cover more than one match.
- **Fix:**
  - At warning time, record which contact clashed (e.g. a `key_warning_of INTEGER REFERENCES contacts(id)` column set in the intro path at `service.rs:2953-2966`). Alternatively, have the UI pass it in: `accept_key_change(new_id, old_id)`.
  - Merge exactly that one contact. Refuse (`BadInput`) if it no longer exists, is the same id, or no longer matches.
  - Show the old contact in the confirmation (name, verified/blocked state, last message time).
  - Add a test with two same-name contacts (one kept apart) and check only the chosen one moves.

**P6-2 — Medium — [HIGH confidence] A wrong PIN in "Erase everything" stops all relay traffic until the next lock**
`crates/client/src/service.rs:573-575` (`Client::purge_all`) and `:1435-1447` (`Cmd::PurgeAll`).
- **What happens:** `purge_all` sets `interrupt.pending = true` before the secret is checked. Only `lock_now` clears that flag (`:1047`). On `WrongPassphrase` or `RetryLater` the session stays unlocked but the flag stays set.
- **Effect:** from then on, `interruptible` (`:1062`) returns `Err(Locked)` for every relay call: `connect`, `sync`, sends, `flush_token_removals`. `retry_failed` also stops early (`:2797`, `:2804`).
- **Scenario:** the user mistypes their PIN in step 3, cancels, and keeps chatting. Nothing is received and sends fail or queue. This lasts until a manual lock or 5 minutes without input; staying active postpones auto-lock, so it can last indefinitely.
- **Tests:** `erase_everything_from_settings` checks only state and files after the wrong PIN, not that messaging still works.
- **Fix:** in the `Err(e)` arm of `Cmd::PurgeAll`, add `self.interrupt.pending.store(false, Ordering::SeqCst);`. Extend the test so a message is sent and received after the wrong PIN.

**P6-3 — Medium — [HIGH confidence on the cascade; MEDIUM on how often users hit it] The new reaction hit area is displaced over the bubble**
`app/src/styles/app.css:124`.
- **What happens:** the new rule `.reaction::after { content: ""; position: absolute; inset: -9px -4px; }` has the same specificity as the existing `base.css:723` rule and loads later. The base rule's `width: max(100%, 44px)`, `height: 44px` and `transform: translate(-50%, -50%)` still apply.
  - With `top`, `height` and `bottom` all set, `bottom` is ignored; likewise `right`.
  - The box then starts at `top: -9px`, `left: -4px` and is shifted up 22px and left by half its width.
  - Net result: the hit area runs from about 31px above the chip to 13px below its top. That covers roughly the bottom 25px of the bubble (the `.reactions` row has `z-index: 1` and `margin-top: -6px`).
- **Scenario:** on a message that has reactions, a tap on the lower part of the bubble (last text line, time, or voice-note/file controls near the bottom) hits a chip. That sends a reaction to the contact with no confirmation, or removes one. A hold or swipe started there never reaches the bubble.
- **Fix:** delete `app.css:124`; `base.css:723` already gives a centred 44×44 area. If the override is kept, reset it fully: `inset: -9px -4px; width: auto; height: auto; transform: none;`. Note that `-4px` on a 34px chip gives only 42px width.

**P6-4 — Low — [HIGH confidence] Erase skips the Android Keystore key and webview clearing if `wipe()` reports an error**
`app/src-tauri/src/lib.rs:235-239`.
- **What happens:** `c.purge_all(current).await.map_err(err)?` returns before `finish_purge`. In the actor the secret has already been verified, the session locked and the files partly deleted. Only `wipe()` failed, for example a file held by a scanner or backup tool on Windows, or a slow keystore.
- **Scenario:** the hardware key and webview storage remain, while the user was told this does what the Purge PIN does. The Purge PIN path always runs `finish_purge`, because it ignores `wipe()`'s result.
- **Fix:** distinguish the two error kinds, e.g.:
  ```rust
  match c.purge_all(current).await {
      Ok(()) => { finish_purge(&app).await; Ok(()) }
      Err(e @ (ClientError::WrongPassphrase | ClientError::RetryLater | ClientError::Locked)) => Err(err(e)),
      Err(e) => { finish_purge(&app).await; Err(err(e)) }
  }
  ```
  Or have the client return a distinct "wiped with errors" result.

**P6-5 — Low — [MEDIUM confidence] The preview.5 "remove clears all" fallback also fires for preview.6 peers**
`crates/client/src/service.rs:3097-3106`.
- **What happens:** any removal naming an emoji the receiver does not have deletes all of that contact's reactions on the message.
- **Scenario:** a preview.6 peer has A, B, C.
  1. The "remove A" envelope fails transiently and stays queued for retry.
  2. "Add D" goes out. The receiver keeps the newest three: B, C, D (A is dropped).
  3. The retried "remove A" arrives later (libsignal decrypts out-of-order messages). The receiver has no A, so B, C and D are all cleared, although the peer still shows them.
- **Fix:** apply the fallback only to preview.5's placeholder, which was `"x"` (old `react`: `unwrap_or_else(|| "x".into())`): `if gone == 0 && r.emoji == "x" { … }`. Add a case to `replies_reactions_edits_and_deletes`.

**P6-6 — Low — [HIGH confidence] Touch-only users have no visible non-gesture way to open a message's actions**
`app/src/styles/app.css:64-66` and `app/src/screens/Chats.tsx` (`MessageRow`).
- **What happens:** a tap on a text bubble no longer opens the actions (before this commit it was `role="button"`). The "⋯" button has `opacity: 0` unless hovered (only with `hover: hover`) or focused.
- **Scenario:** on a phone, a sighted user who cannot hold still for 450 ms within 10 px (tremor, motor impairment) has no visible way to react, reply, edit or delete. The invisible 44px button still takes taps, so a tap beside a bubble opens the dialog unexpectedly. Keyboard and screen-reader users are fine.
- **Fix:** show "⋯" on coarse pointers, e.g. `@media (hover: none) { .msg-more { opacity: 0.6; } }`. Alternatively, make a single tap on a text bubble open the actions again (the hold then only adds the vibration).

**P6-7 — Low — [HIGH confidence] The "nothing sealed to the old key is sent on" claim has no test (CLAUDE.md rule 9)**
`docs/INVARIANTS.md` (INV-ID-2 row) and `crates/client/tests/contacts_and_privacy.rs` (`accepting_a_key_change_moves_the_old_conversation`).
- **What's missing:** the row states that hidden queued rows are dropped and that unsent messages and uploads stay "not sent". The cited test only sends successfully delivered messages.
- **Code reading:** the code looks right. Control and mailbox rows are deleted. Unsent rows get `status='failed', envelope=NULL`, and `retry_failed` needs `envelope IS NOT NULL`. Uploads become `failed` with their chunks dropped, and only the user's own Retry re-encrypts them under a fresh key for the new contact.
- **Fix:** add a test that cuts Alice off from the relay, queues a text, a reaction and an upload to the old contact, accepts the key change, reconnects, and then checks that:
  - `hidden_rows(new) == 0`;
  - the text is `failed`;
  - Bob2 receives nothing from those rows.

  Also add the multi-match test from P6-1.

**P6-8 — Low — [HIGH confidence] The quote button's `aria-label` hides the quoted text from screen readers**
`app/src/screens/Chats.tsx:389-392`.
- **What happens:** `aria-label="Go to the quoted message from Bob"` replaces the button's accessible name, so the quoted text inside is not read. Before this commit the quote was a plain span and was read.
- **Fix:** drop the `aria-label`. Add a visually hidden prefix inside the button instead, e.g. `<span className="sr-only">Quoted message, go to original: </span>`, so the name and excerpt stay readable.

**P6-9 — Info**
- **Merged history:** after a merge, the new key holder can edit or delete (within 48 h) and react to messages the old key sent, because they are now its own conversation. This follows from the user's choice; it is worth a line in ADR-0017.
- **preview.5 interop:** a preview.5 receiver keeps only one reaction from a preview.6 sender, and any single removal clears all of them there. ADR-0017 describes only the other direction.
- **`user-select: none`:** this is a UX choice, not a clipboard guarantee. Rule 6 covers Veil writing to the clipboard. The same plaintext can still be selected in the action dialog's `.msg-preview` and the reply bar, so the ADR's "there is no copy" is broader than what the code does.
- **Focus after a hold:** when the dialog was opened by a hold, the opener is the non-focusable bubble, so focus does not return anywhere useful on close. Keyboard users open it from "⋯", so the impact is small.
- **Unsent messages after a merge:** they stay `failed` with no way to resend them, because there is no envelope and no text retry. This matches "stay as not sent" but could be stated in the UI.

### Checked and found sound
- **No auto-merge (INV-ID-2):** `accept_key_change` refuses without `key_warning` (tested). It runs only from an explicit IPC call behind a confirmation step, and neither verifying nor doing nothing merges.
- **"Verifying no longer clears the warning" leaves no dead end:** "Keep apart" and "It's them" stay available while the contact is verified.
- **Atomicity of the merge:** there is no relay I/O inside `atomically`. `forget_contact` writes through the same SQLite savepoint, as `delete_contact` already does, and token withdrawal happens after commit. Reactions and attachments follow the moved messages by message id, unread counts are added, and `typing_sent` is cleaned up.
- **Erase everything:**
  - goes through `verify_current`: attempt counting, retry delay, and no wipe on a wrong secret;
  - on success runs the same `lock_now` and `wipe()` as the Purge PIN, and clears the watcher and decoy, so the state becomes `New` and the welcome screen shows;
  - the UI's three steps (tick, type ERASE, PIN or password) make a slip unlikely.
- **Reactions against a hostile contact:**
  - incoming emoji are validated by the core (≤ 8 characters, ≤ 32 bytes, no control or bidi characters);
  - targets are limited to that conversation's undeleted text and attachment messages;
  - the contact's rows are trimmed to `MAX_REACTIONS` after every insert, so they cannot grow without bound;
  - nothing in the path can panic.
  - Our own side checks the cap before queueing anything.
- **Migration 4:** copies the version 3 rows. Version 3's key `(message, mine)` means there are no duplicates. The rename keeps `ON DELETE CASCADE`, and the migration runs in one transaction with `user_version`. `migrates_a_version_3_database` covers data kept, a second reaction fitting, and the cascade.
- **Gestures:**
  - `touch-action: pan-y` keeps vertical scrolling native, and pointer cancel clears the hold timer.
  - Pointer capture is taken only once a swipe is recognised.
  - The click after a hold is swallowed; the flag is reset on the next pointerdown.
  - Right-click and Android `contextmenu` do not open the actions twice.
  - Swiping is turned off for blocked contacts, deleted messages and messages without actions.
- **CSS:** only design tokens, no raw colours. The new transitions are transform and opacity only, use `--dur-*` (zeroed under `prefers-reduced-motion` and `data-motion="reduced"`), and are covered by the global reduced-motion overrides. `design/proto/base.css` mirrors `base.css`.
- **Custom emoji input:** labelled, `aria-invalid`/`aria-describedby` wired, single grapheme checked with `Intl.Segmenter`, `maxLength` set, server-side validation is still the authority.
- **The rest:** IPC stays in `ipc.ts`, the new commands are in the shell's handler list, and the docs (ADR-0017, the INVARIANTS rows, DESIGN.md) were updated with the change.

## Preview.6 changes review, round 2

**Scope:** fix commit `1b4a5cd` ("Fix preview.6 review round 1 findings"), 13 files, +412/−44. I checked it against round 1's findings P6-1 to P6-9. Besides the diff I read the code it relies on:
- `upsert_contact`, the `Opened::NewContact` intro path, and core `Account::open`, to see when an intro can come from a known address;
- `contact_view` / `contacts`, `accept_key_change` / `warned_about`, `dismiss_key_warning`;
- `verify_current`, `wipe`, `lock_now`, `interruptible`, the `ask!` macro, `retry_failed` / `deliver` and `tick` / `connect`;
- `finish_purge`, the shell `purge_all`, Settings' `EraseForm`, and App's handling of the `locked` event;
- the `.reaction` / `.msg-more` / `.sr-only` CSS;
- the contacts schema and migrations 1 to 4;
- the preview.5 `react` code, to confirm its placeholder (`git show 4f9b90c^`).

I edited no files.

**Verdict: PASS.** All nine round-1 findings are fixed, including the High (P6-1). The fix code adds no Critical, High or Medium findings. The new findings below are Low, Nit or Info and can be handled as follow-ups.

### Commands run

| Command | Result |
|---|---|
| `cargo test -p veil-client --locked` | **pass**: unit 15, attachments 10, contacts_and_privacy 10 (one more than round 1: `a_merge_sends_nothing_sealed_to_the_old_key`), lock_and_setup 3, messaging 7, notifications 4, pair_and_message 2, unlock_options 6, doc 0; 0 failed |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | **pass** (exit 0) |
| `(cd app/src-tauri && cargo clippy --all-targets --locked -- -D warnings)` | **pass** (exit 0) |
| `pnpm -C app typecheck` | **pass** (`tsc --noEmit`, exit 0) |
| `pnpm -C app lint` | **pass** ("lint: 14 files clean") |

I ran no mutation checks: the brief did not allow edits. The commit message says mutation checks were done for P6-2 and P6-5.

### Round-1 findings

| ID | Sev. (r1) | Status | Evidence |
|---|---|---|---|
| P6-1 | High | **Fixed** | See the analysis below. |
| P6-2 | Medium | **Fixed** | `service.rs:1460-1464`: the `Err(e)` arm of `Cmd::PurgeAll` resets `interrupt.pending`. This covers every failure there: `WrongPassphrase`, `RetryLater`, `Locked`, and header or keystore load errors. `unlock_options.rs:321` now calls `create_invite()` (relay I/O) after the wrong PIN. One narrow race remains (P6R2-6, Info). |
| P6-3 | Medium | **Fixed** | `app.css` no longer has a `.reaction::after` override. `base.css:723` gives the centred `max(100%, var(--tap-min))` × `var(--tap-min)` area. |
| P6-4 | Low | **Fixed** | Details below. One follow-up on what the user sees (P6R2-1). |
| P6-5 | Low | **Fixed** | `service.rs:3157`: `gone == 0 && r.emoji == "x"`. The preview.5 placeholder was indeed `"x"` (`4f9b90c^:service.rs:2442`). `messaging.rs:145-154` sends a removal of a dropped emoji (🍕) and checks the three reactions survive, then checks that `"x"` still clears them. |
| P6-6 | Low | **Fixed** | `app.css:69`: `@media (hover: none) { .msg-more { opacity: 0.55; } }`. `.msg:focus-within .msg-more` has higher specificity, so focus still gives full opacity. |
| P6-7 | Low | **Fixed (with a weakness)** | `contacts_and_privacy.rs:117-190`. It queues a text, a reaction and a file while offline, merges, and checks `hidden_rows == 0`, text `failed`, file `failed`. The status checks carry the proof; the "neither Bob receives it" checks cannot fail (P6R2-2). |
| P6-8 | Low | **Fixed** | `Chats.tsx:~400`: the `aria-label` is gone. An `sr-only` prefix ("Quoted message, go to the original: ") is followed by the author and the excerpt, so the button's name includes the quoted text. |
| P6-9 | Info | **Mostly addressed** | ADR-0017 now covers: what the new key holder can do with merged history, preview.5 interop in both directions, and corrected `user-select` wording ("Veil itself never writes to the clipboard"). Not addressed, acceptable as Info: focus return after a hold-opened dialog, and a UI hint that unsent messages after a merge cannot be resent. |

#### P6-1 in detail

**Can the merge hit the wrong contact through id reuse?** No [HIGH confidence]. The rows behind each step:

1. `contacts.id` is `INTEGER PRIMARY KEY` without `AUTOINCREMENT` (`db.rs:17-18`). SQLite therefore gives a new row `max(rowid)+1`, so a deleted id comes back only if it was the largest id in the table.
2. The warned contact W always has a larger id than its recorded contact O:
   - `Opened::NewContact` is produced only for an address the core does not know (`core/src/account.rs:657-704`; known keys yield `Opened::Message`).
   - `forget_contact` and the contacts row are deleted together, so in practice the `upsert_contact` `ON CONFLICT` branch never runs for an intro. Every warned contact is a new, maximal row.
   - The clash candidates are only pre-existing rows, ordered by id, so O < W.
3. While W exists, O can never become the maximum again. After O is deleted, new rows get ids above W, so the recorded id is never reused.
4. If O is gone, `warned_about` (`service.rs:3746-3774`) returns `None`. It does not fall back to name matching. `accept_key_change` then refuses with `BadInput`, and the UI shows "Veil cannot tell …".

**Can it hit the warned contact itself?** No. The intro excludes it (`address != ?1`), and `warned_about` checks `id != ?2`.

**Only one contact merged?** Yes. `accept_key_change` (`service.rs:3666-3739`) builds `olds` from that single id. The new assertions in `accepting_a_key_change_moves_the_old_conversation` show it:
- a same-name contact the user kept apart survives;
- its message stays in its own chat;
- `previous.id == a_bob.id`.

**Can the confirmation name a contact the user cannot see?** No. `contacts()` lists every row with no filter, and `PreviousView` is read live from the same row the backend merges. The confirmation (`Chats.tsx:82-89`) shows its current name, verified/blocked state and last-message time. "Yes, it's them" is only rendered when `previous` is non-null.

**Legacy warnings (preview.5, `key_warning_of IS NULL`):** they merge only when exactly one other contact has the same name; with two or more, nothing is chosen. Because migration 4 is unreleased, the new column is safe to add there. The fallback has no test (P6R2-3).

#### P6-4 in detail

**Error paths before the secret is verified:** all of them return `Err` with nothing touched, and the shell's `?` (`lib.rs:237`) skips `finish_purge`. These paths are:
- `self.s()?` (`Locked`);
- `wait_secs > 0` (`RetryLater`);
- `header()?`;
- `keystore::load(..)?`;
- `record_failure(..)?`;
- `WrongPassphrase`.

**After verification:** the arm runs `lock_now()`, clears `watcher` and `decoy`, then `Ok(self.wipe().is_ok())`. There is no way to return `Err` after that point.

**Remaining `Err` sources:** only `ask!`'s channel errors. These happen if the actor thread is gone before the command is received, or dies mid-command before replying. Neither is reachable without a panic in the actor; I am noting it, not raising a finding.

### New findings

**P6R2-1 — Low — [HIGH confidence] The "some file could not be deleted" result never reaches the user**
`app/src-tauri/src/lib.rs:240-244`; `app/src/screens/Settings.tsx:139-145`; `app/src/App.tsx:73-83`.
- **What happens:** on `Ok(false)` the shell runs `finish_purge` and returns `Err(Storage)`. But `lock_now()` has already emitted `locked`, so App drops back to state routing and `EraseForm` is unmounted. `setError("Could not erase")` lands on an unmounted component.
- **Effect:** the user sees the welcome screen, or the lock screen if `veil.header` survived, with no explanation. If `keystore::remove` was the step that failed, the PIN may still open the vault, so the user may believe the data is gone when it is not.
- **Fix:** keep the success path as is. For `false`, have the shell emit a one-off event or return a distinct value, e.g. `Res<bool>`. Show the message on the screen the user lands on, e.g. "Some of Veil's files could not be deleted. Erase again, or remove the app's data in system settings." On the TypeScript side: `const allGone = await ipc.purgeAll(current); onErased(allGone);`.

**P6R2-2 — Low — [HIGH confidence] The "neither Bob receives them" checks in P6-7's test cannot fail**
`crates/client/tests/contacts_and_privacy.rs:159-182`; `docs/INVARIANTS.md` (INV-ID-2 row).
- **Why:** `deliver` (`service.rs:2765-2798`) deposits to the mailbox and token of the contact the row belongs to *now*. After the merge that is Bob2. A row that kept its old-key envelope would therefore go into Bob2's mailbox. Bob2 cannot decrypt an envelope sealed to the old session and drops it, and old Bob never sees it.
- **Effect:** `!got.contains("queued for the old key")`, `bob2 … attachment.is_none()` and the old-Bob text check pass whether or not the fix is present.
- **What does carry the proof:**
  - `hidden_rows == 0`;
  - `q.status == "failed"`: if the envelope were kept, `connect` runs `retry_failed`, the row would be deposited and become `sent`, and this check would fail;
  - the attachment state `failed`.
  The claim holds, but the INVARIANTS row credits the test with something it does not observe.
- **Fix:** either reword the row to "the hidden row is dropped; the text and file stay `failed`, so nothing is deposited". Or make the test observe it: add a deposit counter to the test relay or `Proxy`, take it before `hop.restore()`, and after the "after the merge" round trip assert exactly one deposit to Bob2's mailbox, e.g. `assert_eq!(r.deposits_to(bob2_mailbox) - before, 1)`. A test-only `envelope IS NULL` probe would also do.

**P6R2-3 — Low — [HIGH confidence] `warned_about`'s other branches have no test**
`crates/client/src/service.rs:3746-3774`.
- **Covered today:** only the recorded-id path.
- **Not covered:**
  - the recorded contact is gone (`previous == None`, `accept_key_change` → `BadInput`, nothing deleted);
  - the legacy `NULL` fallback with exactly one same-name contact (merges it);
  - the legacy fallback with two or more (refuses).

  These are the guards that keep P6-1 from coming back for upgraded databases (CLAUDE.md rule 9).
- **Fix:** extend `db.rs::migrates_a_version_3_database`, or add a unit test on a v3 database:
  1. Insert three contacts named "Bob" with `key_warning = 1` on the last.
  2. Migrate, then assert `warned_about(..) == None`.
  3. Delete one, then assert it is `Some(the other)`.

  For the gone case, add an integration step: delete `a_bob` before accepting, then assert `BadInput` and that `a_other` is still there.

**P6R2-4 — Nit — [MEDIUM confidence] `PreviousView.last_at_ms` counts deleted and expired messages**
`crates/client/src/service.rs:1914-1916`.
- **What happens:** `MAX(at_ms)` has no `deleted = 0` filter and no expiry filter, while the contact's own `last` query (`:1898-1906`) has both. A contact whose last message was deleted for everyone, or has expired, shows "last message <time>" for something no longer visible.
- **Fix:** `(SELECT MAX(at_ms) FROM messages WHERE contact = ?1 AND kind IN ('text','attachment') AND deleted = 0 AND (expires_at_ms IS NULL OR expires_at_ms > ?2))`, with `params![old, now_ms()]`.

**P6R2-5 — Nit — [HIGH confidence] Focus is lost when "It's them…" opens the "cannot tell" variant**
`app/src/screens/Chats.tsx:82-89`.
- **What happens:** the `autoFocus` is on "Yes, it's them", which is not rendered when `prev` is null. The "It's them…" button unmounts, so focus falls to `<body>`, and keyboard and screen-reader users lose their place. The verified-state text above also says "their earlier conversation can move here", which is not true in this case.
- **Fix:** put `autoFocus={!prev}` on the "Not now" button. Optionally, when `prev` is null, skip the confirm step: replace "It's them…" with the "cannot tell" text directly.

**P6R2-6 — Info**
- **Interrupt race:** the `pending = false` reset in the `PurgeAll` error arm can clear a lock request that `Client::lock()` set while `PurgeAll` was queued.
  - The `Cmd::Lock` itself still runs.
  - A relay call queued between the two commands would not be interrupted: a send would block the lock only until the relay call finishes or the auto-lock timer fires. This narrowly weakens P4-1's "the relay cannot delay a lock".
  - A generation counter, or not setting `pending` before verification in `purge_all`, would close it. The wipe path does not need an in-flight interrupt, because the actor is not mid-I/O while it handles the command.
- **`key_warning_of` is never cleared:** neither "Keep apart" nor a merge resets it. This is harmless, because only the intro sets `key_warning = 1` and it rewrites both columns. Setting it to `NULL` on dismiss and accept would keep the data tidy.
- **Two warnings about the same contact:** two warned contacts can point at one old contact (e.g. Bob2 and Bob3 both warned about Bob). Accepting one leaves the other's pointer dangling, so it can only "Keep apart". This is conservative and acceptable, but the "cannot tell" text could say the earlier contact was already merged.
- **Earlier "Keep apart" choice is not shown:** the confirmation does not say the user once chose "Keep apart" for the previous contact. If the real Bob was deleted earlier, the oldest same-name contact, and so the merge target, may be an impostor the user kept apart. The confirmation names it with "not verified" and its last-message time, which is reasonable. Recording "kept apart" and saying so in the confirmation would make it clearer.
- **No expected-id check in the merge:** `acceptKeyChange(contact.id)` does not pass the `prev.id` the user saw. With the recorded path the target cannot change. In the legacy path the target could change only if contacts were renamed, deleted or added between render and tap. Passing `prev.id` and refusing on a mismatch would be cheap defence in depth.

### What is good
- **P6-1 is fixed at the root:** the warning records its target when it is raised, the merge touches exactly that row, and every failure refuses rather than guessing (gone → refuse, ambiguous legacy → refuse). The confirmation shows exactly the row that would be merged, so the dialog and the backend cannot disagree. The new test covers the round-1 scenario directly (a same-name contact kept apart survives with its messages).
- **`purge_all`'s `Result<bool>` contract is clean:** every `Err` comes before verification and nothing has been touched; after verification there is no error, so the shell's `?` only stops on errors where nothing was erased. The Keystore key and webview storage are now cleared exactly when the Purge PIN path would clear them.
- **P6-5 is the minimal correct fix:** it matches the real preview.5 placeholder, and its regression test also checks that the placeholder still clears all of that person's reactions.
- **P6-3 removes the bad override:** the base rule is used instead of a second partial reset.
- **The P6-7 test checks rows, not only messages:** it sets up the queue genuinely offline through the proxy, covers text, reaction and upload, and asserts on persisted state. The reconnect runs `retry_failed`, so a regression in the envelope handling would make it fail.
- **Docs kept in step:** ADR-0017, the INV-ID-2 row and the commit message were updated with the fixes, and the commit body explains each change.
- **All gates are green:** tests, both clippy runs, typecheck and lint.

## Milestone 6 calls review, round 1 (commit bde54b3)

**Verdict: FAIL** (1 High)

Scope: `git diff 62e1bda bde54b3`, 28 files, about 2,750 added lines. No files were modified.

Commands run:
- `cargo test -p veil-core --lib ice`: 15 passed.
- `cargo test -p veil-client --test calls`: 2 passed.
- `cargo test -p veil-client --lib calls`: 3 passed.
- `pnpm -C app typecheck`: 0 errors.

---

### C6-1: High. Hanging up during call setup leaves the microphone and camera on, and can still send the offer or answer
**Where:** `app/src/calls.ts` L231, L244 (`start`), L296, L317 (`accept`), and `end()` L542-548.

**Problem:** After each `await`, `start()` and `accept()` only check `this.current?.id !== id`. `end()` does not clear `current`. It sets `phase: "ended"` and keeps the same `id` for `ENDED_MS` (1.8 s). So a hangup or decline during `ipc.callSetup` or `getUserMedia` passes that check. The code then:
- patches `local` into the ended state;
- creates a new `RTCPeerConnection` and assigns it to `this.pc`;
- negotiates, and sends the offer or answer if gathering finishes within the 1.8 s.

When gathering finishes after `current` has been nulled, the function returns early. Nothing stops the `local` tracks or closes that `pc`, and the next call overwrites `this.pc`.

**Failure scenario:** A user taps "Voice call", sees they picked the wrong contact, and taps End within about a second. Their microphone (and camera for a video call) stays capturing with no call on screen. The Android mic/camera indicator stays on until the app is killed, and a TURN allocation is held open. If the offer went out after the hangup, the contact's phone rings for 45 s for a call that no longer exists: the hangup arrived first and was ignored because no call existed yet. The `accept()` path behaves the same way: the answer is sent after a decline, and the callee's capture leaks.

**Fix:** Check that the call is still live, not just that the id matches, and release everything on bail-out:
```ts
private live(id: string): boolean {
  return this.current?.id === id && this.current.phase !== "ended";
}
// start(), after media():
if (!this.live(id)) { for (const t of local.getTracks()) t.stop(); return; }
// start(), after gathered(pc):
if (!this.live(id)) { if (this.pc === pc) { pc.close(); this.pc = null; } for (const t of local.getTracks()) t.stop(); return; }
// same two checks in accept() with c.id
```
Also make `patch()` a no-op once `phase === "ended"`, except for the patch in `end()` itself.

---

### C6-2: Medium. A call signal that failed to send is retried later, so the contact rings for an abandoned call
**Where:** `crates/client/src/service/calls.rs` L254-262; `service.rs` `retry_failed` (about L2866), `connect()` L1235; `app/src/calls.ts` L247-248.

**Problem:** `call_send` stores the sealed signal as a `control` row with `expires_at_ms = now + 60 s`. When `deliver` fails (relay connection drops, deposit error), the row stays in `failed` status. The UI gets `Unreachable` and calls `end(…, false)`, so no hangup is ever queued. On reconnect, `retry_failed()` delivers every failed row, call signals included, as long as `expire_messages` has not removed it yet. The receiver accepts anything sent less than 90 s ago.

**Failure scenario:** The caller is on a flaky mobile link. The deposit fails and they see "could not start". The link comes back 20 s later, the offer goes out, and the callee rings for 45 s. If they answer, they sit in "Connecting…" because the caller ignores the answer.

**Fix:** Call signals are only useful right now, so do not queue them for retry. In `call_send`, delete the row when delivery fails:
```rust
if self.deliver(row).await { Ok(()) } else {
    let _ = self.s()?.db.conn().execute("DELETE FROM messages WHERE id = ?1 AND kind = 'control'", [row]);
    Err(ClientError::Unreachable)
}
```
Add a client test: offer with the relay down, then reconnect, then the peer receives nothing.

---

### C6-3: Medium. The TURN URL host check can be bypassed, and the docs claim more than it guarantees
**Where:** `crates/client/src/service/calls.rs` L117-126 (`turn_url_ok`); `docs/PROTOCOL.md` §8 (new TURN URLs bullet); `docs/ARCHITECTURE.md` ADR-0018 ("A hostile relay therefore cannot point the webview at hosts on the user's network").

**Problem:** A host that does not parse as a Rust `IpAddr` is treated as a DNS name, and it passes if it contains a dot and uses only `[A-Za-z0-9.-]`. Rust's IPv4 parser is strict, but the resolver WebRTC uses (`getaddrinfo` / `inet_aton`) accepts shorthand:
- `turn:127.1:3478` resolves to 127.0.0.1;
- `turn:10.1` resolves to 10.0.0.1;
- `turn:192.168.1` resolves to 192.168.0.1;
- `turn:0x7f.1` resolves to 127.0.0.1.

All of these pass `turn_url_ok` today. Separately, any public-looking name can have an A record pointing at a private address, which the filter cannot see.

**Failure scenario:** A hostile relay returns `turn:192.168.1:3478?transport=tcp`. The webview opens TCP connections to a LAN host and writes STUN to it. PROTOCOL §8 says this is impossible, which breaks CLAUDE.md rule 9: the security claim needs a test or a correct written argument.

**Fix:**
1. Reject names whose last label is not alphabetic (real TLDs never are):
   ```rust
   && lower.rsplit('.').next().is_some_and(|tld| tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic()))
   ```
   Add `127.1`, `10.1`, `192.168.1` and `0x7f.1` to the test's `bad` list.
2. Reword the ADR and PROTOCOL claim: IP literals are enforced, but names are checked syntactically only. A relay-controlled DNS name can still resolve to a private address. coturn's `denied-peer-ip` does not cover this, because it is the TURN client's own connection. Record this residual risk in `THREAT_MODEL.md`.

---

### C6-4: Medium. The share-quality sheet steals keyboard focus every second
**Where:** `app/src/screens/Call.tsx` L88-95 (`ShareSheet` effect with `[onClose]`), L277 (`onClose={() => setSheet(false)}`), L151-157 (1 s clock).

**Problem:** While the call is active, `CallScreen` re-renders every second for the clock. Each render passes a new inline `onClose`, so the `ShareSheet` effect tears down and runs again. That moves focus back to the checked radio every second.

**Failure scenario:** A keyboard or screen-reader user tabs to "Share screen" or "Close". Within a second focus is pulled back to the radio, so the sheet is effectively unusable without a pointer. The sheet and the call overlay also set `aria-modal` with no focus trap, even though DESIGN.md says dialogs trap focus in the app.

**Fix:**
- Use `const closeSheet = useCallback(() => setSheet(false), [])` in `CallScreen`.
- In `ShareSheet`, split the effect: initial focus with `[]` deps, and keys via the existing `useDialogKeys(box, onClose)` from `ui.tsx`, which also traps Tab.
- Return focus to the Share button when the sheet closes.

---

### C6-5: Low. The 90 s staleness rule has no test and depends on the sender's clock
**Where:** `crates/client/src/service/calls.rs` L279-281.

**Problem:** "A phone that was offline does not ring for an old call" (ADR-0018, PROTOCOL §8) is a stated promise with no test. It also trusts the sender's `sent_at_ms`. A sender whose clock is more than 90 s behind has every call silently dropped: the caller sees "No answer" and the callee gets nothing.

**Fix:** Extract `fn is_stale(now_ms: i64, sent_at_ms: u64) -> bool` and unit-test it at the edges (89 s, 91 s, future, `u64::MAX`). Document the clock-skew limitation in ADR-0018 Costs, or add the 30 s grace on both sides symmetrically.

---

### C6-6: Low. The docs say nothing of a call is written to the database, but undelivered signals are
**Where:** `docs/ARCHITECTURE.md` ADR-0018 "Signals in memory only"; `docs/INVARIANTS.md` INV-NET-3; `calls.rs` L255-257.

**Problem:** Outgoing offers and answers are stored as sealed envelopes in the `messages` table until delivered. An undelivered row survives a lock until the next unlock's `expire_messages`. It is ciphertext inside the encrypted DB, so the risk is small, but the written claim is wrong. The `UFRAG` test only checks state after successful delivery.

**Fix:** The C6-2 fix (delete the row on failure) makes the claim true. Then add an assertion to `a_call_is_signalled_relay_only` that no `kind='control'` row is left after a failed send.

---

### C6-7: Low. Two people calling each other at once both get "Busy"
**Where:** `app/src/calls.ts` L255-258.

**Problem:** Both sides are in `calling` when the other's offer arrives. Each replies `busy`, and both calls end.

**Fix:** Break the tie deterministically. If `c.outgoing && c.phase === "calling" && s.contact === c.contact`, the side with the smaller `callId` drops its own call quietly (close the pc, stop tracks, no busy) and takes the incoming offer. The other side keeps waiting and receives the answer as a hangup or busy for its own id.

---

### C6-8: Low. The Android "Incoming call" notification outlives the call
**Where:** `app/android/VeilNativePlugin.kt` (`notifyMessage` with `CALL_ID`, cancelled only in `onResume`).

**Problem:** After a missed call or a caller hangup, the heads-up "Incoming call" notification stays until the app is opened. A later tap opens Veil with no call on screen.

**Fix:** Add a `cancelCall` command (or reuse `callAudio(false)`) that cancels `VeilNotify.CALL_ID`, and call it from `CallManager.end()`.

---

### C6-9: Nit. INVARIANTS cites a test that does not exist
**Where:** `docs/INVARIANTS.md` INV-NET-1 row.

The row cites `real_chromium_video_call_passes`. The test is `ice::tests::real_chromium_calls_pass` (`crates/core/src/ice.rs` L542). Rename the reference.

### C6-10: Nit. `Debug` derives would print TURN credentials and SDP if ever logged
**Where:** `crates/client/src/service/calls.rs` L30, L46.

`IceServerView` derives `Debug` with `credential`, and `CallSignal` with the SDP (ICE password, fingerprint). Nothing logs them today, but a future `tracing::debug!(?setup)` would print a token. Implement a redacting `Debug`, as `SetupInput` does.

### C6-11: Nit. Indentation in the chat header
**Where:** `app/src/screens/Chats.tsx` L711.

The `{contact.blocked ? null : (` block is indented 14 spaces instead of 8. Reformat.

---

### Checked and fine
- **INV-NET-1 with `own_turn`:**
  - The allowance only adds `typ relay` candidates whose IP equals the user-configured relay host (`setup` input, stored as `relay`). Host, srflx and prflx are still refused (`own_turn_server_may_be_private`).
  - Every contact uses the same relay (moving relays is unsupported), so contacts already know that address. It is the server's address, not the user's, and no new address is leaked.
  - IPv4-mapped v6 forms do not match and fail closed.
  - On incoming SDP, a peer can only name addresses on the user's own TURN host, and coturn `denied-peer-ip` plus the nft rules bound that. Allowing public relay IPs was already the case before this change.
  - The `Mode::Direct` branch is unused by calls.
- **No panics on untrusted input in `calls.rs`:**
  - no indexing or `unwrap`;
  - `decode_id` and `encode_id` are bounded;
  - `call_id` length and SDP size are enforced by `Content` validation (`content.rs` L315-329);
  - `sent_at_ms` is converted with saturation.
- **Relay I/O rules:** `call_send` seals inside `atomically` and delivers after commit. `receive_call` runs inside `process` with no relay I/O. A re-processed duplicate offer is harmless because the UI compares `callId`.
- **Blocked contacts:** `call_setup`, `queue_control` and `receive_call` all refuse them, and this is tested.
- **Signal queue:** memory only, capped at 32, dropped with the session on lock (tested).
- **`video_in`:** correct on the real Chromium vectors and the synthetic cases. A caller-controlled flag only changes the callee's own "Accept video call" prompt.
- **TURN credentials in the webview:** short-lived relay HMAC logins, no Veil keys (rule 2). CSP is unchanged; WebRTC is governed by `iceTransportPolicy: "relay"`.
- **Data channel state parsing:** strict (four booleans, 256-character limit, wrong types ignored), and stale-pc messages are rejected (`this.pc === pc`).
- **Screen sharing:** via `replaceTrack` into fixed slots. A peer offer with fewer than 4 transceivers is refused, and wrong-kind slots throw and end the call.
- **Notifications are content-free:** "Incoming call" with no name on Android (`IMPORTANCE_HIGH`, `CATEGORY_CALL`); on desktop a Critical attention flash only when the window is unfocused.
- **Android audio:** `callAudio` restores `MODE_NORMAL`, clears the communication device and `KEEP_SCREEN_ON` on end.
- **Design rules:**
  - new colours are tokens in both `tokens.css` files;
  - the only animation (`share-in`) uses transform and opacity and honours `data-motion` and `prefers-reduced-motion`;
  - controls are `.icon-btn` with labels and visible text;
  - state pills use icon plus words, not colour alone;
  - the range input is `--tap-min` tall and the radio rows 56 px.
- **SDP vectors:** only 127.0.0.1 relay candidates and `raddr 0.0.0.0`, nothing identifying; marked `-text` in `.gitattributes`.
- **IPC:** all new calls go through `ipc.ts`, with no direct `invoke`.

## Milestone 6 calls review, round 2 (commit 07b6547)

**Verdict: PASS** (0 Critical, 0 High; 1 Medium, 3 Low, 1 Nit)

Scope: `git diff bde54b3 07b6547`, 14 files. No files were modified.

Commands run:
- `cargo test -p veil-client --features test-hooks --test calls`: 3 passed, including `an_undelivered_offer_is_never_sent_later`.
- `cargo test -p veil-client --lib calls`: 4 passed, including `old_signals_are_stale`.
- `cargo test -p veil-core --lib ice`: 15 passed.
- `pnpm -C app typecheck`: 0 errors.

The full-workspace totals in TEST_REPORT (225 passed, clippy, lint, design check) were not re-run.

---

### Round-1 findings

| ID | Status | Notes |
|---|---|---|
| C6-1 (High) | **fixed** | See the `start()` / `accept()` walk-through below the table. The same leak exists in `flip()`, which the fix did not touch: C6R2-1. |
| C6-2 (Medium) | **fixed** | See the `call_send` notes below the table. |
| C6-3 (Medium) | **fixed** | See the TURN host notes below the table. |
| C6-4 (Medium) | **fixed** | See the ShareSheet notes below the table. A dialog left open under the call can still swallow Tab: C6R2-3. |
| C6-5 (Low) | **fixed** | `is_stale` was extracted and tested at 0, 89, 90 and 90.001 s, plus the future, `u64::MAX` and `i64::MAX`. Clock skew is in ADR-0018 Costs. |
| C6-6 (Low) | **fixed** | Same delete as C6-2. The new test checks `hidden_rows == 0`. ADR-0018, PROTOCOL §8 and INV-NET-3 wording match the code. |
| C6-7 (Low) | **fixed** | The tie-break is consistent on both sides: lowercase 32-hex ids, so string comparison equals numeric comparison. A small gap remains: C6R2-2. |
| C6-8 (Low) | **fixed for answered, missed and ended calls** | `callAudio` cancels `CALL_ID` on every `end()` and when the call connects. Offers rejected as busy or ignored in glare are not covered: C6R2-4. |
| C6-9 (Nit) | **fixed** | INVARIANTS now cites `real_chromium_calls_pass` (`ice.rs` L542). |
| C6-10 (Nit) | **fixed** | `IceServerView` and `CallSignal` have redacting `Debug` impls. `CallSetup`'s derived `Debug` delegates to them. |
| C6-11 (Nit) | **fixed** | `Chats.tsx` L711 is now indented 8 spaces. |

**C6-1 walk-through (`start()` and `accept()`).** Every await has a `live(id)` check that releases what was taken:
- `callSetup`: nothing is held yet, so it just returns.
- `media`: `release(local, null)`.
- `createOffer` / `setRemoteDescription` / `setLocalDescription` on a pc that `end()` or `abandon()` closed: they throw, and the catch path calls `release`.
- `gathered`: `release(local, pc)`.
- `callSend`: the ring timer is no longer armed for a call that has gone.

Calling `pc.close()` and `track.stop()` twice is harmless. `release` nulls `this.pc` only if it still points at that pc, so a call that started in the 1.8 s "ended" window keeps its own pc. `patch()` is a no-op after the call ends, except for the `end()` patch itself. If a hangup is sent while the offer or answer is still in flight, the actor sends the hangup second, so the peer ends cleanly.

**C6-2 (`call_send`).** The `DELETE … AND kind='control'` runs in the same actor turn as `deliver` (`&mut self`), so `retry_failed` and `tick` cannot interleave. It runs in autocommit after the `atomically` savepoint is released, like `deliver`'s own updates. Deleting a sealed envelope after the ratchet has advanced leaves a gap in the message chain, which libsignal tolerates.

The new test is meaningful. On the old code the failed row (`attempts=1`, not expired) would be redelivered by `connect()` → `retry_failed()` before "back", so both `hidden_rows == 0` and the "no signal, no ring" asserts would fail.

**C6-3 (TURN host check).** `tld_ok` requires a last label of at least two letters, all alphabetic. That rejects every `inet_aton` shorthand form: decimal, octal and hex labels all contain a digit. Bare 32-bit integers are dotless and already refused. The ADR, PROTOCOL and THREAT_MODEL §4 item 12 now state the residual risk from DNS correctly. Renumbering "Bugs" to item 13 left no stale references in the docs.

**C6-4 (ShareSheet).** `closeSheet` is stable, and initial focus runs only once. `useDialogKeys` traps Tab across [Close, Share/Stop], and the native tab order passes through the radio group between them. The trap cycle (Close, radio, Share) and Shift+Tab both work. Focus returns to the Share control when the sheet closes.

---

### New findings

#### C6R2-1: Medium [HIGH that tracks are not stopped; MEDIUM that the OS indicator stays on]. `flip()` never stops a microphone track it opens, and leaks the new camera track if the call ends mid-flip
**Where:** `app/src/calls.ts` L493-509 (`flip`) and L122-127 (`media`). This code is unchanged since bde54b3. It is the same class of bug as C6-1, and the C6-1 fix does not cover it.

**Problem:**
1. **The microphone track.** `media(true, facing)` always requests `audio` as well as video. `flip()` keeps only `getVideoTracks()[0]`. The new audio track is never stored or stopped. The rebuilt `local` keeps the old audio track, so `end()` does not stop the new one either. This happens on every successful flip.
2. **The camera track.** If the call ends during `await media(...)`, `end()` has set `this.pc = null`. The next line, `this.pc.getTransceivers()`, then throws a TypeError, which the catch swallows. `next` is never stopped, so the camera keeps capturing with no call. If a new call has started in the meantime, `this.pc` is the new call's pc, and the old flip's track is swapped into its camera slot.

**Failure scenario:** On Android, Flip is shown in every video call. After one flip, an extra microphone capture is held. The other side hanging up while the user is flipping (camera switch takes about 0.5-1 s on Android) leaves the camera running and the privacy indicator lit after the call screen has gone. This is the harm C6-1 was raised for.

**Fix:**
```ts
async flip(): Promise<void> {
  const c = this.current;
  const old = c?.local?.getVideoTracks()[0];
  if (!c || !old || !this.pc) return;
  const facing = old.getSettings().facingMode === "environment" ? "user" : "environment";
  try {
    const stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: facing, width: { ideal: 1280 }, height: { ideal: 720 } },
    });
    const next = stream.getVideoTracks()[0];
    if (!next) return;
    const pc = this.pc;
    if (!this.live(c.id) || !pc) { next.stop(); return; }
    next.enabled = !c.cameraOff;
    await pc.getTransceivers()[Slot.Camera]?.sender.replaceTrack(next);
    old.stop();
    this.patch({ local: new MediaStream([...(this.current?.local?.getAudioTracks() ?? []), next]) });
  } catch { /* keep the current camera */ }
}
```
The key change is to request video only, so no stray microphone track is opened.

#### C6R2-2: Low [HIGH]. In glare, the side that steps aside sends nothing for its own call, so a late copy of its offer can ring later
**Where:** `app/src/calls.ts` L276-287 (`handle`, glare) and L355-361 (`abandon`).

**Problem:** The side with the larger id (B) drops its call silently. If B's offer had already been deposited and reaches A only after A's own call has ended, A is idle when it arrives. A then rings for a call B gave up on. A's call ends locally if A hangs up or its setup fails; B's offer is within the 90 s window.

**Failure scenario:**
1. A, on a flaky mobile link, and B call each other at the same moment. A's offer reaches B, and B steps aside and rings for A.
2. A sees only "Calling…" and hangs up after 10 s. B sees "Missed call".
3. A's next sync fetches B's stale offer, and A's phone rings for up to 45 s.
4. If A answers, B ignores the answer. A sits in "Connecting…" until ICE fails.

**Fix:** In `abandon()`, send a hangup for our own id. The peer ignores hangups whose `callId` is not current (L297), so this is harmless in the normal case. In the late case, the hangup follows the offer in session order and ends the ring at once.
```ts
private abandon() {
  const c = this.current;
  window.clearTimeout(this.ringTimer);
  if (c) void ipc.callSend(c.contact, c.id, "hangup").catch(() => undefined);
  this.release(c?.local ?? null, this.pc);
  this.current = null;
  this.emit();
}
```

#### C6R2-3: Low [HIGH]. A dialog open under the call still holds the keyboard: Tab does nothing on the call screen
**Where:** `app/src/ui.tsx` L187-211 (`useDialogKeys`), used by MessageActions (`Chats.tsx` L271) and PhotoViewer (`Attachment.tsx` L353); `app/src/App.tsx` L53-58 (`inert`).

**Problem:** The app now stays mounted under the call, so an open MessageActions dialog or PhotoViewer keeps its `document` keydown listener. On Tab, focus is outside its box, so the listener calls `preventDefault()` and then `first.focus()`. That focus call fails silently because the target is inert. The net effect is that Tab never moves.

Before this diff, focus went behind the overlay instead. That was also broken, so this is not a regression, but the C6-4 claim that focus stays in the call is not met in this case. Escape also closes the hidden dialog.

**Failure scenario:** A desktop keyboard-only user has a photo open when a call comes in. The call screen focuses Decline. Tab cannot reach Accept, so Enter can only decline.

**Fix:** Make the hook stand down while its dialog is inert:
```ts
const onKey = (e: globalThis.KeyboardEvent) => {
  if (box.current?.closest("[inert]")) return;
  ...
```

#### C6R2-4: Low [MEDIUM]. On Android, an "Incoming call" notice for an offer rejected as busy (or ignored in glare) stays up through the current call
**Where:** `app/src/calls.ts` L281-285 (the busy reply and the glare `continue`), `app/src-tauri/src/lib.rs` L686-687, `app/android/VeilNativePlugin.kt` L192-214 and L222-227.

**Problem:** Rust raises `Ringing` for every offer it accepts. If Veil is in the background, the shell posts a high-priority "Incoming call" notice. The webview then replies busy, or ignores the offer in glare, but nothing cancels the notice. It is only cleared by `callAudio`, which runs when the current call connects or ends, or on a speaker toggle. C6-8 covers answered, missed and ended calls, but not these.

**Failure scenario:** An Android user switches to another app during a voice call. A second contact calls. A heads-up notice alerts on the Calls channel and stays in the shade for the rest of the call, for a call that was already turned away. Tapping it shows the existing call.

**Fix:** Add a dedicated `cancelCallNotice` plugin command, exposed as `ipc.cancelCallNotice()`, that only cancels `VeilNotify.CALL_ID`. Call it from the busy and glare-ignore branches of `handle()`. Do not reuse `callAudio(true, …)` there, because it would switch the audio mode.

#### C6R2-5: Nit. A comment now sits above the wrong effect
**Where:** `app/src/App.tsx` L51-52.

The comment "Notifications are on by default; Android asks for its permission the first time (review M4-3)…" now sits above the new `inert` effect, not above the `notifyWelcome` effect it describes. Move the `inert` effect (L53-58) above that comment, and give it its own one-line comment (e.g. "The app under a call is inert (C6-4)").

---

### Checked and fine
- **`start()` / `accept()` await paths:** all checked; see the C6-1 walk-through above.
- **Glare:** symmetric and deterministic.
  - Only an outgoing call in `calling` to the same contact counts as glare, and an offer echoing our own id is not treated as one.
  - `abandon()` clears the ring timer and releases tracks and pc. The pending `start()` continuation then releases or returns at its next `live()` check, and no longer overwrites `ringTimer`.
  - A busy reply for the abandoned id is ignored, because its `callId` is not current.
- **`call_send` delete:** cannot race `retry_failed`, `deliver` or `tick` (same actor turn). It is outside any open savepoint, matching how `deliver` writes. A blocked contact or pending intro also ends in delete plus `Unreachable`.
- **`is_stale`:** saturating arithmetic, no panics. Senders with a fast clock are not penalised, by design (ADR-0018 Costs covers the slow-clock case).
- **`turn_url_ok`:** the rule holds against `127.1`, `10.1`, `192.168.1`, `0x7f.1`, `1.2.3.4.5`, a trailing-dot name (refused), bracketed and bare IPv6 (refused unless public or own), and zone ids (charset).
- **Redacted `Debug`:** `IceServerView` prints only `urls`; `CallSignal` prints only contact, kind and video. `CallSetup` delegates to them. Nothing in the diff logs them.
- **`.under-call { display: contents }`:** no layout rule depends on `#root`'s direct child. The wrapper also keeps the main screen at the same tree position whether or not a call is up, so drafts survive. `inert` is re-applied after unlock (the `state` dependency).
- **ShareSheet:** stable `closeSheet`; the focus trap and the return of focus to the Share control work.
- **Android `callAudio`:** cancels `CALL_ID` on the UI thread, before the audio-mode changes. `NotificationManagerCompat` is already imported.
- **Docs match the code:**
  - ADR-0018 (signaling, memory-only signals, TURN names, ringing, glare, Costs);
  - PROTOCOL §8;
  - THREAT_MODEL §4 item 12, with "Bugs" renumbered to 13 and no stale references;
  - INVARIANTS INV-NET-1 and INV-NET-3;
  - the TEST_REPORT round-1 fix section, including the mutation claim for the new client test, which holds by reasoning: on the old code `retry_failed` redelivers the failed row on reconnect.

## Funnel calls review, round 1 (commit dc2b29a)

**Verdict: PASS.** No Critical or High findings. There are two Lows and one Nit.

Scope: 19 files. Reviewed in full: `crates/wire`, `crates/relay` (`main.rs`, `server.rs`, `turn.rs`, tests), `crates/client` (`service.rs`, `service/calls.rs`, `tests/calls.rs`), deploy (`turnserver.conf`, `entrypoint.sh`, `docker-compose.yml`, `.env.example`, `README.md`), `.github/workflows/ci.yml`, and the docs (ARCHITECTURE ADR-0018, PROTOCOL §8, THREAT_MODEL, INVARIANTS, TEST_REPORT). I also read the relevant parts of `crates/core/src/ice.rs`.

Tests run on this commit:
- `cargo test -p veil-client --features test-hooks --test calls`: 4 passed, including `an_outsider_reaching_the_relay_by_name_can_call`.
- `cargo test -p veil-wire`: 5 passed.
- `cargo test -p veil-client --lib`: 21 passed.
- `cargo test -p veil-relay`: **not run.** The volume filled up (0 MB free) during its build, and after that no shell command could run. Someone needs to free space (most likely `target/`) before running it.

### F6-1. Low. Strangers can use up coturn's allocations through Funnel and block the owner's calls
`deploy/coturn/turnserver.conf` L15-19 (`user-quota=4`, `total-quota=100`, `max-allocate-lifetime=3600`); `deploy/README.md` "Calls with people outside your tailnet" and the TURN bullet at about L256.

**Problem.** The deny-all-peers change works: nobody can reach the LAN, the tailnet or the internet through this coturn. Availability is a separate matter:
- Mailbox creation is open, and the relay gives out up to 10 TURN credentials per mailbox at once, then 1 per minute.
- Every credential has a fresh username, so `user-quota=4` limits each credential, not each person.
- Funnel now puts coturn on the internet, and with option C it was reachable only from the tailnet before. Through Funnel every client also appears to coturn as tailscaled's loopback address, so coturn cannot tell people apart.

**Scenario.** A stranger who knows the relay's Funnel name creates three mailboxes and fetches 30 credentials. With 4 allocations each, that is 120 allocations, more than `total-quota=100`. The attacker refreshes them for an hour. Every new call from the owner and their contacts then fails to allocate. The attacker can also relay traffic between two of their own allocations (each allocation is allowed to send to coturn's own address) and use up to 1 MB/s per session of the Pi's Funnel bandwidth. The README says the quotas "limit what they can do", but it does not say this can block the owner's calls.

**Fix.** Document it in the README's "Costs" list, for example: "Anyone who can open a mailbox can use up coturn's 100 allocations and block calls until they expire. Turn Funnel for coturn off if that happens." Optionally make it harder: cut the relay's `turn_per_mailbox` burst from 10 to 3. Rate limits per mailbox cannot stop this, because mailbox creation is open, so the README note is the real fix.

### F6-2. Low. If the first-call TURN lookup fails, the outsider's first call silently cannot connect
`crates/client/src/service/calls.rs` L358-377 (`call_signals`).

**Problem.** If `relay_ips` is still unknown, `call_signals` asks the relay once (`let _ = self.turn_credentials().await;`). If that request fails, it still drains the whole queue and filters each SDP without the announced addresses. Possible reasons for the failure:
- the relay connection is still being re-established;
- `RateLimited`: the burst is 10, then 1 per minute, shared with `call_setup`;
- a timeout.

For an outsider, the tailnet caller's only relay candidate (on `100.x`) is then removed. The UI rings with an offer that has no usable candidate. When the user answers, `call_setup` does fill `relay_ips`, but the offer has already been handed over with the candidate removed. Nothing goes back to re-filter it, so the call never connects and the user is not told why. This is not a security problem: removing candidates fails closed.

**Scenario.** Bob (outside the tailnet) unlocks his app just as Alice calls. The push with her offer arrives before his relay connection is ready to answer requests. The lookup fails, the phone rings, and the answered call stays at "connecting" until it times out.

**Fix.** If the lookup failed, keep the offers and answers in the queue and return only signals without SDP. The UI polls again shortly:
```rust
if s.calls.needs_sdp_filter() && s.calls.relay_ips.borrow().is_none()
    && self.turn_credentials().await.is_err()
{
    return Ok(self.s()?.calls.take_without_sdp()); // offers/answers stay queued for the next poll
}
```
Alternatively, after a failure keep a "fetch failed" marker and let `call_setup` re-filter the waiting offer. Add a test that exercises the failure, for example a relay with TURN rate-limited to 0.

### F6-3. Nit. The ADR cites some CVEs that do not apply and misses the one that does
`docs/ARCHITECTURE.md`, ADR-0018 "Kept current" bullet.

**Problem.** I checked the cited CVEs against the coturn GitHub advisories:
- **CVE-2026-40613** (GHSA-j662-9wcj-mf36): unauthenticated crash on ARM64, fixed in 4.10.0. Cited correctly.
- **CVE-2026-73212** (GHSA-2x4g-wx24-48m4): bypass on the RFC 6062 TCP CONNECT relay path, fixed in 4.13.1. Veil's config sets `no-tcp-relay`, so this one never applied.
- **CVE-2026-27624** (GHSA-j8mm-mpf8-gvjg): the advisory lists no patched version.
- **CVE-2026-73213** (GHSA-4v97-rxjj-4f99), not cited: the IPv6 comparison in `addr_less_eq()` lets clients get past `denied-peer-ip`/`allowed-peer-ip` ranges. It affects 4.15.0 and earlier and is fixed in 4.16.0. This is the advisory that matters for the new `denied-peer-ip=::-ffff:…` line.

The TEST_REPORT's local check also ran coturn 4.6.1, which has this IPv6 bug. Only IPv4 peers were tested there, so the results still hold.

**Fix.** Change the sentence to: "…peer-restriction bypasses (CVE-2026-27624; CVE-2026-73213, IPv6 range comparison, fixed in 4.16.0, which the deny-all IPv6 line depends on)". Drop CVE-2026-73212, or mark it as not applicable because of `no-tcp-relay`.

### Checked and fine
- **Wire (`crates/wire/src/lib.rs`):**
  - `relay_ips` is checked in `decode_strict`: at most 4 entries (`MAX_URLS`), each at most 45 bytes and parsed as an `IpAddr` before use.
  - Names, shorthand IPv4, `public/private` pairs and 5 entries are refused, and the tests cover these.
  - Tag 5 is new, so it does not break the wire format.
- **Relay (`turn_from_env`, `server.rs`, `turn.rs`):**
  - In `public/private` form only the part before `/` is used (`unwrap_or_default`, no panic). A bad IP or a 5th entry stops startup with an error.
  - The redacting `Debug` on `TurnConfig` now also shows the operator's IPs, which contain no client data.
  - The response sends the configured IPs as strings. The secret handling is unchanged.
- **Client, announced addresses (`announced`, `turn_hosts`):**
  - Unparseable, unspecified and multicast entries are dropped, and at most 4 are kept. Nothing on this path can panic.
- **Client, TURN URLs never use announced addresses:**
  - `call_setup` filters URLs with `own_turn(&s.relay_addr)` only, never with `turn_hosts`.
  - The test confirms it: with `127.0.0.1` announced, an outsider's setup still drops `turn:127.0.0.1…` and keeps only the name URL.
- **A hostile relay announcing addresses gains nothing:**
  - Announced addresses only widen which `typ relay` candidates pass the filter. With `iceTransportPolicy: relay`, the webview sends only to the TURN servers it was given; remote candidates are reached through that TURN server.
  - On the outgoing side, `filter_sdp_with` still requires `typ relay`, so the user's host or srflx addresses cannot leak even if the relay announces the user's LAN IP.
  - INV-NET-1 holds.
- **Lazy filtering does not change what is accepted or rung:**
  - Each candidate line is kept or dropped on its own and is not subject to the fail-closed address scan. `validate_dtls` does not depend on candidates, and `video_in` reads only the `m=` and direction lines.
  - So whether a signal is accepted, rung, and marked as video is decided at arrival and cannot change at take time. The `filter_map` that drops signals at take time cannot fire for an SDP that passed at arrival.
- **No unfiltered SDP reaches the UI:**
  - `call_signals` is the only reader of the queue (`calls.take`; grep confirms), and it filters every `Some(role)` entry.
  - The raw SDP waiting in memory was size-checked at arrival (`MAX_SDP`) and is bounded by `MAX_PENDING`.
- **No borrow conflict in `call_signals`:** the `RefCell` borrow in the `if` condition ends before `turn_credentials` writes to the same cell (the passing test exercises this path).
- **State on lock and between accounts:**
  - `Pending` (queue plus the `relay_ips` cache) lives in `Session` and is created fresh at create and unlock (`service.rs` L1630, L1744). It is dropped on lock. The relay address never changes within a session.
  - `call_setup` refreshes `relay_ips` on every call.
- **Test `an_outsider_reaching_the_relay_by_name_can_call` is meaningful:**
  - It runs both with and without the announcement. Bob reaches the relay as `localhost:port`, which stands in for a Funnel name.
  - Filtering at arrival (the old behaviour), or removing the lazy lookup, would fail the `announce=true` check on the offer.
  - It checks both directions and the TURN URL rule.
- **coturn config:**
  - In coturn's `good_peer_addr` (checked against coturn master), the allowed list is checked before the denied list, so `allowed-peer-ip` overrides the deny-all ranges.
  - Link-local and ULA addresses are always denied before the allowed list is checked. That does not affect `100.x` (option C), public IPs (A), or the public half of B's `public/private` form. `entrypoint.sh` strips `/private`, so B allows the public address, the same as before. Relaying to it still needs hairpin NAT on the router, which is unchanged.
  - CI tests the override: the client-to-client run (`-y`, UDP and new TCP) must lose 0 packets, and peers `10.0.0.1` and `1.1.1.1` must get `403`.
  - I could not test 4.18.0 itself here. coturn 4.18.0 is a real release (2026-09-08), and its changelog shows no option removals that would affect this config. CI is the check for the exact image.
- **Compose and CI:** `VEIL_TURN_RELAY_IPS` takes the same value as coturn's `external-ip`. Images are pinned by digest. In CI, `-t` makes only the client leg TCP, which still works with `no-tcp-relay`.
- **Docs:** PROTOCOL §8, INVARIANTS INV-NET-1, THREAT_MODEL items 12-14, the deploy README Funnel steps and the TEST_REPORT description match the code. The only exception is F6-3. TURN URLs are still refused for private IPs other than the relay's own, so item 12 is still accurate. I did not verify the Tailscale "1.104.4 / Tailworm" claim.

## Camera in voice calls and call bubble review, round 1 (commit 753adb0)

**Verdict: PASS.** No Critical or High findings. There are one Medium, five Low and two Nit findings.

Scope: `git diff 753adb0~1 753adb0`, 14 files, about 800 lines (about 410 of them are SDP vectors). Commands run on 753adb0:

```text
$ pnpm -C app typecheck                     # tsc --noEmit, exit 0
$ pnpm -C app lint                          # lint: 17 files clean
$ cargo test -p veil-client --lib camera    # the_camera_section_tells_voice_from_video ... ok (1 passed)
$ cargo test -p veil-core --lib ice         # 15 passed, 0 failed (incl. arbitrary_input_never_panics, relay_only_sdp_never_leaks)
```

### CB-1: Medium. The call's live status was moved outside the `aria-modal` dialog, so the full-screen call no longer announces anything
- **Where:** `app/src/screens/Call.tsx:410` (the `<span className="sr-only" role="status">`), together with `Call.tsx:345` (`role="dialog" aria-modal="true"`).
- **Problem:** The status span used to sit inside `.call-overlay`. It is now a sibling of the overlay inside the fragment. Chromium is the engine of both WebView2 and the Android WebView. When focus is inside an `aria-modal="true"` dialog, Chromium treats everything outside that dialog as ignored in the accessibility tree (`IsBlockedByAriaModalDialog`). On every full-screen render, the focus effect at `Call.tsx:312` moves focus into `.call-controls`. So while the call is full screen, the live region is outside the active modal and is pruned. (Confidence MEDIUM: the Chromium behaviour is from the engine's design, not tested here with a screen reader.)
- **Failure scenario:** A screen-reader user places a voice call and keeps it full screen. They no longer hear "Call connected", "Alex is muted" or "Alex is sharing their screen". Before this commit they did. The announcements only work while the call is minimized.
- **Fix:** The `.under-call` element already gets `inert` while the call is full screen (`App.tsx:52-57`), so `aria-modal` is redundant. Remove it and leave the status span where it is:
  ```tsx
  <div className="call-overlay" role="dialog" aria-label={`${call.video ? "Video" : "Voice"} call with ${name}`}>
  ```
  The other option is to keep `aria-modal` and render the status span inside the overlay when full screen and inside the bubble's root when minimized.

### CB-2: Low. Mixed versions with preview.8: the voice/video signal no longer agrees, in both directions
- **Where:** `crates/client/src/service/calls.rs:174-191` (the new `video_in` rule), `app/src/calls.ts:263` (voice offers now carry a sending camera section), `app/src/calls.ts:417-453` (`toggleCamera`).
- **Problem (a), new caller to preview.8 callee:** preview.8's `video_in` (the parent commit's) reads any camera section that is not `inactive`/`recvonly` as video. A voice offer from this build has `a=sendrecv` + `a=msid:- …`, so preview.8 shows "Incoming video call". On Accept, `media(true)` opens the callee's camera. The new caller then shows that picture, because `remoteCamera` turns true. The callee did accept a "video call", so no camera opens without consent, but the caller's choice of voice is lost.
- **Problem (b), preview.8 caller to new callee:** The offer's camera section is `a=inactive`, so the negotiated direction is inactive. On the new side the Camera button still works locally. `getUserMedia` opens the camera, `replaceTrack` succeeds on an inactive transceiver, the self-view shows, and `tell()` sends `cameraOff: false`. Nothing is ever sent. The same wrong state happens if `pc.getTransceivers()[Slot.Camera]` is `undefined` (the `?.` at `calls.ts:438` silently skips `replaceTrack`, and `local` is still patched with the camera).
- **Failure scenario:** An outsider on preview.8 calls the owner, who is on the new build. The owner presses Camera and sees themselves "on camera". The other side never sees it, and the owner's camera light stays on for nothing.
- **Fix:**
  1. In `toggleCamera`, do not open the camera unless the camera transceiver exists and was negotiated to send:
     ```ts
     const cam = pc.getTransceivers()[Slot.Camera];
     if (!cam || !(cam.currentDirection === "sendrecv" || cam.currentDirection === "sendonly")) { next.stop(); return; }
     await cam.sender.replaceTrack(next);
     ```
     Better still, run this check before `getUserMedia`, so the camera is never opened. Note that `currentDirection` is null until negotiation completes, so this also blocks the camera while the call is "calling". If that matters, allow `currentDirection === null` and check `cam.direction`.
  2. In ADR-0018 "Voice or video", add one line: a voice call from this build is read as video by preview.8, so both sides need this build.

### CB-3: Low. A drag that ends off the bubble swallows the next keyboard or assistive-tech activation
- **Where:** `app/src/screens/Call.tsx:175-199` and `Call.tsx:213-220`.
- **Problem:** `dragged.current` is reset only on the next `pointerdown` or inside the button's `click`. If the bubble is clamped at an edge, the finger keeps moving and lifts outside the bubble. No `click` follows, so `dragged.current` stays `true`. Enter or Space on the focused "Back to the call" button, or a screen reader's activate, fires a `click` with no `pointerdown`, and that click is thrown away. A related issue: the window listeners do not filter by `pointerId`. A second finger's `pointerup` ends the first finger's drag, and both fingers' moves drive one drag.
- **Failure scenario:** The user drags the bubble hard into the bottom corner, lets go, then presses Enter (or double-taps with a screen reader) to return to the call. Nothing happens until they try again.
- **Fix:**
  - Ignore keyboard clicks in the suppression: `if (dragged.current && e.detail !== 0) { … return; }`. For activation that has no pointer, `e.detail` is 0.
  - Clear the flag after the click would have fired: in `up`, add `window.setTimeout(() => { dragged.current = false; }, 0);`.
  - Track a single pointer: store `const id = e.pointerId` and return early in `move`/`up` when `ev.pointerId !== id`. Optionally call `e.currentTarget.setPointerCapture(id)`.

### CB-4: Low. The focused bubble button's accessible name changes every second
- **Where:** `app/src/screens/Call.tsx:212` (`aria-label={`Back to the call with ${name}, ${status}`}`), and `status` is the running clock. The bubble focuses this button on mount (`Call.tsx:164`).
- **Problem:** The focused element's name changes once a second. NVDA and JAWS on Chromium may speak name changes of the focused object, so this repeats the running-timer problem raised earlier (REVIEW_REPORT, `Chats.tsx` recording bar: "announce it every second"). (Confidence MEDIUM: depends on the screen reader.)
- **Failure scenario:** A screen-reader user minimizes a call and hears "Back to the call with Alex, 0:42 … 0:43 …" until they move focus.
- **Fix:** Keep the label static, and let the visible time stay `aria-hidden` as it already is:
  ```tsx
  aria-label={call.phase === "active" ? `Back to the call with ${name}` : `Back to the call with ${name}, ${status}`}
  ```

### CB-5: Low. The core SDP test's new voice/video assertion cannot fail
- **Where:** `crates/core/src/ice.rs:589-596`.
- **Problem:** The old check (`a=inactive` present exactly in voice calls) was removed. The new one checks that some `a=msid:` line in the whole SDP is not `a=msid:- `. In every vector, the microphone section already carries `a=msid:<stream> <track>`, so the assertion holds even if the filter dropped the camera section's msid. Nothing replaced the check on the voice side. (The client test `the_camera_section_tells_voice_from_video` does cover the filtered vectors end to end, so this is not a coverage hole, but the core test now claims more than it checks. See CLAUDE.md rule 9.)
- **Fix:** Look at the camera section (the first `m=video`) only, and check both cases:
  ```rust
  let camera: Vec<&str> = out.split("\r\n").skip_while(|l| !l.starts_with("m=video ")).skip(1)
      .take_while(|l| !l.starts_with("m=")).collect();
  let named = camera.iter().any(|l| l.starts_with("a=msid:") && !l.starts_with("a=msid:- "));
  assert_eq!(named, video, "the camera section's stream id must survive the filter");
  ```

### CB-6: Low. The TEST_REPORT entry has no real command output
- **Where:** `docs/TEST_REPORT.md:5-24`.
- **Problem:** CLAUDE.md says "updated `docs/TEST_REPORT.md` (real command output)", and earlier entries include a `text` block with fmt, clippy, test and audit results. This entry lists test names and manual browser steps, but no `cargo fmt/clippy/test` or `pnpm typecheck/lint` output for 753adb0.
- **Fix:** Add the block, for example `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `pnpm -C app typecheck`, `pnpm -C app lint`, each with its result.

### CB-7: Nit. The bubble sits above dialogs and toasts
- **Where:** `app/src/styles/app.css:140` (`z-index: 100`). The tokens are `--z-modal: 50` and `--z-toast: 60`.
- **Problem:** Unlike the full-screen overlay, the bubble is meant to sit over a usable app, so it also covers that app's modals and toasts. Its default spot (top right, y=76) can hide a dialog's top-right Close button until the user drags it away. The z-index is also a raw number, not a token.
- **Fix:** Add a token between sticky and modal, for example `--z-call-bubble: 40`, and use `z-index: var(--z-call-bubble)`. Then dialogs and toasts stay on top, and the bubble still floats over the content.

### CB-8: Nit. The bubble keeps acting like a live call after the call ends
- **Where:** `app/src/calls.ts:456-460` (`setMinimized`), `calls.ts:218-219` (`patch` ignores changes once the call has ended), `calls.ts:449-452`, and `app/src/screens/Call.tsx:209-220`.
- **Problem:** During the `ENDED_MS` window, the bubble still says "Back to the call with X, Call ended", but tapping it does nothing, because `patch` drops the change. Separately, when `toggleCamera` fails (no camera, or permission denied), the user gets no feedback.
- **Fix:**
  - Make the bubble's open button do nothing visible once the call has ended, for example `aria-disabled={call.phase === "ended"}` with a label of just `status`.
  - Or let `setMinimized(false)` bring back the full-screen "Call ended" view with `this.patch({ minimized }, true)` when the phase is `"ended"`.
  - For the camera failure, consider a short status message, such as reusing `reason(err, …)` in the sr-only status.

### Checked and fine
- **`video_in` (Rust):**
  - No indexing, `unwrap` or panics. It uses `split`/`strip_prefix`/`is_some_and` only, and the `Vec` is bounded by the SDP size limit applied before it.
  - It runs on the SDP after `filter_sdp_with`, which keeps `a=msid` (`KEPT_ATTRIBUTES`).
  - All six vectors are correct: video offer/answer have a camera stream id, the new voice offer/answer have `a=msid:- …`, and the preview8 offer/answer have `a=inactive`.
  - The preview8 vectors are byte-identical to the parent's voice vectors.
  - A missing `a=msid` reads as voice.
- **Abuse of the flag:** a caller who forges a camera stream id only makes the callee's screen say "Incoming video call" and open the camera after an explicit "Accept video call". That is exactly a normal video call, so nothing new is exposed.
- **`toggleCamera` races:**
  - Double tap: the second `getUserMedia` result is stopped when the first already set a video track.
  - `end()`, `abandon()` or glare during `getUserMedia` or `replaceTrack`: `live()` checks stop `next`. After the patch, `end()` and `release()` stop it as part of `c.local`.
  - `flip()` cannot run before a video track exists. The audio tracks are carried over, so mute and deafen keep working.
  - The phone speaker switch is documented in ADR-0018, and `end()` resets audio.
- **`remoteCamera`:**
  - Listeners are tied to the remote track's lifetime, and patches are ignored when `this.pc !== pc` or the call has ended.
  - `fresh()` resets `remoteCamera` and `minimized`, and voice calls start with `cameraOff: true`.
  - `tell()` reports the camera as off when there is no video track.
  - A camera that is turned off stays hidden through `peer.cameraOff` (a disabled track sends black frames and does not mute).
- **Audio:** every `<video>` is `muted`. The remote voice and screen `<audio>` elements keep the same positions in the fragment, so they are not remounted when the call is minimized or expanded. There is no double playback.
- **App and focus:** `App.tsx` makes the app inert only for a full-screen call. Incoming calls can never be minimized. Focus goes to the bubble on minimize and back to the first control on expand. The resize listener is cleaned up. Drag listeners are removed on `pointerup` and `pointercancel`. `bubbleAt` lives in module memory only, which matches the ADR's "never stored".
- **CSS:** only tokens for colour. Movement is `transform` only, with no transition while dragging, under `data-motion="reduced"` or under `prefers-reduced-motion`. The End button is 44×44 and the open button is 120×168. All icon buttons have labels, and the Camera button shows its state with icon and `aria-pressed`, not colour alone. All icons used exist in `public/icons.svg`.
- **IPC:** it only uses `ipc.callAudio`, through `ipc.ts`, with no direct `invoke`. Nothing new reaches the network, and no key material, paths or plaintext reach the webview.
- **Docs:** ADR-0018 ("Fixed media sections", "Voice or video", "Camera in a voice call", "Minimize", the updated "Not done"), the DESIGN.md §6 row and the TEST_REPORT steps match the code, apart from CB-2's missing compatibility note and CB-6.
- **Checks:** `pnpm -C app typecheck` and `lint` are clean, and the `veil-client` and `veil-core` ice tests pass.

## Look (milestone 4.5) review, round 1 (2026-10-29)

**Scope:** commit fdd85b5, 24 files, +1257/−19 lines. I reviewed every changed source, CSS and doc file and skipped the lockfiles. No files were edited.

**Checks run**
- `pnpm -C app typecheck`: passes (tsc, 0 errors). `app/` has no uncommitted changes, so this result applies to the commit.
- `CARGO_INCREMENTAL=0 cargo test --offline -p veil-client --test look`: `wallpapers_and_chat_colours` passes. **Caveat:** the working tree has uncommitted changes to `crates/client/src/{db.rs,service.rs,service/look.rs}`, `crates/core/src/content.rs` and a new `service/profile.rs`, apparently from another session. So this run tested the working tree, not exactly fdd85b5. All line numbers below are from the commit (`git show fdd85b5:<path>`).
- I copied `color.ts` into the scratchpad and ran it with node to measure contrast for all 360 hues. The figures in LK-1 come from that.

**Checked and found correct:**
- **CSS/URL injection:** the `data:` URL uses only a MIME type from an allowlist plus the base64 alphabet. `--wp-dim` and `--wp-blur` are built from u8 values that Rust range-checks. Hues are bounded on read, in both Rust and `loadAppearance`.
- **CSP:** custom properties are set through the CSSOM, which `style-src 'self'` allows, and `img-src data:` covers the CSS `background`.
- **At rest:** the photo is in SQLCipher with `secure_delete = ON`, and the at-rest probe test passes.
- **Nothing sent:** nothing reaches the contact or the relay.
- **Atomicity:** the photo and the setting are written in one `atomically` SAVEPOINT.
- **Trigger:** `contact_wallpaper_gone` fires from `delete_contact` and from the key-change merge. There is no `REPLACE INTO contacts` anywhere.
- **Migration:** migration 5 runs inside BEGIN/COMMIT, and the generic `migrates_an_old_database_once` test covers it.
- **Parsing and logic:** `parse` is strict, the `keep_photo` state machine is correct, and nothing on the boundary can panic. `WallpaperInput`'s Debug is redacted, and `Cmd` has no Debug.
- **Design rules:** no raw colours in `app.css`, no new animations, and swatches and tiles are at least 44 px.

---

### LK-1: High. Text in sent bubbles fails 4.5:1 for 345 of 360 custom hues
**Where:** `app/src/color.ts:42-50` (`bubbleLightness`), `:75`, `:90`. Related: `app/src/styles/tokens.css:210` (`--text-on-accent-2: rgb(255 255 255 / 0.86)`) and `base.css:381/389/419/433` (`.meta`, reply, file subtitle and voice duration in sent bubbles use `--sent-meta`).

**Problem:**
- `bubbleLightness` lowers the lightness only until **pure white** reaches 4.5:1. The chosen colours therefore sit right at the threshold (the report's worst case is 4.5007).
- Timestamps, reply quotes, file sizes and voice durations in sent bubbles are 86 % white. On these computed colours they reach only **3.64:1** (worst case: hue 317). 345 of 360 hues fail.
- The presets are fine: they range from 4.89 to 6.28.
- So the commit's headline claims are false: "a custom colour cannot make text unreadable" in the commit message, and "keeps 4.5:1" in ADR-0019. Per-chat colours have the same problem, because they use `bubbleVars`.

**Secondary point (medium confidence; I did not trace which elements use it):** in pure black, `--surface-3` is `#1a1a1f`, which is lighter than the "hardest" `DARK_BG` (16, 19, 49). The dark accent on it drops to 4.31:1.

**Fix:** check the meta colour as well, and add the pure-black surfaces to the backgrounds the accent is checked against.
```ts
const META_ALPHA = 0.86; // --text-on-accent-2
const meta = (c: Rgb) => mix(c, WHITE, META_ALPHA);
if ([...cols, ...between].every((c) => contrast(WHITE, c) >= 4.5 && contrast(meta(c), c) >= 4.5)) return l;
```
For the accent, take the lightest dark candidate across `[DARK_BG, [26,26,31] /* black --surface-3 */]`. Then re-run the check for all 360 hues and record the new worst cases.

### LK-2: Medium. The hue and level sliders save on unrelated key presses
**Where:** `app/src/components/Look.tsx:52-53`, and `:132`, `:137` for Dim and Blur.

**Problem:**
- `onKeyUp` fires for **any** key. That includes the keyup of the **Tab** press that moves focus *onto* the slider, because keyup goes to the newly focused element.
- In a contact's profile with "App accent" selected (`value === null`), `draft` defaults to 245. Tabbing through the page therefore calls `setChatAccent(id, 245)` and silently gives the chat an Indigo colour.
- On Dim and Blur, Tab or Shift fires redundant `set_wallpaper` writes.
- Separately, `onPointerUp` is the only commit path for a mouse drag. If the user releases the mouse outside the input, the commit can be lost and the slider shows a draft that was never saved, because `draft` resyncs only when `value` changes. Medium confidence: this depends on the engine's pointer-capture behaviour.

**Fix:** commit on the native `change` event, which fires once when a drag or key step ends, and only if the value actually changed:
```tsx
const ref = useRef<HTMLInputElement>(null);
useEffect(() => {
  const el = ref.current; if (!el) return;
  const commit = () => { const h = Number(el.value); if (h !== value) onChange(h); };
  el.addEventListener("change", commit);
  return () => el.removeEventListener("change", commit);
}, [value, onChange]);
// <input ref={ref} … onChange={(e) => setDraft(Number(e.target.value))} />  (drop onPointerUp/onKeyUp)
```
Do the same for `commitLevels`, skipping the save when `dim === value.dim && blur === value.blur`.

### LK-3: Medium. Keyboard use of the wallpaper radio group deletes data and loses focus
**Where:** `app/src/components/Look.tsx:107`, `:113`, `:119`.

**Problem:**
- Arrow keys in a native radio group fire `onChange` for each radio they land on. Each step saves immediately.
- Arrowing off "Photo" onto a preset or onto None/Default **deletes the user's photo for good**, because Rust drops the `wallpaper_photos` row. Arrowing onto "Photo" opens the file chooser.
- After every choice, `disabled={busy}` disables the focused radio. The browser then moves focus to `<body>`, so a keyboard or screen-reader user loses their place after each step.

**Fix:**
- Remove `disabled={busy}` and guard re-entry with a ref (`if (busyRef.current) return;`). Keep `aria-busy`.
- Open the file chooser only from `onClick`, which also fires for Space, and not from `onChange`:
```tsx
<input type="radio" … checked={value?.photo === true} onChange={() => {}} onClick={() => file.current?.click()} />
```
- Before a preset or None replaces an existing photo, ask for confirmation, for example with the existing `<AlertDialog>`: "Remove your photo wallpaper?"

### LK-4: Medium. System lines and day separators become unreadable over a photo
**Where:** `app/src/styles/app.css:217-226`, with `base.css:359-360` (`.day-sep` and `.sys-msg` use `--surface-glass` and `--text-2`).

**Problem:**
- Dim can be 0, and the pill backgrounds are translucent: `rgb(20 23 56 / .62)` in Aurora dark, and only `rgb(255 255 255 / .05)` in the new pure-black block.
- Over a bright photo, `--text-2` falls to about 2.5:1 in Aurora dark and close to 1:1 in pure black.
- Light mode over a dark photo is about 4.3:1.
- This affects call lines, timer notices and day separators. Received bubbles are opaque and are fine.

**Fix:** give these pills an opaque token background whenever a wallpaper is present:
```css
.chat-screen:has(> .chat-wallpaper) :is(.sys-msg, .day-sep) { background: var(--surface-2); }
```
Alternatively, enforce a minimum dim for photos: for example `MIN_PHOTO_DIM = 20`, checked in `look::check` and used as the slider's `min`.

### LK-5: Medium. No size limit before the webview decodes the picked photo
**Where:** `app/src/wallpaper.tsx:88`.

**Problem:**
- `createImageBitmap(file)` decodes whatever the user picks, at full resolution.
- A 100 MB file or a 20 000 × 20 000 PNG means gigabytes of RGBA memory and a webview OOM, which is likely on Android.
- The Rust 3 MiB limit applies only after this step.
- Also, transparent PNG areas come out black in the JPEG.

**Fix:**
```ts
const MAX_PICK_BYTES = 25 * 1024 * 1024;
if (file.size > MAX_PICK_BYTES) throw new Error("This picture is too large");
```
before decoding. Fill the canvas first with the theme background, e.g. `ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--bg-1"); ctx.fillRect(…)`, so no raw colour is introduced.

### LK-6: Low. Photo buffers are not zeroized, unlike attachments
**Where:** `crates/client/src/service/look.rs:92-100` (base64 `String` and decoded `Vec<u8>`), `:223-240` (BLOB `Vec<u8>` and data URL `String`).

**Problem:** `app/src-tauri/src/lib.rs` (`Upload`, `Uploads::part`) keeps attachment plaintext in `Zeroizing` and grows buffers by hand so no unwiped copy is left behind. Wallpaper photos are user content but bypass this convention.

**Fix:**
- Decode into `Zeroizing::new(…decode(..)?)`.
- Read the BLOB as `Zeroizing<Vec<u8>>`.
- Build the URL into a pre-sized `Zeroizing<String>` using `STANDARD.encode_string(&*data, &mut out)`. The final IPC serialization copy is unavoidable, as it is for attachments.

### LK-7: Low. The Rust boundary is looser than the ADR describes
**Where:** `look.rs:61-66`, `:92`, and `app/src-tauri/src/lib.rs` (`set_wallpaper`).

**Problem:**
- The whole base64 string is deserialized from IPC JSON before the length check. Attachments use bounded `MAX_PART_CHARS` chunks instead.
- Rust accepts PNG and WebP, but the webview only ever sends JPEG. The "metadata stripped" property therefore depends entirely on the webview.

**Fix:** accept only `image/jpeg` in `image_mime` for new photos; keep reading the old formats if you want. Either note in ADR-0019 that the size limit applies after IPC deserialization, or route the photo through the existing chunked upload slot.

### LK-8: Low. Clearing the cache on lock depends only on the `locked` event
**Where:** `app/src/App.tsx:123`, `wallpaper.tsx:16-24`. Medium confidence on the event ordering.

**Problem:**
- Settings' Lock button runs `ipc.lock().then(onLocked)`, which calls `refreshState()`. Once the state becomes `"locked"`, the effect cleanup unsubscribes from `onChange`.
- If the `locked` event arrives after that, `forgetWallpapers()` never runs. The photo `data:` URLs then stay in JS memory while Veil is locked.
- Contact-keyed entries also survive the next unlock, because `refreshWallpaper` deletes only key `"0"`.
- Separately, a `refreshWallpaper()` still in flight at lock time can write `global` after it was cleared.

**Fix:**
- In App.tsx, use `return () => { off?.(); forgetWallpapers(); };`.
- In `refreshWallpaper`, replace `photos.delete("0")` with `photos.clear()`.
- Guard `global` with a generation counter that `forgetWallpapers` increments: `const gen = ++epoch; const w = await ipc.wallpaper(); if (gen === epoch) global = w;`.

### LK-9: Low. Failed photo fetches are cached for the rest of the session
**Where:** `app/src/wallpaper.tsx:54-55`.

**Problem:** `ipc.wallpaperPhoto(owner).catch(() => null)` is stored in `photos`. One transient error leaves that chat without its photo until the next save or lock.

**Fix:**
```ts
p = ipc.wallpaperPhoto(owner).catch(() => { photos.delete(key); return null; });
```

### LK-10: Low. A per-chat colour forces a gradient in Ink
**Where:** `app/src/styles/app.css:209`.

**Problem:** `.chat-screen[data-own-colour] { --sent-bg: var(--sent-gradient) }` overrides Ink's `--sent-bg: var(--sent-ink)` from `tokens.css:343`. That breaks the DESIGN §2 rule that "Default" bubbles in Ink are solid.

**Fix:** add after line 209:
```css
:root[data-style="ink"] .chat-screen[data-own-colour] { --sent-bg: var(--sent-ink); }
```
The soft and minimal rules on lines 210-211 must stay after it.

### LK-11: Low. Accepting a key change silently drops the chat's look
**Where:** `crates/client/src/service.rs:3872` (`accept_key_change`).

**Problem:** the history moves to the new contact row. The old row is then deleted, and the trigger deletes its photo, so the chat's wallpaper and colour are lost without notice.

**Fix:** before the `DELETE`, carry the look over:
```sql
UPDATE contacts SET accent_hue = COALESCE(accent_hue, (SELECT accent_hue FROM contacts WHERE id = ?1)),
                    wallpaper  = COALESCE(wallpaper,  (SELECT wallpaper  FROM contacts WHERE id = ?1)) WHERE id = ?2;
UPDATE OR IGNORE wallpaper_photos SET owner = ?2 WHERE owner = ?1;
```
Add a case for this to `tests/look.rs`.

### LK-12: Low. The contrast guarantee has no committed test
**Where:** `docs/TEST_REPORT.md` (the "contrast-check" entry) and `app/package.json`, which has no `test` script.

**Problem:** the "all 360 hues, worst case 4.50" result cannot be reproduced from the repository. A test would have caught LK-1.

**Fix:** add `app/scripts/contrast-check.mjs` or a vitest, and run it from `pnpm -C app lint` or CI. It should cover every hue for white text, meta text and the accent on the dark, light and black backgrounds.

### LK-13: Low (nit). Two components now share the `.swatch` class
**Where:** `design/DESIGN.md` §6 (new row, and the existing line 130 mapping `.swatch` to `<AccentSwatch>`), and `app/src/styles/app.css:233-238`, which overrides `base.css:279-286`.

**Problem:** `.swatch` now maps to two components, which breaks the 1:1 rule.

**Fix:** rename the new classes to `.hue-swatches` / `.hue-swatch`, or update the old row.

---

**Verdict: FAIL.** One High finding: LK-1, the meta-text contrast. Fixing LK-1 and adding LK-12's test is enough to clear the gate. LK-2 to LK-5 should go into the same round.

## Look (milestone 4.5) review, round 2 (2026-10-29)

**Scope:** fix commit 503a6bb, on top of fdd85b5. I read all 14 changed files and did not edit any. Line numbers below come from `git show 503a6bb:<path>`. The working tree's uncommitted profile work is in `crates/` only, and `app/` is unchanged, so the frontend results below apply to the commit itself.

**Checks run**
- `pnpm -C app lint`: passes. Output: `lint: 20 files clean`, then `contrast: worst white 5.4293, meta 4.5001, accentDark 4.5127, accentLight 4.5002`.
- `pnpm -C app typecheck`: passes, 0 errors.
- `CARGO_INCREMENTAL=0 cargo test --offline -p veil-client --test look`: 2 passed (`wallpapers_and_chat_colours`, `a_key_change_keeps_the_chats_look`). This build includes the uncommitted working-tree changes in `crates/client`.
- I copied `color.ts` from the commit into the scratchpad and measured the computed accents for all 360 hues against every surface token in `tokens.css`. That run produced the figures in LK2-1.
- I read WebKit's `RadioInputType::handleKeydownEvent` for LK2-2. When an arrow key moves the selection, it calls `dispatchSimulatedClick` on the newly selected radio.

### Status of the round 1 findings

| ID | Status | Notes |
|---|---|---|
| LK-1 | **Fixed for meta text. The accent part is incomplete (see LK2-1).** | `readable()` now checks white and 86 % white. The worst meta case is 4.5001, and 0.86 is the dimmer theme (light is 0.88). Pure black `--surface-3` was added to the accent backgrounds, but Aurora dark and Ink dark `--surface-1`/`--surface-2` are missing, and they do carry accent text. |
| LK-2 | Fixed | `useSliderCommit` listens to the native `change` event, so Tab no longer saves. `HuePicker` and `levels()` skip a save when the value has not changed. The `shown` dependency re-binds Dim and Blur when they mount. |
| LK-3 | **Partly fixed (see LK2-2, LK2-4)** | `disabled={busy}` was removed and a ref guard replaces it. Leaving a photo now asks first, which removes the data-loss risk. However, arrowing onto "Photo" still opens the file chooser. |
| LK-4 | Fixed | `.chat-screen:has(> .chat-wallpaper) :is(.sys-msg, .day-sep)` gives an opaque `--surface-2` pill. `ChatWallpaper` is a direct child of `.chat-screen` (Chats.tsx:745). There are two small side effects, noted in LK2-5. |
| LK-5 | Fixed | A 25 MiB limit is checked before `createImageBitmap`. The canvas is filled with `--bg-1` (a plain hex value in every theme) before drawing. |
| LK-6 | **Partly fixed (see LK2-3)** | The decoded bytes and the BLOB are now `Zeroizing`. The `data:` URL string is not pre-sized, so building it leaves freed copies. |
| LK-7 | Fixed | New photos must be `image/jpeg`, and a unit test covers PNG rejection. Stored PNG/WebP photos still read back. ADR-0019 states that the size check runs after IPC deserialization. |
| LK-8 | Fixed | The App.tsx effect cleanup calls `forgetWallpapers()`. `refreshWallpaper` checks the epoch and clears all photos. `refresh`, `refreshState` and `setTypingFor` are stable `useCallback([])`, so the cleanup only runs when the state changes. |
| LK-9 | Fixed | A failed photo read deletes its own cache entry. It is retried on the next store change, and there is no retry loop. |
| LK-10 | Fixed | The Ink rule (specificity 0,4,0) comes before the soft/minimal rules. `bubbleVars` sets `--sent-ink`, so a chat's colour applies in Ink. |
| LK-11 | Fixed | The look is carried over inside the `atomically` block. `COALESCE` keeps the new contact's own settings. `UPDATE OR IGNORE`, guarded by `LIKE 'photo:%'`, moves the photo only when the merged wallpaper is a photo; otherwise the trigger removes it. The new integration test passes. |
| LK-12 | Fixed | `app/scripts/contrast-check.mjs` runs from `pnpm lint`. Release CI uses Node 22, which supports `--experimental-strip-types`. Its background list is incomplete (LK2-1). |
| LK-13 | Fixed | Renamed to `.hue-swatches` / `.hue-swatch`, and the DESIGN.md §6 row is updated. |

### New findings

#### LK2-1: High. Custom accent text fails 4.5:1 on the surfaces it actually sits on [HIGH]
**Where:** `app/src/color.ts:38` (`DARK_BGS`), `:101`. The check in `app/scripts/contrast-check.mjs:20` inherits the same gap.

**Problem:**
- `DARK_BGS` holds Aurora dark `--bg-2` (16,19,49) and pure-black `--surface-3` (26,26,31). Pure-black `--surface-3` never carries accent text.
- Accent text does sit on lighter surfaces:
  - `.msg.in .reply { background: var(--surface-2); color: var(--accent) }` (base.css:385). This is the quoted sender's name in every received reply.
  - `.composer-ctx .reply` (app.css:82).
  - `.btn-ghost` and `.link-btn` on cards (`--surface-1`).
- Measured worst cases, all at hue 243:

  | Surface | Worst contrast | Hues below 4.5 |
  |---|---|---|
  | Aurora dark `--surface-2` `#1e2250` (the default style) | 3.91:1 | 114 |
  | Ink dark `--surface-2` `#1f1f25` | 4.27:1 | 65 |
  | Aurora dark `--surface-1` `#171a3d` | 4.37:1 | 43 |

- The presets pass on the same surfaces; for example Aurora `#a49dff` on `#1e2250` is 6.32:1.
- This is the same class of defect as LK-1. The commit and ADR-0019 now claim the accent keeps 4.5:1 "on every panel it sits on", and the lint check passes only because the list omits these surfaces.

**Fix:**
```ts
/** Every dark panel accent text sits on: Aurora --bg-2, --surface-1, --surface-2;
 *  Ink --surface-1, --surface-2; pure black --surface-2/3. */
export const DARK_BGS: Rgb[] = [[16, 19, 49], [23, 26, 61], [30, 34, 80], [26, 26, 31], [31, 31, 37]];
```
I verified this in the scratchpad: the worst case becomes 4.500 on Aurora `--surface-2`, with 0 failures on any surface that carries accent text. The light surfaces already pass (worst 4.575). Also update the ADR-0019 wording.

Better still, have `contrast-check.mjs` read the `--surface-1`/`--surface-2`/`--bg-2` hex values from `src/styles/tokens.css`, so a later token change cannot reopen the gap.

#### LK2-2: Medium. Arrow keys still open the file chooser on "Photo" [HIGH]
**Where:** `app/src/components/Look.tsx:154`.

**Problem:**
- Arrow navigation in a native radio group dispatches a simulated `click` on the newly selected radio. WebKit does this in `RadioInputType::handleKeydownEvent` (`dispatchSimulatedClick`), and Chromium does the same; React's radio `onChange` relies on exactly that.
- So `onClick={() => file.current?.click()}` still fires when a keyboard user arrows past "Photo". The key press counts as a user activation, so the OS file chooser opens and interrupts navigation.
- The code comment ("never as arrow keys pass by") and the DESIGN.md §6 row are therefore wrong.
- The photo is no longer deleted by mistake, because the confirm handles that.

**Fix:** take "pick a photo" out of the radio's activation:
```tsx
const viaArrow = useRef(false);
<div className="wp-tiles" role="radiogroup" … onKeyDownCapture={(e) => { viaArrow.current = e.key.startsWith("Arrow"); }}>
…
<input type="radio" … onClick={() => { if (viaArrow.current) { viaArrow.current = false; return; } file.current?.click(); }} />
```
Alternatively, and more simply, keep "Photo" as a radio that only selects, and add a separate `<button>` labelled "Choose photo…" that opens the chooser.

#### LK2-3: Low. The photo `data:` URL grows without pre-sizing, leaving unwiped copies [HIGH]
**Where:** `crates/client/src/service/look.rs:244-245`, and `:94`.

**Problem:**
- base64 0.23 `encode_string` pushes 1 KiB chunks into the `String` with `push_str` and never reserves space up front (checked in the vendored source).
- So a ~2–4 MiB URL is reallocated about 12 times, and each freed buffer keeps part of the photo's base64. This misses the pre-sized form that LK-6 asked for.
- Separately, the `TooLarge` return at L94 and the `_ => BadInput` arm drop the base64 `String` before it is wrapped in `Zeroizing`.

**Fix:**
```rust
let prefix = format!("data:{mime};base64,");
let mut url = String::with_capacity(prefix.len() + base64::encoded_len(data.len(), true)?);
url.push_str(&prefix);
STANDARD.encode_string(&*data, &mut url);
```
Here `?` stands for mapping the `None` result to `ClientError::Storage`. Also move `let b64 = Zeroizing::new(b64);` above the length check.

#### LK2-4: Low. Keyboard focus is lost after "Keep photo", and saves during a save are dropped silently [MEDIUM]
**Where:** `app/src/components/Look.tsx:168`, `:103`, `:124`.

**Problem:**
- "Keep photo" unmounts the alert along with the focused button, so focus falls to `<body>`. That is the same focus loss LK-3 set out to remove.
- Separately, `save()` returns at once while another save is in flight, for example a photo upload. A Dim or Blur release during that time is dropped, but the slider keeps showing the unsaved value. The resync effect only runs when `value.dim`/`value.blur` change.

**Fix:**
- Before calling `setReplacing`, store the focused radio in a ref: `const back = useRef<HTMLElement | null>(null); back.current = document.activeElement as HTMLElement`. On both buttons, call `back.current?.focus()` after closing.
- In `levels()`, when `saving.current` is set, reset the sliders: `setDim(value.dim); setBlur(value.blur)`. Alternatively, queue the latest levels and save them in the `finally`.

#### LK2-5: Low. The wallpaper pill override also catches hover and warning pills [HIGH]
**Where:** `app/src/styles/app.css:221`.

**Problem:**
- `button.sys-msg.call-line:hover` (specificity 0,3,1, app.css:140) outranks the new rule (0,3,0). Over a photo, hovering a call line brings back the translucent `--surface-glass-strong`.
- The new rule outranks `.sys-msg.warning` (0,2,0), so timer and key-warning notices lose their `--warning-soft` tint.

**Fix:**
```css
@media (hover: hover) { .chat-screen:has(> .chat-wallpaper) button.sys-msg.call-line:hover { background: var(--surface-3); } }
.chat-screen:has(> .chat-wallpaper) .sys-msg.warning { background: linear-gradient(var(--warning-soft), var(--warning-soft)), var(--surface-2); }
```

### Also checked and found correct
- **Contrast math:** `meta()` composites white at 0.86 alpha correctly. The script measures the exact hex values `bubbleVars`/`accentVars` produce, including `--sent-solid`/`--sent-ink` and the gradient midpoints.
- **Gradients:** luminance is convex along an sRGB line segment, so the lightest point of each gradient segment is a stop. Sampling the stops is sufficient for white text.
- **`useSliderCommit`:** the latest-callback ref avoids stale closures, and the listener is removed on cleanup.
- **Cache epoch:** a stale `refreshWallpaper` cannot repopulate the cache after a lock. A photo read still in flight is never re-cached once `photos.clear()` has run.
- **`accept_key_change`:** every statement runs inside one `atomically` SAVEPOINT. No `UPDATE` trigger interferes, and the `wallpaper_photos.owner` primary-key conflict is handled by `OR IGNORE`.
- **Rust boundary:** no `unwrap`/indexing on the IPC input, and nothing new is logged or reaches the network.

### Verdict: **FAIL**
LK2-1 is High: custom-accent text still drops to 3.91:1 in the default Aurora dark style, and the new lint check misses it. Fixing LK2-1 clears the gate. LK2-2 should go into the same round, because it leaves part of LK-3 open. LK2-3 to LK2-5 can follow.

### Action options
- **A.** Fix all of LK2-1 to LK2-5.
- **B (recommended).** Fix LK2-1 and LK2-2, then re-run `pnpm -C app lint` and re-review.
- **C.** Fix specific items.
- **D.** Report only.

Files: `/home/user/ataraxia/app/src/color.ts`, `/home/user/ataraxia/app/scripts/contrast-check.mjs`, `/home/user/ataraxia/app/src/components/Look.tsx`, `/home/user/ataraxia/app/src/styles/app.css`, `/home/user/ataraxia/crates/client/src/service/look.rs`, `/home/user/ataraxia/docs/REVIEW_REPORT.md`.

## Look (milestone 4.5) review, round 3 (2026-10-29)

**Verdict: PASS.** LK2-1 to LK2-5 are all fixed and every earlier LK fix still holds. There are no Critical or High findings. I found one Medium issue, LK3-1, which I recommend fixing before release: over a bright photo wallpaper, the in-chat banners, including the identity-key warning, become unreadable.

**Scope:** fix commit 2af205b, on top of 503a6bb and fdd85b5. I read every changed file and edited nothing. Line numbers are from the working tree; they match the commit for every file cited below.

The working tree also has uncommitted profile-picture work (ADR-0020). It does not touch `color.ts`, `contrast-check.mjs`, `Look.tsx` or the wallpaper rules:
- `look.rs`: only `image_mime` changed, from private to `pub(super)`.
- `app.css`: new rules appended at the end.
- `Chats.tsx`: only the `<Avatar>` props.

**Checks run**
- `pnpm -C app lint`: passes. Output: `lint: 22 files clean`, then `contrast: worst white 5.4293, meta 4.5001, accentDark 4.5001, accentLight 4.5001`.
- `pnpm -C app typecheck`: passes, 0 errors.
- `CARGO_INCREMENTAL=0 cargo test --offline -p veil-client --test look`: 2 passed (`wallpapers_and_chat_colours`, `a_key_change_keeps_the_chats_look`).
- Scratchpad runs on copies, with nothing in the repo touched:
  - all 360 hues against `--surface-3` and against `--accent-soft` laid over every panel;
  - chat text over a white or black photo at dim 0;
  - a copy of `contrast-check.mjs` run against altered copies of `tokens.css`.

### Status of the round 2 findings

| ID | Status | Notes |
|---|---|---|
| LK2-1 | **Fixed** | `DARK_BGS` and `LIGHT_BGS` now hold every 6-digit `--bg-0..2` and `--surface-1..2` value of Aurora dark and light, Ink dark and light, and pure black. I checked all 22 values against `tokens.css`. The worst accent is now 4.5001 in both themes. The new check script does fail when a 6-digit panel is missing (tested: exit 1). It has gaps, see LK3-2. |
| LK2-2 | **Fixed** | Choosing a file is now its own button, "Use a photo…" / "Choose another photo…" (`Look.tsx:175`). The "Your photo" radio only selects (`onChange` does nothing) and is shown only while a photo is in use. Arrow keys no longer reach anything that opens a file chooser. |
| LK2-3 | **Fixed** | The photo's base64 is wrapped in `Zeroizing` right in the `match` (`look.rs:90`). The `TooLarge` return, the decode error and the `_ =>` arm now all wipe it. The `data:` URL is sized up front with `base64::encoded_len(.., true)` plus the prefix. `encode_string` writes exactly that many bytes, so the string is never reallocated. If the length calculation overflowed, the photo would come back as `None` with no error; at 3 MiB that cannot happen. |
| LK2-4 | **Fixed** | "Keep photo" puts focus back on the element that had it (`back` ref, `:123`, `:185`). "Remove" moves focus to the radio just chosen (`:190`). A slider let go during another save now shows the saved value again (`:131-135`). One remaining focus drop is on the new button, see LK3-3. |
| LK2-5 | **Fixed** | Specificity checked. `.chat-screen:has(> .chat-wallpaper) .sys-msg.warning` is (0,4,0), above the base rule (0,3,0). The hover rule is (0,5,1), above `button.sys-msg.call-line:hover` (0,3,1). One note: no TSX renders `.sys-msg.warning` today (only `sys-msg` and `sys-msg call-line` at `Chats.tsx:195,235,239`), so the warning rule has no effect yet. That is harmless. |

### Earlier fixes, re-checked
- **LK-1, LK-12:** the lint check passes; worst meta 4.5001, worst white 5.43.
- **LK-2:** `useSliderCommit` and the skip-if-unchanged checks are unchanged.
- **LK-3:** the radios stay enabled, a ref guards against two saves at once, and leaving a photo asks first.
- **LK-4:** holds for notices and day separators, but other chat elements have the same problem (LK3-1).
- **LK-5:** `MAX_PICK_BYTES`, the 25 MiB limit, is still in place, and the canvas is still filled with `--bg-1` before drawing (`wallpaper.tsx:96,112`).
- **LK-6, LK-7:** the photo is still wiped and must still be JPEG.
- **LK-8, LK-9:** the cache epoch, `forgetWallpapers()` (App.tsx:94,128), and deleting a failed entry (`wallpaper.tsx:52,63`) are all present.
- **LK-10:** the Ink override is present (`app.css:210`).
- **LK-11:** the key-change carry-over SQL is present (`service.rs:3994`).
- **LK-13:** the `.hue-swatch*` classes are present.

All still hold.

### New findings

#### LK3-1: Medium. Over a photo wallpaper, chat banners and pure-black glass become unreadable [HIGH]
**Where:**
- The fix goes in `app/src/styles/app.css:221-223`.
- Affected elements: `app/src/screens/Chats.tsx:746` (`.chat-hdr.glass`), `:771` (ConnectionBar), `:772` (KeyWarning), `:773-776` (info banner with the "Compare safety numbers" link).
- Their backgrounds: `base.css:327`, `:329`, `:340`, `:461` and `tokens.css:417-418`.

**Problem:**
- `.chat-wallpaper` covers all of `.chat-screen` (`inset: 0`), so the header, the banners and the composer all sit on the photo.
- The LK-4 fix made only `.sys-msg` and `.day-sep` opaque. Banner tints are translucent: `--warning-soft` is 14 % in dark mode and `--accent-soft` is 10–18 %. Pure black's glass is 5–8 % white.
- Measured at dim 0, which is the default:

  | Element | Background | Contrast |
  |---|---|---|
  | KeyWarning heading "Is this really X?" (`--warning`), dark | white photo | 1.43:1 |
  | KeyWarning body text, dark | white photo | 1.79:1 |
  | Info banner text, light | black photo | 2.11:1 |
  | Header name and composer text, pure black | white photo | 1.11:1 |
  | Header text, Aurora dark | white photo | 4.44:1 |

- KeyWarning is the INV-ID-2 identity-key prompt. A security warning the user cannot read in their own chat matters in this app.
- This dates from fdd85b5 and is the same class as LK-4 (which was Medium), so I rate it Medium.

**Fix:** put the same opaque base under each tint, as LK2-5 did:
```css
.chat-screen:has(> .chat-wallpaper) > .banner.info,
.chat-screen:has(> .chat-wallpaper) > [role="alert"] > .banner.info { background: linear-gradient(var(--accent-soft), var(--accent-soft)), var(--bg-1); }
.chat-screen:has(> .chat-wallpaper) > [role="alert"] > .banner.warning,
.chat-screen:has(> .chat-wallpaper) > .conn-bar.reconnecting { background: linear-gradient(var(--warning-soft), var(--warning-soft)), var(--bg-1); }
.chat-screen:has(> .chat-wallpaper) > .chat-hdr { background: var(--bg-2); }
.chat-screen:has(> .chat-wallpaper) .composer .box { background: var(--surface-1); }
```
Also extend the DESIGN.md §6 wallpaper row ("over a wallpaper, notices and day separators get an opaque pill") to cover banners, the header and the composer.

#### LK3-2: Low. The token check skips any panel not written as 6-digit hex, and never checks the theme [HIGH]
**Where:** `app/scripts/contrast-check.mjs:12-14`.

**Problem:**
- The pattern `/--(?:bg-[0-2]|surface-[12]):\s*(#[0-9a-fA-F]{6})/` silently skips any value in another form. In my tests the script still exited 0 when Aurora `--surface-2` was written as `#2a5`, `rgb(38 42 92)` or `var(--surface-3)`.
- It already skips two panels today: pure black `--bg-0` and `--bg-1` are `#000`. They are harmless, being the darkest panels, but they show the gap.
- Dark and light are merged into one `known` list. So a light panel set to a dark-list colour passes (tested: setting Ink light `--surface-1` to `#1e2250` exits 0), although the light accent is never checked against it.
- ADR-0019 says the check "fails if color.ts misses one". That is true only for 6-digit hex.

**Fix:** match every declaration of these tokens, refuse any value that is not hex, and check it against the list for its own theme:
```js
const hexRgb = (v) => { const m = v.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i); if (!m) return null;
  const h = m[1].length === 3 ? [...m[1]].map((c) => c + c).join("") : m[1]; return rgb(`#${h}`); };
const bad = [];
for (const [, sel, body] of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
  const dark = !/data-theme="light"/.test(sel);
  for (const [, tok, val] of body.matchAll(/--(bg-\d+|surface-[12]):\s*([^;]+);/g)) {
    const c = hexRgb(val.trim());
    const list = (dark ? DARK_BGS : LIGHT_BGS).map((x) => x.join(","));
    if (!c || !list.includes(c.join(","))) bad.push(`${sel.trim()} --${tok}: ${val.trim()}`);
  }
}
if (bad.length) { console.error(`contrast: panels not covered by color.ts:\n${bad.join("\n")}`); process.exit(1); }
```
Add `[0, 0, 0]` to `DARK_BGS` so pure black `--bg-0` and `--bg-1` are listed.

#### LK3-3: Low. Disabling the photo button while it saves loses keyboard focus [MEDIUM]
**Where:** `app/src/components/Look.tsx:175`.

**Problem:**
- When the file chooser closes, focus returns to the button.
- `pick()` then calls `save()`, which sets `busy`. The button becomes disabled while it has focus, and browsers move focus to `<body>`.
- This is the same pattern that `Look.tsx:90-91` and LK-3 removed from the radios.
- I have not checked WebKitGTK's exact blur behaviour, hence MEDIUM confidence.

**Fix:**
```tsx
<button className="btn btn-secondary btn-block" type="button" aria-disabled={busy}
  onClick={() => { if (!saving.current) file.current?.click(); }}>
```

#### LK3-4: Low. "Remove" fails silently while another save is running [HIGH]
**Where:** `app/src/components/Look.tsx:186-190`, and `:104-105`.

**Problem:**
- The radios stay enabled during a save, for example while a new photo uploads, so the photo prompt can still be opened and "Remove" clicked.
- `apply(p)` reaches `save()`, which returns at once because `saving.current` is set.
- The dialog closes as if the photo were removed, but it is not. There is no message, and `.then` still moves focus to radio `p`, which is unchecked.

**Fix:** have `save` report whether it ran, and move focus only on success:
```tsx
async function save(f: () => Promise<void>): Promise<boolean> {
  if (saving.current) { setError("Wait for the current change to finish."); return false; }
  … try { await f(); return true; } catch (e) { …; return false; } finally { … }
}
// Remove:
void apply(p).then((ok) => { if (ok) document.querySelector<HTMLInputElement>(`input[name="${name}"][value="${p}"]`)?.focus(); else back.current?.focus(); });
```

### Also checked and found correct
- **`color.ts`:**
  - No accent text sits on `--surface-3`. I grepped every `color: var(--accent)` rule; on Aurora dark `--surface-3` the accent would be 3.87:1, but nothing puts it there.
  - Accent on `--accent-soft` measures as low as 3.83:1, but every such use is an icon (`.row-icon.accent`, `.ficon`, `.banner.info > .icon`), which needs only 3:1. `.chip.accent` is not used in any TSX.
- **`contrast-check.mjs`:** it reads `src/styles/tokens.css`, which matches `design/tokens.css` apart from font URLs. It runs before the hue loop and exits 1 when a 6-digit panel is missing.
- **`Look.tsx`:**
  - "Keep photo" focuses synchronously, before the banner unmounts, so focus is not lost on the way.
  - The selector in `querySelector` is built only from `wp-<number>` and the preset union, so it cannot be injected.
  - The slider reset compares against the saved `value`, so it cannot overwrite a newer value.
- **`look.rs`:** nothing new is logged, nothing panics, and nothing is indexed on IPC input.

### Verdict: **PASS**
There are no Critical or High findings. LK3-1 should be fixed before release, because over a bright photo it hides the identity-key warning. LK3-2 to LK3-4 can follow.

### Action options
- **A.** Fix LK3-1 to LK3-4.
- **B (recommended).** Fix LK3-1 and LK3-2, then re-run `pnpm -C app lint`.
- **C.** Fix specific items.
- **D.** Report only. The gate passes as it stands.

Files: `/home/user/ataraxia/app/src/styles/app.css`, `/home/user/ataraxia/app/scripts/contrast-check.mjs`, `/home/user/ataraxia/app/src/components/Look.tsx`, `/home/user/ataraxia/app/src/color.ts`, `/home/user/ataraxia/app/src/screens/Chats.tsx`, `/home/user/ataraxia/app/src/styles/base.css`, `/home/user/ataraxia/app/src/styles/tokens.css`, `/home/user/ataraxia/crates/client/src/service/look.rs`.
