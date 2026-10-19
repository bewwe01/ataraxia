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
