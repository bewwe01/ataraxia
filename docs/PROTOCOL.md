# Veil: Protocol specification (v1)

Status: **Phase 1 draft, awaiting approval.** Normative words (MUST, MUST NOT, SHOULD) follow RFC 2119. Every MUST that matters for security is tracked as an invariant in [`INVARIANTS.md`](INVARIANTS.md) with the test that proves it. Do not change this document without updating those tests.

Veil composes existing, reviewed constructions; **it invents no cryptography**:

| Purpose | Construction | Implementation |
|---|---|---|
| Initial key agreement | **PQXDH** (X25519 + ML-KEM-1024/Kyber1024, signed prekeys) | `libsignal-protocol` v0.105.0 |
| Message encryption | **Triple Ratchet** = Double Ratchet + **SPQR** (sparse post-quantum ratchet) | `libsignal-protocol` (+ `spqr` v1.6.0) |
| Sender anonymity towards the relay | **Sealed sender v1** | `libsignal-protocol` |
| Safety numbers | libsignal **Fingerprint** (numeric + scannable) | `libsignal-protocol` |
| Invite sealing, vault key wrapping | **XChaCha20-Poly1305** (192-bit random nonces) | RustCrypto `chacha20poly1305` |
| Attachments | **STREAM** (online AEAD, chunked; Hoang et al.) with XChaCha20-Poly1305, `StreamBE32` | RustCrypto `aead::stream` |
| Key derivation | **HKDF-SHA-256** | RustCrypto `hkdf`, `sha2` |
| Passphrase hardening | **Argon2id** | RustCrypto `argon2` |
| Mailbox authentication | **Ed25519** signatures | `ed25519-dalek` (strict verification) |
| Transport | **TLS 1.3** only, relay SPKI pinned | `rustls` |

Domain-separation labels are ASCII strings starting `veil/v1/…`. All integers are big-endian unless noted.

---

## 1. Identities and addresses

- **Identity key**: a libsignal `IdentityKeyPair` (Curve25519; XEdDSA signatures) generated on-device at onboarding. It never leaves the device except inside an encrypted backup (§12).
- **Address**: `addr = "v1:" || hex(SHA-256("veil/v1/addr" || identity_pub))[0..40]`. This is the libsignal `ProtocolAddress` name; the device ID is fixed to `1` in v1. Multi-device later uses device IDs 2…127. Addresses are **derived from keys**, so there are no usernames, phone numbers or directory.
- **Identity fingerprint shown in the UI** ("Your identity · 7F3A 91C2 …"): the first 16 bytes of `SHA-256("veil/v1/fp" || identity_pub)`, hex in groups of 4. Display only; verification uses safety numbers (§5).

## 2. Mailboxes (what the relay knows instead of identities)

A **mailbox** is where others deposit envelopes for you.

- `mailbox_id`: 32 random bytes. It is unrelated to the identity key, and the relay never learns which identity owns it (INV-META-1).
- `mailbox_auth`: a fresh **Ed25519 key pair per mailbox**, separate from the identity key. The relay stores only `mailbox_auth_pub`.
- **Fetching / subscribing** requires a challenge-response: relay sends a 32-byte `nonce`; client signs `"veil/v1/mbox-auth" || relay_spki_hash || mailbox_id || nonce || unix_secs` (±120 s skew). The relay MUST use strict Ed25519 verification and single-use nonces.
- **Delivery tokens (anti-spam without identity).**
  - For each contact, the owner creates a 32-byte random `delivery_token` and registers `SHA-256("veil/v1/tok" || token)` with the relay for that mailbox.
  - A sender MUST present the token to deposit. The relay checks membership and rate-limits **per token**, never per IP.
  - Blocking a contact removes their token; the relay then refuses their deposits.
  - The relay learns how many tokens a mailbox has (≈ number of contacts). Clients pad this with dummy tokens up to the next multiple of 8 (THREAT_MODEL §5).
- **Rotation.** Every 7 days, and on demand, the owner creates a new mailbox and sends each contact a `MailboxUpdate` (§7) with a new token. The old mailbox is drained, then deleted after a 7-day grace period. Rotation breaks long-term linkability of mailbox IDs at the relay.

## 3. Prekeys

**Prekey bundles never reach the relay in readable form.** A bundle contains the identity key, so uploading one under a mailbox would let the relay link an identity to a mailbox (INV-META-1). Instead:

- Every invite (§4) carries its **own** PQXDH bundle, sealed inside the invite package:
  - one one-time EC prekey;
  - one signed EC prekey;
  - one **signed one-time Kyber1024** prekey;
  - the identity key.
  
  All ids are random 32-bit values. The inviter refuses to create an invite whose ids collide with existing keys.
- There are no last-resort keys. A redemption consumes the invite's one-time keys (libsignal deletes the EC one-time key; Veil deletes the Kyber key on use), and the inviter then deletes the signed prekey and the invite record. Expired or revoked invites have all their prekeys deleted (`sweep_expired_invites`, `revoke_invite`).
- **Re-keying** (after a restore from backup, §12) uses a **standing re-key invite** that each side hands the other inside its E2EE `ContactIntro.rekey`. It is consumed like any invite and replaced afterwards.
- Clients MUST verify both prekey signatures (libsignal does; Spike A and the session tests show a forged Kyber signature is rejected). They MUST reject any session message below libsignal message version 4, and any `PreKeySignalMessage` without a Kyber prekey id. **No downgrade to non-PQ X3DH** (INV-CRY-3).

## 4. Invites and pairing

### 4.1 Invite payload (QR code or link)

Fixed binary layout, big-endian, then base64url without padding (`crates/core/src/invite.rs`):

```
v (1) = 1 | mode (1: 0 = in person, 1 = remote) | ik (33) | id (16) | secret (32)
  | expires_at (u64) | relay_spki_sha256 (32) | url_len (1) | relay_url (url_len, "wss://…", ≤ 200 B)
link = "veil://i/" || base64url(…)        // ≈ 230 characters → QR version ≈ 10, error correction M
```

Parsing is strict:
- the length is checked before decoding (≤ 512 characters);
- unknown versions are rejected (`UnsupportedVersion`);
- trailing bytes are rejected;
- the URL must be printable ASCII starting `wss://`.

### 4.2 Publishing

```
prk        = HKDF-Extract(salt = "veil/v1/invite", ikm = secret)
k_package  = HKDF-Expand(prk, info = "veil/v1/invite-key"   || id, 32)
k_proof    = HKDF-Expand(prk, info = "veil/v1/invite-proof" || id, 32)
package    = protobuf { registration_id, prekey/signed-prekey/kyber-prekey ids, public keys and signatures,
                        identity_key, mailbox_id, delivery_token }, ISO/IEC 7816-4-padded to exactly 4096 bytes
sealed     = nonce (24, random) || XChaCha20-Poly1305(k_package, nonce, aad = "veil/v1/invite" || id || ik, package)
```

`sealed` is exactly **4136 bytes**. The relay stores it under `id` with **TTL = expires_at** and **deletes it on first successful fetch** (single use, INV-PAIR-2). It never sees `secret`, so it can read neither the bundle nor the identity key. The inviter stores only `k_proof`, the prekey ids, the expiry and the mode, not the secret.

### 4.3 Redeeming

1. Parse the link. Fetch `sealed` by `id` from the pinned relay and open it with `k_package`. Any failure means "invalid or expired"; show a generic error.
2. MUST check `package.identity_key == Invite.ik`. The AEAD's associated data already binds the package to `ik` and `id`, and this explicit check makes the binding visible (INV-PAIR-1).
3. Record the inviter's identity, then run libsignal `process_prekey_bundle` (signature checks, PQXDH).
4. Send the first message: a sealed-sender `PreKeySignalMessage` (§6) to the inviter's mailbox, using the package's delivery token. Its `Content` is:

   ```
   ContactIntro { mailbox_id, delivery_token, display_name?, invite_id = id,
                  invite_proof = HMAC-SHA-256(k_proof, "veil/v1/invite-proof" || id || redeemer_identity_key),
                  rekey? }
   ```
5. The inviter's `open` sees an unknown sender and proceeds **only if all of these hold**:
   - the message is a `PreKey` message whose EC, signed and Kyber prekey ids are exactly those of one live, unexpired invite;
   - inside a store transaction, the sender's identity is recorded *provisionally* and the message decrypts;
   - the content is a `ContactIntro` naming that invite;
   - the proof verifies in constant time against the sender's authenticated identity key (INV-PAIR-4).

   Then the invite is consumed and the transaction commits; otherwise everything rolls back. A relay that knows `id` but not `secret` can forge neither the decryption (it never saw the one-time public keys) nor the proof.
6. The inviter replies with its own `ContactIntro` (no invite fields) over the new session.

### 4.4 Verification state

`crates/core/src/trust.rs` implements this as a pure state machine and tests it exhaustively over every state and event:

| How the contact was added | Initial state |
|---|---|
| **In person, mutual scan**: each side scanned the other's QR within the same pairing session, and each side checks that the session's remote identity == the `ik` it scanned | **Verified** |
| Remote link, or one-sided scan | **Unverified**, until safety numbers are compared (§5) |

The UI MUST show these states exactly as designed (verified shield vs "Not verified"; design §1).

A leaked invite link lets a third party redeem it. Mitigations:
- the inviter sees "New contact via invite link · not verified", with the redeemer's safety number;
- invites are single use with a short expiry (≤ 7 days, default 24 h);
- the user can revoke an invite, which deletes its prekeys locally and its `id` at the relay.

## 5. Safety numbers and key changes

- Use libsignal `Fingerprint::new(version = 2, iterations = 5200, local_id = addr_local, local_key, remote_id = addr_remote, remote_key)`.
- Displayable: **60 digits** shown as 12 groups of 5. Scannable: the libsignal protobuf, compared in constant time.
- **Key changes are structurally impossible in place.** An address is a hash of the identity key (§1), so a different key is a different address and therefore a different contact. A contact who reinstalls Veil, or anyone impersonating them, arrives as a **new, unverified contact** via a new invite. The store's identity policy is exact-match-only and never records or overwrites a key on libsignal's behalf, which keeps this true even if libsignal's internals change (INV-ID-2).
- **The UI's "safety number changed" flow** covers the case where a new identity claims to be an existing contact, for example a matching display name after a reinstall:
  - the client MUST NOT merge it into the old conversation automatically;
  - it shows the key-changed warning;
  - sending stays paused until the user compares safety numbers with the new identity and explicitly links them;
  - a link never inherits "verified": the trust state machine's `IdentityChanged → ChangeAccepted` path always lands in *Unverified*.

## 6. Envelopes (what crosses the relay)

### 6.1 Sealing

1. Validate, then serialize `Content` (§7) with `prost`.
2. Pad with ISO/IEC 7816-4 (`0x80` then `0x00…`) to the next multiple of 256 bytes (always at least one padding byte).
3. Wrap in sealed sender v1 with a **self-issued sender certificate** (ADR-0006), issued per message:
   - a fresh ephemeral signer key;
   - `ServerCertificate { key_id = 1, key = signer_pub }` signed by the sender's **identity key** (the sender is its own trust root);
   - `SenderCertificate { sender_uuid = address, device_id = 1, key = identity_pub, expires = now + 30 days }` signed by the signer.
   
   `message_encrypt` encrypts the padded content with the libsignal session (Triple Ratchet). The result is wrapped in an `UnidentifiedSenderMessageContent` and sealed to the recipient's identity key with `sealed_sender_encrypt_from_usmc`. This is the same composition as libsignal's `sealed_sender_encrypt`, with one difference: the USMC's `groupId` field (unused by Veil) carries zero filler bytes. Their count is chosen so that the sealed output is exactly `bucket − 1` bytes for the smallest bucket that fits. When a protobuf varint boundary makes one size unreachable, the `contentHint` field is set as well (+2 bytes). Both fields are inside the sealed-sender encryption and are ignored on receipt.
4. Frame: `version (1) = 2 || sealed`, with the total exactly one of {**1 KiB, 4 KiB, 16 KiB, 64 KiB**} (INV-META-3). There is no length field and no padding outside the encryption, so within a bucket every relay-visible length is identical whatever the content size or message type (test `relay_learns_only_the_bucket`). Because a PreKey message carries a 1569-byte ML-KEM ciphertext, it never fits 1 KiB: a short first message is visible as 4 KiB rather than 1 KiB. Larger payloads MUST go through attachments (§9).

   *Changed after review round 1 (H1).* Framing v1 had a plaintext `len (u32 BE)` field and trailing zero padding, which revealed the exact sealed size and the message type.

### 6.2 Unsealing (recipient)

Every step runs inside a store transaction that commits only on success, so **rejected input never changes state** (INV-STATE-1).

1. Strict unframe:
   - the size is exactly a bucket;
   - the framing version is 2.
2. The sealed payload must start with exactly `0x11` (sealed sender v1; v2 and malleated low nibbles are refused). Then `sealed_sender_decrypt_to_usmc`. libsignal checks, in constant time, that the certificate key == the static key authenticated by the outer ECDH.
3. Derive the sender address from that key, then require:
   - the certificate names exactly that address and device 1;
   - it validates with that key as trust root and is unexpired;
   - the sender is not ourselves.
4. Require message version ≥ 4; for `PreKey` messages also require a Kyber prekey id.
5. Known contact (stored key == sender key): decrypt with libsignal, which applies the ratchet, replay and order checks. Unknown sender: only the invite-redemption path of §4.3 step 5 is allowed; anything else is dropped (`UnknownSender`).
6. Unpad, strict canonical `prost` decode (re-encoding must reproduce the exact bytes), and field validation. Drop on any error; no partial processing.

### 6.3 Wire form to the relay

```
Deposit { v: 1, mailbox_id: 32 B, token: 32 B, envelope: bytes (exactly one bucket size) }
```

The relay stores `{ mailbox_id, server_seq, received_at (rounded to the minute), envelope }` with a TTL (default 14 days). **No sender, no IP, no User-Agent** (INV-META-2).

## 7. Content messages (inside the envelope)

`Content` is a protobuf `oneof`:

| Type | Fields (summary) | Notes |
|---|---|---|
| `Text` | `id`, `body ≤ 64 KiB UTF-8`, `reply_to?`, `expire_timer?` | rendered as **plain text** only |
| `Reaction` | `target_id`, `emoji (≤ 8 code points)`, `remove` | |
| `Edit` | `target_id`, new `body` | best effort; history not kept |
| `Delete` | `target_id` | best-effort remote delete |
| `Attachment` | `id`, `blob_id`, `key (32 B)`, `nonce_prefix (19 B)`, `ciphertext_sha256`, `size`, `padded_size`, `mime`, `name?`, `thumbnail? (≤ 8 KiB, inline, encrypted with the message)`, `voice_note?` (duration, waveform) | §9 |
| `Receipt` | `kind: delivered \| read`, `ids[]` | delivered always; read only if both sides opted in |
| `Typing` | `started \| stopped` | only if opted in |
| `TimerUpdate` | `seconds (0 = off)` | per conversation |
| `Call` | `call_id`, one of `Offer{sdp}`, `Answer{sdp}`, `Ice{candidates[]}`, `Hangup{reason}`, `Busy` | §8 |
| `ContactIntro` | `mailbox_id`, `delivery_token`, `display_name?`, `invite_id?` + `invite_proof?` (both or neither), `rekey?` | §3, §4 |
| `MailboxUpdate` | `new_mailbox_id`, `new_token`, `relay?` | §2 |
| `SessionReset` | — | after restore (§12) |

Every message has a random 16-byte `id`, and `sent_at` is set by the sender but **never trusted for ordering security**. Duplicate `id`s are ignored (idempotent processing; libsignal already rejects ciphertext replays).

## 8. Calls

- **Signaling** (offer, answer, ICE, hangup) travels only as `Content::Call` over the E2EE session. The relay sees ordinary padded envelopes (INV-NET-3).
- **DTLS identity binding.**
  - The SDP carries `a=fingerprint:sha-256`, and the WebRTC stack refuses a DTLS peer whose certificate doesn't match. Because the SDP arrives authenticated by the session, a relay or TURN operator cannot substitute its own DTLS endpoint (INV-NET-4).
  - Clients MUST reject SDP without a `sha-256` fingerprint, with more than one fingerprint, or with `a=setup` inconsistent with the offer/answer role.
- **Relay-only mode (default).**
  - The peer connection uses `iceTransportPolicy: "relay"`.
  - Independently, **Rust filters every outgoing SDP and candidate**: any `a=candidate` / `candidate:` line whose `typ` ≠ `relay` is removed before encryption.
  - Incoming non-relay candidates are dropped too.
  - Kept candidates have `raddr`/`rport` rewritten to `0.0.0.0 0`. Even a relay candidate's related address can reveal our reflexive or local IP.
  - Tests assert that no non-relay candidate is ever sent (INV-NET-1, the brief's key test).
- **Direct mode** (per-contact opt-in, warned):
  - host/srflx candidates are allowed, but private, link-local, CGNAT and ULA addresses (RFC 1918, 169.254/16, 100.64/10, fc00::/7, fe80::/10) and mDNS `.local` hosts are filtered;
  - LAN pairing mode is the only exception.
- **TURN credentials.**
  - Clients authenticated to a mailbox may request credentials from the relay.
  - Format (coturn `use-auth-secret`): `username = "<expiry_unix>:<16 random hex>"`, `credential = base64(HMAC-SHA1(turn_secret, username))`, TTL 1 hour, rate-limited per mailbox.
  - The username contains **no identity or mailbox ID**.
- **Media** is DTLS-SRTP end to end between peers. TURN relays ciphertext only.

## 9. Attachments (incl. voice notes)

1. Generate a random 32-byte `key` and a 19-byte `nonce_prefix`.
2. Pad the plaintext with **Padmé** (bounded size leakage), then split into 64 KiB chunks.
3. Encrypt with `EncryptorBE32<XChaCha20Poly1305>`. The last chunk uses `encrypt_last`, so truncation, reordering and chunk swapping are detected (INV-ATT-1/2).
4. Upload to the relay blob store under a random 32-byte `blob_id`.
   - Uploads are **resumable** by chunk index: the client re-sends the ciphertext it already stored, and never re-encrypts (the chunk encryptor is private, so a changed file cannot reuse a nonce; review round 1, L4).
   - Each upload uses a one-time capability `upload_token` obtained with mailbox auth.
   - Blobs expire (default 30 days).
5. Send `Content::Attachment` containing the key material. The recipient downloads, checks `SHA-256(ciphertext) == ciphertext_sha256` *before* decrypting, then decrypts chunk by chunk, writing **only to the encrypted attachment store** and never to plaintext temp files (INV-REST-4).

## 10. Disappearing messages

- A per-conversation timer is set with `TimerUpdate`.
- Each `Text`/`Attachment` carries the effective `expire_timer`. The countdown starts on **read** for received messages and on **send** for own messages.
- Expired rows are deleted, attachment keys zeroized, and blob files deleted. A background sweep runs at least once a minute while unlocked, and at unlock.
- Honest limits (THREAT_MODEL §4): recipients can copy, screenshot or modify their client. The relay's own TTL is independent.

## 11. Receipts, typing, and drop detection

- **Delivery receipts** are always sent: the brief requires clients to detect dropped messages. A sender marks a message "not delivered" after 72 hours without a receipt and offers a retry.
- **Read receipts** and **typing indicators** are opt-in and symmetric: you only get them if you send them. Default off.
- The relay assigns a per-mailbox `server_seq`. Gaps seen by the owner trigger a re-fetch. A relay that silently drops messages is detectable through missing delivery receipts, not preventable.

## 12. Local vault (data at rest)

- **DB key**: 32 random bytes, used as the SQLCipher key.
- **KEK**, from two factors:
  - `pw = Argon2id(passphrase, salt 16 B, m = 256 MiB / t = 3 / p = 1 on desktop; m = 64 MiB / t = 4 / p = 1 on Android)`. Tuning is benchmarked per device class and recorded in the vault header.
  - `dev = 32 random bytes held by the OS keystore`:
    - Android: wrapped by a non-exportable AES-256-GCM key in Android Keystore, StrongBox when present;
    - desktop: Keychain / DPAPI-backed Credential Manager / Secret Service.
  - `KEK = HKDF-SHA-256(ikm = pw || dev, salt = vault_id, info = "veil/v1/kek")`.
- **Vault header** (unencrypted file, exactly 124 bytes, `crates/core/src/vault.rs`): `"VEILVLT" | v=1 | vault_id (16) | m_kib, t, p (u32 BE each) | salt (16) | nonce (24) | XChaCha20-Poly1305(KEK, nonce, aad = all preceding header bytes, DB key) (48)`.
  - The Argon2 parameters are authenticated, so lowering them in the header only makes unlocking fail.
  - New vaults may not use less than **m = 19 MiB, t = 2** (OWASP's Argon2id minimum); defaults are higher.
  - No vault may use more than **m = 512 MiB, t = 8, p = 4**. This ceiling applies when opening too, and is checked before Argon2 runs, so a tampered header cannot force a huge allocation or hours of CPU (review round 1, L1).
  - Passphrases are limited to 1–1024 bytes, UTF-8 as entered (the UI normalises to NFC).
- **Biometric unlock** (optional) releases `dev` plus a passphrase-derived key cached in the keystore. The passphrase is required after every restart (design copy), so biometrics only guard warm unlocks.
- **Auto-lock** zeroizes the DB key and session caches in memory.
- **Panic wipe**: delete the keystore entry → overwrite and delete the vault header → delete the DB and attachment store. Destroying `dev` and the header crypto-shreds everything, even if file deletion is imperfect on flash storage (INV-REST-3).
- **Backup**:
  - `XChaCha20-Poly1305(Argon2id(backup_passphrase, m = 512 MiB / t = 4), archive)`, streamed with STREAM;
  - contents: identity key, contacts, verification states, messages and attachments;
  - **ratchet sessions are deliberately excluded**. Restoring old ratchet state would reuse message keys, so after a restore every contact gets a `SessionReset` and a fresh PQXDH, and the UI notes it.

## 13. Versioning and downgrade resistance

- Every wire structure carries `v`. Clients and relay reject unknown versions and versions below `min_supported` (INV-CRY-3).
- Session messages MUST be libsignal message version ≥ 4 (PQ), and pre-Kyber bundles are rejected.
- The relay key is pinned per relay (SPKI SHA-256 from the invite or manual entry). A mismatch is a hard error, never a prompt-to-continue (INV-NET-2).

## 14. Limits (enforced on both sides)

| Item | Limit |
|---|---|
| Envelope | exactly one of 1 / 4 / 16 / 64 KiB |
| Text body | 64 KiB |
| Attachment | 100 MiB (v1), 64 KiB chunks |
| Envelopes per mailbox held by relay | 10 000, oldest first dropped (detected via `server_seq`) |
| Deposits per token | 60/min burst, 600/hour |
| WebSocket frame | 80 KiB; idle timeout 90 s; handshake timeout 10 s |
| Invite TTL | ≤ 7 days (default 24 h) |
| Clock skew accepted | ±120 s for auth; message timestamps never security-relevant |
