# Veil: Protocol specification (v1)

Status: **v1. Phase 1 approved; implemented in `crates/core` (Phase 2) and in `crates/wire` + `crates/relay` (Phase 3).** Normative words (MUST, MUST NOT, SHOULD) follow RFC 2119. Every MUST that matters for security is tracked as an invariant in [`INVARIANTS.md`](INVARIANTS.md) with the test that proves it. Do not change this document without updating those tests.

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

**Randomness.** Every secret of an invite comes from the RNG passed to `create_invite`: the invite secret and id, the one-time EC prekey, the signed prekey, the **ML-KEM (Kyber1024) prekey**, and the nonce. Veil generates the Kyber key with `kem::KeyPair::generate(…, rng)` and signs it with the identity key, following the same steps as libsignal's `KyberPreKeyRecord::generate`, which would use its own OsRng. Callers MUST pass an OS-seeded CSPRNG (`OsRng` / `rand::rng()`). Seeded RNGs are for tests and fuzzing only. A weak RNG here would now also weaken the post-quantum layer (review round 5, R5-4; pinned by `pairing_tests::invite_keys_come_only_from_the_callers_rng`).

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
   
   `message_encrypt` encrypts the padded content with the libsignal session (Triple Ratchet). The result is wrapped in an `UnidentifiedSenderMessageContent` and sealed to the recipient's identity key with `sealed_sender_encrypt_from_usmc`. This is the same composition as libsignal's `sealed_sender_encrypt`, with one difference: the USMC's `groupId` field (unused by Veil) carries zero filler bytes. Their count is chosen so that the sealed output is exactly `bucket − 1` bytes for the smallest bucket that fits with at least 2 bytes to spare. The filler field itself needs 2 bytes, so a message that would leave 0–1 bytes of slack moves to the next bucket. When a protobuf varint boundary makes one size unreachable, the `contentHint` field is set as well (+2 bytes). Both fields are inside the sealed-sender encryption and are ignored on receipt.
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

### 6.3 Client ↔ relay wire protocol

Defined in `crates/wire` (shared by client and relay).

**Transport.**
- WebSocket over **TLS 1.3 only** (rustls; no TLS 1.2, no plaintext mode).
- The client pins the SHA-256 of the relay's `SubjectPublicKeyInfo` and trusts no CA. A mismatch is a hard failure (INV-NET-2).
- Binary frames only; a text frame closes the connection.

**Frames.**
- Each WebSocket message is one protobuf frame:
  - client → relay: `ClientFrame { v = 1, id, oneof req }`;
  - relay → client: `ServerFrame { v = 1, id, oneof resp }`, where `id` echoes the request, and `id = 0` marks a push (`NewEnvelopes { mailbox_id, last_seq }`).
- Decoding is strict on both sides (`decode_strict`):
  - size is checked first: client frames ≤ `MAX_CLIENT_FRAME` (one blob chunk + 1 KiB), server frames ≤ `MAX_FRAME`;
  - the bytes must re-encode identically (unknown, duplicate and out-of-order fields, and non-minimal varints, are refused);
  - `v` must be 1 (otherwise `Unsupported`);
  - every field is validated: ids exactly 32 or 16 bytes, envelopes exactly a bucket, `limit ≤ 32`, ≤ 64 token changes, chunk sizes, and so on.
- A request that fails validation gets `Error { Malformed }` and changes nothing.

**Errors.** `Malformed`, `Unauthorized`, `NotFound`, `RateLimited`, `QuotaExceeded`, `Conflict`, `Unsupported`, `Internal`. Unknown mailbox and wrong token both answer `Unauthorized`, so a depositor cannot probe which mailboxes exist.

| Request | Auth | Effect |
|---|---|---|
| `CreateMailbox { mailbox_id, auth_pub }` | none (per-connection limit, then relay-wide limit spent only by requests that would succeed) | registers the mailbox's Ed25519 key |
| `Challenge { mailbox_id }` → `Challenge { nonce }` | none | single-use 32-byte nonce, bound to this connection and mailbox (≤ 64 outstanding) |
| `Authenticate { mailbox_id, unix_secs, signature }` | signs §2 message | marks the mailbox authenticated **on this connection** (≤ 64 per connection) and subscribes it to pushes. Every later use re-checks that the mailbox still has the key it was authenticated with, so deleting a mailbox revokes all connections. Pushes go only to connections authenticated with the mailbox's current key |
| `UpdateTokens { mailbox_id, add[], remove[] }` | mailbox | registers/removes `SHA-256("veil/v1/tok" ‖ token)` (≤ 512 per mailbox) |
| `Deposit { mailbox_id, token, envelope }` | delivery token | stores the envelope, pushes `NewEnvelopes` to subscribed connections |
| `Fetch { mailbox_id, after_seq, limit ≤ 32 }` → `Envelopes { items[], last_seq }` | mailbox | `items` = `{ seq, received_minute, envelope }`, oldest first |
| `Ack { mailbox_id, up_to_seq }` | mailbox | deletes envelopes with `seq ≤ up_to_seq` |
| `DeleteMailbox { mailbox_id }` | mailbox | deletes mailbox, tokens and envelopes |
| `PutInvite { mailbox_id, invite_id, sealed, expires_at }` | mailbox | stores a sealed invite package (§4.2), TTL capped at 7 days |
| `TakeInvite { invite_id }` → `Invite { sealed }` | none (the id is the capability) | returns **and deletes** it atomically (INV-PAIR-2) |
| `BlobUploadToken { mailbox_id }` → `UploadToken { token }` | mailbox | one-time 32-byte upload capability (§9), relay stores only `SHA-256("veil/v1/upload" ‖ token)` |
| `BlobPut { token, blob_id, index, total, data }` | upload token | resumable chunk upload; every chunk but the last is exactly 64 KiB + 16; the token binds to the first `blob_id` it is used with |
| `BlobGet { blob_id, index }` → `BlobChunk` | none (the random id is the capability) | only for complete blobs |
| `TurnCredentials { mailbox_id }` → `Turn` | mailbox | §8 |
| `Ping` → `Ok` | none | keep-alive |

**Storage.** For an envelope the relay stores `{ mailbox_id, seq, received_minute, envelope }` with a TTL (default 14 days); a full mailbox (5 000 envelopes) or a full relay (byte cap, default 1 GiB) refuses new deposits with `QuotaExceeded`. It never drops queued envelopes to make room. Mailboxes not authenticated for 60 days expire, and mailboxes never authenticated at all expire after 24 h. Every mailbox may always hold 64 delivery-token hashes. Rows beyond that are capped at 1 000 000 relay-wide, and live upload tokens at 1 000 000. Incomplete blobs expire with their upload token (24 h), complete ones 30 days after completion. Expiry runs from an index of due times, in short batches. **No sender, no IP, no User-Agent, no connection record** is stored or logged (INV-META-2, INV-LOG-1).

**Rate limits** are token buckets keyed by delivery token, mailbox, connection or source key (below), plus relay-wide ones for mailbox creation. Nothing IP-derived is stored or logged, and source-keyed buckets are forgotten once they refill. Token changes and acknowledgements are limited to 20, then 1/s, per mailbox, and requests that change nothing at all (an empty token change, an ack with nothing to remove) are not written. Rate-limit refusals echo the request id.

**Connections.**
- At most 1 024 concurrent connections. The only use of the peer address is a source key (IPv4 address or IPv6 /64), held in memory only and never stored or logged. Per source, the relay allows:
  - 32 concurrent connections;
  - an 8 MiB share of the response budget;
  - 10 mailbox creations, then 1 per minute;
  - 30 upload tokens, then 1 per minute.

  Raising the connection cap (`VEIL_MAX_CONN_PER_SOURCE`) scales all of these together.
- A connection that has not authenticated a mailbox, deposited, taken an invite or transferred a blob chunk within 30 s is closed, whatever it sends meanwhile.
- Idle timeout: 5 min.
- Every write has a 30 s timeout. `Fetch` and `BlobGet` responses reserve their worst-case size from a relay-wide 64 MiB budget until sent; when the budget is exhausted they are refused with `RateLimited`.

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
| `Profile` | `rev`, `name (≤ 64 chars, may be empty)`, `status (≤ 140 chars)`, `picture? (JPEG or GIF, ≤ 1024 px a side; a GIF ≤ 100 frames)`, `pad (zeros; picture + pad ≤ 48 KiB)` | ADR-0020. Each replaces the last if its `rev` is higher. `picture` is present only for contacts the sender shows it to; absent means none. Senders pad every profile to the same size. A receiver drops a picture that is not a JPEG of at most 1024 px a side, checked by its start-of-frame header before anything decodes it, or a GIF within the same side limit, 100 frames and 16 Mpx of canvases in all. A receiver also rebuilds a GIF without its comments and extensions other than frame timing and the loop count. Control and bidi characters are refused. Older apps drop it (unknown `oneof` tag). |

Every message has a random 16-byte `id`, and `sent_at` is set by the sender but **never trusted for ordering security**. Duplicate `id`s are ignored (idempotent processing; libsignal already rejects ciphertext replays).

## 8. Calls

- **Signaling** (offer, answer, ICE, hangup, busy) travels only as `Content::Call` over the E2EE session. The relay sees ordinary padded envelopes (INV-NET-3).
  - Veil does not trickle: one complete offer and one complete answer, each with its relay candidates. Incoming `Ice` signals are ignored (ADR-0018).
  - Signals are sent with a 60 s expiry, and a receiver drops any sent more than 90 s ago. One that cannot be delivered is deleted, never retried. Received signals are held in memory until the app takes them, never stored, and dropped on lock.
- **TURN URLs** from the relay reach the webview only if their host is a public IP, is the relay's own IP, or is a DNS name that does not look local. Refused names: `.local`, `.lan`, `.internal`, `.home.arpa`, `.localhost`, dotless names, and names whose last label is not alphabetic (shorthand IPv4 such as `127.1`). Names are checked by form only; where they resolve is not (THREAT_MODEL §4). A relay that offers none disables calls.
- **DTLS identity binding.**
  - The SDP carries `a=fingerprint:sha-256`, and the WebRTC stack refuses a DTLS peer whose certificate doesn't match. Because the SDP arrives authenticated by the session, a relay or TURN operator cannot substitute its own DTLS endpoint (INV-NET-4).
  - Clients MUST reject SDP without a `sha-256` fingerprint, with more than one fingerprint, or with `a=setup` inconsistent with the offer/answer role.
- **Relay-only mode (default).**
  - The peer connection uses `iceTransportPolicy: "relay"`.
  - Independently, **Rust rebuilds every outgoing and incoming SDP from an allowlist** (`crates/core/src/ice.rs`, `filter_sdp`). This was rewritten after review round 1 (H3), because a line filter let addresses through outside `a=candidate:` lines.
    - Lines must be `CRLF`-separated ASCII `x=` lines; bare `LF` or control characters reject the whole SDP.
    - `o=` is rewritten to `127.0.0.1`, `c=` to `0.0.0.0`, and every `m=` port to `9`. The `m=` tail is validated token by token.
    - `v=` must be `0`, `t=` two decimals, `b=` `<type>:<decimal>`; any other `v=`/`t=`/`b=` content rejects the SDP. Other line types (`i=`, `u=`, `e=`, …) are dropped.
    - `a=` attributes not on the allowlist are dropped. That includes `a=rtcp` and `a=remote-candidates`, which carry addresses. Attribute names are matched case-insensitively and re-emitted in lower case.
    - Candidates (any case) are re-serialised from validated fields only:
      - the address must be an IP literal (mDNS and other hostnames are dropped);
      - `typ` must be `relay`;
      - the relay address must be public (loopback, private, link-local, CGNAT and metadata addresses are refused), **or** equal to the IP of the user's configured relay, **or** one of the TURN addresses the relay announces, because the user's own TURN server may sit on a tailnet or LAN (`filter_sdp_with`, ADR-0018);
      - `raddr`/`rport` become `0.0.0.0 0`;
      - only `tcptype`, `generation`, `ufrag`, `network-id` and `network-cost` extensions are kept.
    - Any kept `a=` line that could still carry an address (a `hexdigit.digit` sequence, or any embedded IP literal, `::` included) rejects the whole SDP (fail closed).
    - DTLS checks run on the filtered output.
  - Tests (INV-NET-1, the brief's key test):
    - a property test over whole SDPs with addresses in every position;
    - a fuzz target with an independent output check;
    - a realistic browser offer that must survive intact.
    - The end-to-end test with two real clients comes in Phase 6.
- **Direct mode** (per-contact opt-in, warned):
  - host/srflx/prflx/relay candidates are allowed, but non-public addresses are filtered:
    - RFC 1918, loopback, 169.254/16, 100.64/10, fc00::/7, fe80::/10 and fec0::/10;
    - Teredo, NAT64 and 6to4 forms that embed a private IPv4 address;
    - documentation ranges.
  - **LAN mode** additionally allows private IP literals.
  - **mDNS `.local` hostnames are dropped in every mode, including LAN mode**, because the filter only accepts IP literals. LAN calls therefore need the platform to expose IP host candidates.
- **What the SDP filter cannot do** (review round 3, R3-4). The filter controls what we *send and accept in signaling*. It cannot stop the local WebRTC stack from gathering host and server-reflexive candidates and running ICE connectivity checks (STUN binding requests) from them, which would reveal our IP to the peer's TURN allocation or to the peer directly.
  - Only the transport policy prevents that: `iceTransportPolicy: "relay"` in webviews, and the equivalent `webrtc-rs` configuration on Linux (ADR-0003).
  - The relay-only promise of INV-NET-1 therefore rests on both the filter and that policy. Whether the policy holds on every platform is tested end to end in **Phase 6**, with two real clients and a packet capture. Spike C (SPIKES.md §C) already showed that webviews may gather host candidates.
- **TURN credentials.**
  - Clients authenticated to a mailbox may request credentials from the relay.
  - Format (coturn `use-auth-secret`): `username = "<expiry_unix>:<16 random hex>"`, `credential = base64(HMAC-SHA1(turn_secret, username))`, TTL 1 hour, rate-limited per mailbox.
  - The response also lists up to 4 `relay_ips`, IP literals that coturn relays on (its `external-ip`). Clients accept relay candidates at those addresses, both ways, besides public ones and the relay's own IP, so that a client reaching the relay by a name (Tailscale Funnel) can call one on the tailnet (ADR-0018). They are never used as TURN URLs.
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
| Text body | 62 464 bytes (61 KiB, so a maximal `Text` or `Edit` still fits the 64 KiB bucket) |
| Attachment | 100 MiB (v1), 64 KiB chunks |
| Envelopes per mailbox held by relay | 5 000; further deposits refused (`QuotaExceeded`), never oldest-dropped |
| Envelope bytes per relay | 1 GiB default (`VEIL_QUOTA_ENVELOPES_MB`); blobs 4 GiB (`VEIL_QUOTA_BLOBS_MB`) |
| Deposits per token | burst 60, then 1/s |
| WebSocket message | client → relay ≤ 64 KiB + 1 040 bytes (one blob chunk + framing); relay → client ≤ 32 envelopes |
| Timeouts | TLS and WebSocket handshakes 10 s each; pre-authentication 30 s; idle 5 min (clients ping); each write 30 s |
| Connections | 1 024 per relay; 32 per source (IPv4 address / IPv6 /64), in memory only |
| Per source (scale with the connection cap) | response budget 8 MiB of 64; mailbox creations 10, then 1/min; upload tokens 30, then 1/min |
| Mailboxes | 100 000 per relay; deleted after 24 h if never authenticated, after 60 days without authentication otherwise |
| Delivery tokens | 512 per mailbox; the first 64 always allowed; 1 000 000 beyond that relay-wide; changes 20, then 1/s per mailbox |
| Upload tokens | 1 000 000 live relay-wide; 20, then 0.1/s per mailbox; 24 h lifetime; at most (chunks + 16) chunk writes each |
| Acknowledgements | 20, then 1/s per mailbox |
| Invite TTL | ≤ 7 days (default 24 h) |
| Clock skew accepted | ±120 s for auth; message timestamps never security-relevant |
