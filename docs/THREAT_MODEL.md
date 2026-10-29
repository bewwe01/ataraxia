# Veil: Threat model

Status: **Phase 1 draft, awaiting approval.** Every "protected" claim below points to an invariant in [`INVARIANTS.md`](INVARIANTS.md). Each invariant has a test, or is explicitly marked *argument only*. Nothing here has had an independent audit; **an independent security audit is required before real-world sensitive use.**

## 1. Assets

| # | Asset | Where it lives |
|---|---|---|
| A1 | Message, attachment, voice-note and call **content** | device (encrypted at rest), relay/TURN (ciphertext only) |
| A2 | **Long-term identity key** | device vault; encrypted backups |
| A3 | **Session state** (ratchet keys, SPQR state) | device vault |
| A4 | **Social graph**: who talks to whom, when, how much | inferable from traffic; relay sees mailboxes |
| A5 | **Network location** (IP address) of each user | visible to relay/TURN; to contacts in Direct mode |
| A6 | **Contact list, verification states, settings** | device vault |
| A7 | **Passphrase** and OS-keystore secret | user memory; OS keystore |
| A8 | **Integrity of the software** users run | build pipeline, dependencies, releases |

## 2. Adversaries and their capabilities

| Adversary | Capabilities assumed |
|---|---|
| **Network observer** (ISP, Wi-Fi operator, state) | Sees all packets, timing and sizes; can block, delay or inject, but has no keys. Can't break TLS 1.3, X25519+ML-KEM, AES-GCM/ChaCha20. |
| **Malicious or compromised relay** | Full control of the relay software, DB and logs, *and* the coturn instance. Can drop, reorder, replay, delay and duplicate messages, serve stale or forged bundles, and correlate its own logs. |
| **Malicious contact** | A legitimate peer with a valid session who sends malformed or abusive content, tries to learn your IP, or keeps your messages. |
| **Device thief, device locked** | Has the device, can image storage and attempt offline attacks. No passphrase, no biometric. |
| **Device thief, device unlocked / app unlocked** | Full UI access while unlocked. |
| **Forensic examiner** | Lab analysis of flash, swap, logs, crash dumps, OS caches and keystore backups. |
| **Supply-chain attacker** | Compromises a dependency, build tool, GitHub Action, or the release channel. |
| **Quantum-capable adversary (future)** | Records traffic now and decrypts later ("harvest now, decrypt later"). |

## 3. What Veil protects

| Claim | Against | Mechanism | Invariants |
|---|---|---|---|
| Content confidentiality and integrity | network, relay, TURN, harvest-now-decrypt-later | PQXDH + Triple Ratchet (SPQR); sealed envelopes; DTLS-SRTP for media | INV-CRY-1…5, INV-MSG-1…5 |
| Forward secrecy & post-compromise security | later device/key compromise | Double Ratchet + SPQR; one-time prekeys deleted | INV-CRY-2, INV-CRY-4 |
| Authentication of peers | relay MITM, invite tampering | identity-bound bundles; safety numbers; never auto-accept key changes | INV-ID-1…3, INV-PAIR-1…3 |
| Replay, reorder and tamper rejection | relay | libsignal message keys + counters; AEAD everywhere; STREAM for attachments | INV-MSG-2…4, INV-ATT-1…3 |
| **Sender identity hidden from the relay** | relay | sealed sender; mailbox IDs unrelated to identity keys | INV-META-1, INV-MSG-6/7 |
| **IP address hidden from contacts** (default) | malicious contact | relay-only ICE + Rust candidate filter | INV-NET-1 |
| Call cannot be MITM'd by relay/TURN | relay | DTLS fingerprint carried in authenticated E2EE signaling | INV-NET-3, INV-NET-4 |
| Data at rest on a **locked** device | thief, forensic examiner | SQLCipher; KEK = HKDF(Argon2id(passphrase) ‖ OS-keystore secret); no plaintext temp files, logs or notifications | INV-REST-1…5 |
| Fast destruction | coercion | panic wipe crypto-shreds the key hierarchy | INV-REST-3 |
| UI compromise does not leak keys | XSS in the webview | keys only in Rust; narrow IPC; strict CSP; plain-text rendering | INV-UI-1…5 |
| Tampered builds are detectable | supply chain | pinned deps and actions, `cargo deny/audit/vet`, SHA-256 checksums, source-linked releases | INV-SUP-1…4 |

## 4. What Veil does **NOT** protect (honest list)

1. **That you use Veil, and when.** Your network sees TLS connections to your relay (and TURN) and their timing. The relay sees connection times and your IP **while connected**. It is designed not to store IPs, but a malicious relay operator can log them anyway.
2. **Your IP address from the relay and TURN operator.** Relay-only hides your IP from *contacts*, not from the infrastructure. A future Tor transport (not in v1) is the answer to this.
3. **Your IP address from contacts in Direct mode.** That's the explicit trade-off of Direct, and the UI says so every time.
4. **Traffic analysis by a global observer or a malicious relay.** Padding and buckets reduce size leakage. Timing correlation is not prevented: two mailboxes that always exchange envelopes seconds apart can be linked, and v1 has no cover traffic. A profile change (ADR-0020) deposits into many contacts' mailboxes from one connection. It is spread over rounds of at most 4 random contacts a minute, which slows that linking but does not prevent it. Every profile is padded to the same size, so the relay cannot tell which contacts may see the picture.
5. **An unlocked or compromised device.** Anyone who can use your unlocked app, and any malware with sufficient OS privileges, can read everything.
6. **Memory forensics while unlocked.** `zeroize` and best-effort `mlock` reduce remnants, but the webview, the OS, GPU buffers and the JS heap hold decrypted text we can't scrub. The same goes for photos, files and voice notes that are shown, played or saved: copies pass through the IPC layer, the webview and, on Android, the save plugin's buffers. Android cannot `mlock` meaningfully.
7. **Recipients.** Recipients can screenshot, photograph, forward or keep messages. Disappearing messages and screenshot blocking are courtesies, not guarantees. Remote delete and edit are best-effort.
8. **Denial of service by the relay or network.** They can always refuse service. Veil can only detect drops (missing delivery receipts and `server_seq` gaps) and let you switch relays.
9. **Weak passphrases on a stolen device**, if the attacker also extracts the OS-keystore secret (rooted device or unpatched keystore vulnerability). Argon2id raises the cost but does not make a weak passphrase strong.
10. **Metadata of invites.** Whoever obtains an invite link before it is used can redeem it. That shows up as an unverified contact that must be checked.
11. **The first contact (trust on first use) for remote invites**, until you compare safety numbers.
12. **A hostile relay's TURN names.** The relay names the TURN servers for calls. Veil refuses private IP addresses (other than the relay's own) and local-looking names, but it checks a DNS name only by its form (ADR-0018). A relay that controls a public-looking name can point it at an address on your network, and your device would connect to it to speak TURN. Your relay is yours or someone you chose; a relay you do not trust should not get your calls at all.
13. **Media decoders.** A call plays audio and video that a contact sends, decoded by the webview's WebRTC (Android System WebView, WebView2). A contact who has a codec exploit could attack that decoder. Only contacts can call, blocked ones cannot, and unknown senders cannot reach you at all; keep the WebView and Edge WebView2 updated. Contacts who call through Tailscale Funnel also show their IP and call timing to Tailscale.
14. **Bugs.** Veil, libsignal and every dependency are software. libsignal's use outside Signal is unsupported by Signal. There has been **no independent audit yet.**

## 5. Metadata leakage by transport mode

| Who learns what | Messaging via relay mailbox | Call, relay-only (default) | Call, Direct (opt-in) |
|---|---|---|---|
| **Contact** learns your IP | No | No (sees TURN relay address only) | **Yes** |
| **Contact** learns your online/typing/read state | Delivery and read receipts, typing: only while you have them on (off by default; ADR-0013) | Yes, during the call | Yes, during the call |
| **Relay** learns your IP | Yes, while connected (not stored by design) | Yes (TURN allocation) | Yes for signaling; media may bypass TURN |
| **Relay** learns who you talk to | **Yes, in v1 (Phase 4 build).** The client deposits over its own authenticated connection and mailboxes do not rotate, so the relay can link your mailbox (and IP) to each mailbox you send to. Not your names or keys. Rotation and unlinkable deposit connections are future work (ADR-0011) | Same as messaging; TURN sees both allocations' IPs and timing (**can link the two parties of a call**) | Sees signaling envelopes only; may see nothing of media |
| **Relay** learns message sizes | Bucket only (1/4/16/64 KiB); nothing inside a bucket depends on content length (INV-META-3). A session's first (PreKey) messages never fit 1 KiB, so a short first message shows as 4 KiB. Attachments padded (Padmé) | Media bitrate via TURN | — |
| **Relay** learns number of contacts | ≈, rounded up to a multiple of 8 (delivery-token count) | — | — |
| **Relay** learns identity keys / names | **No** (prekey bundles are opaque and only served to token/invite holders; sealed sender) | No | No |
| **Network observer** | TLS 1.3 to relay; timing and volume | Plain `turn:` to the TURN server by default (that you use TURN is visible; the media inside is DTLS-SRTP); timing and bitrate | DTLS between peers: **both IPs visible to the observer** |
| **Push service** (Google FCM, if push is ever added) | v1 uses no push service; Android keeps a foreground connection or polls | — | — |

Relay-side notes (Phase 3, ADR-0010):
- **Relay TLS is not post-quantum.** The relay's rustls/*ring* stack has no ML-KEM, so its key exchange is classical. Message content stays post-quantum protected end to end (PQXDH + SPQR). A harvest-now-decrypt-later attacker who records relay traffic could later recover only what the relay itself sees: mailbox ids, tokens, sizes and timing.
- **Open mailbox creation.** The relay cannot know who its users are, so anyone who can reach it can create mailboxes and fill its storage caps (`deploy/README.md`). When the caps are reached, new deposits and uploads are refused (denial of service). Stored data cannot be read, altered or deleted that way. Rate limits barely slow this down: with many tokens per mailbox, the caps fill as fast as the attacker's uplink allows.
- **Source keys in memory.** To bound what one host can take, the relay keys some limits by a source key (IPv4 address or IPv6 /64): concurrent connections, response-budget share, mailbox creations and upload tokens. The key is held in memory only, never logged or stored. Counts are dropped at zero, and rate buckets once they refill (within about 30 min). A memory image of a running relay therefore reveals the addresses of current and recently active clients. The relay also necessarily holds them while connected.
- **Resource exhaustion.** Per source, the relay limits concurrent connections, response-budget share, mailbox creations and upload tokens. Unauthenticated connections close after 30 s, and never-authenticated mailboxes are deleted after 24 h. Every mailbox keeps a guaranteed 64 delivery tokens. Relay-wide limits can still be exhausted: tokens beyond each mailbox's 64 by one host in about 37 h; connections by 32 sources; the response budget by 11; mailbox creation by about 60 (this blocks onboarding and rotation); upload tokens by about 680. Numbers and effects are in `deploy/README.md`. One host can also keep the single database writer busy with real writes: deposits into its own mailboxes, and attachment chunk uploads, bounded to (chunks + 16) writes per upload token since review P3R4-5. Empty changes are not committed, and token changes and acknowledgements are rate-limited per mailbox. On an SD card this costs latency for everyone, and wear. IPv6 makes sources cheap (one /48 holds 65 536 /64s). This is a denial of service, not data exposure.
- **TURN is open to anyone.** TURN credentials go to any authenticated mailbox, and mailbox creation is open, so anyone can relay traffic through the operator's coturn, as with any public TURN server. Private, CGNAT and loopback peers are refused. The host's own services, including those Docker publishes, are protected by the required firewall rule (`deploy/firewall/veil-turn.nft`, loaded at boot by its systemd unit), because coturn must be allowed to relay to its own address. A host where that rule is missing is exposed.
- **What the relay keeps.** On disk: mailbox ids, auth public keys, token hashes, queued envelopes with sequence numbers and a minute-rounded receive time, sealed invites, and blob ciphertext. Peer IP addresses are never written to disk or logs (INV-META-2). coturn is configured to log nothing.

## 6. Specific threat scenarios

| Scenario | Outcome | Where handled |
|---|---|---|
| Relay serves a forged prekey bundle | Impossible to read or forge: bundles travel only inside invite packages sealed under the invite secret, bound to the inviter's identity key; prekey signatures are checked | PROTOCOL §3–4, INV-PAIR-1 |
| Relay redeems a leaked invite id | Fails: it never saw the one-time public keys, and cannot produce the HMAC proof without the invite secret | INV-PAIR-4 |
| Relay replays an old envelope | libsignal rejects the duplicate message key (Spike A: `DuplicatedMessage`) | INV-MSG-3 |
| Relay withholds messages | Detected via missing delivery receipts and `server_seq` gaps; not preventable | PROTOCOL §11 |
| Relay MITMs a call | Fails: DTLS fingerprint comes from authenticated signaling | INV-NET-4 |
| Contact's key changes (reinstall or attack) | Structurally impossible in place: addresses are hashes of identity keys, so a new key is a new, unverified contact. The UI warns when a new identity claims an existing name, and never merges automatically | INV-ID-2, PROTOCOL §5 |
| Malformed message from a contact | Strict decoding; size limits; fuzzed parsers; no panic | INV-MSG-5, INV-ROB-1 |
| XSS in a message | Rendered as plain text; CSP forbids inline script; IPC exposes no secrets | INV-UI-1…3 |
| Link-preview IP leak | Previews off by default; when on, fetched by Rust with a fixed User-Agent, no cookies, and only after a warning | INV-UI-4 |
| Locked phone stolen | DB encrypted; key needs passphrase + keystore secret; Argon2id slows guessing | INV-REST-1/2 |
| Notification leaks content | Notifications say "New message" only | INV-REST-5 |
| Crash dump with plaintext | No secrets in `Debug`; panic hook scrubs; crash reports never auto-sent | INV-REST-4, INV-LOG-1 |
| Malicious dependency update | Exact pins, lockfile integrity, `cargo vet`, `cargo deny` sources allowlist | INV-SUP-1…3 |
| Tampered release APK | SHA-256 checksums plus signing key; reproducible-build work is future | INV-SUP-4 |

## 7. Assumptions

- The OS, its keystore and the webview engine are not compromised.
- Users protect their passphrase.
- Primitives are secure: X25519, ML-KEM-1024, Ed25519/XEdDSA, AES-256 (libsignal), XChaCha20-Poly1305, HMAC/HKDF-SHA-256, Argon2id.
- libsignal correctly implements PQXDH/SPQR/sealed sender. We rely on Signal's reviews and formal analyses, not our own.
- The relay operator controls only the relay and TURN. Running your own relay (deploy/README) removes the third party but **not** the protocol's distrust of the relay.
