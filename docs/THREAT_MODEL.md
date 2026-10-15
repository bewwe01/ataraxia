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
4. **Traffic analysis by a global observer or a malicious relay.** Padding and buckets reduce size leakage. Timing correlation is not prevented: two mailboxes that always exchange envelopes seconds apart can be linked, and v1 has no cover traffic.
5. **An unlocked or compromised device.** Anyone who can use your unlocked app, and any malware with sufficient OS privileges, can read everything.
6. **Memory forensics while unlocked.** `zeroize` and best-effort `mlock` reduce remnants, but the webview, the OS, GPU buffers and the JS heap hold decrypted text we can't scrub. Android cannot `mlock` meaningfully.
7. **Recipients.** Recipients can screenshot, photograph, forward or keep messages. Disappearing messages and screenshot blocking are courtesies, not guarantees. Remote delete and edit are best-effort.
8. **Denial of service by the relay or network.** They can always refuse service. Veil can only detect drops (missing delivery receipts and `server_seq` gaps) and let you switch relays.
9. **Weak passphrases on a stolen device**, if the attacker also extracts the OS-keystore secret (rooted device or unpatched keystore vulnerability). Argon2id raises the cost but does not make a weak passphrase strong.
10. **Metadata of invites.** Whoever obtains an invite link before it is used can redeem it. That shows up as an unverified contact that must be checked.
11. **The first contact (trust on first use) for remote invites**, until you compare safety numbers.
12. **Bugs.** Veil, libsignal and every dependency are software. libsignal's use outside Signal is unsupported by Signal. There has been **no independent audit yet.**

## 5. Metadata leakage by transport mode

| Who learns what | Messaging via relay mailbox | Call, relay-only (default) | Call, Direct (opt-in) |
|---|---|---|---|
| **Contact** learns your IP | No | No (sees TURN relay address only) | **Yes** |
| **Contact** learns your online/typing/read state | Delivery receipts: yes (timing). Read/typing: only if both opted in | Yes, during the call | Yes, during the call |
| **Relay** learns your IP | Yes, while connected (not stored by design) | Yes (TURN allocation) | Yes for signaling; media may bypass TURN |
| **Relay** learns who you talk to | Not directly. Sees mailbox IDs (rotating) and deposits with unlinkable tokens; **timing correlation possible** | Same as messaging; TURN sees both allocations' IPs and timing (**can link the two parties of a call**) | Sees signaling envelopes only; may see nothing of media |
| **Relay** learns message sizes | Bucket only (1/4/16/64 KiB); attachments padded (Padmé) | Media bitrate via TURN | — |
| **Relay** learns number of contacts | ≈, rounded up to a multiple of 8 (delivery-token count) | — | — |
| **Relay** learns identity keys / names | **No** (prekey bundles are opaque and only served to token/invite holders; sealed sender) | No | No |
| **Network observer** | TLS to relay; timing and volume | TLS/DTLS to TURN; timing and bitrate | DTLS between peers: **both IPs visible to the observer** |
| **Push service** (Google FCM, if push is ever added) | v1 uses no push service; Android keeps a foreground connection or polls | — | — |

## 6. Specific threat scenarios

| Scenario | Outcome | Where handled |
|---|---|---|
| Relay serves a forged prekey bundle | Rejected: the bundle's identity key must equal the identity key in the invite; prekey signatures are checked | PROTOCOL §4.3, INV-PAIR-1 |
| Relay replays an old envelope | libsignal rejects the duplicate message key (Spike A: `DuplicatedMessage`) | INV-MSG-3 |
| Relay withholds messages | Detected via missing delivery receipts and `server_seq` gaps; not preventable | PROTOCOL §11 |
| Relay MITMs a call | Fails: DTLS fingerprint comes from authenticated signaling | INV-NET-4 |
| Contact's key changes (reinstall or attack) | Messages held, sending paused, loud warning; never auto-accepted | INV-ID-2 |
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
