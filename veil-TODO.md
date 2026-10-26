# Veil TODO

Status of every feature, for v0.1.0-preview.3 (updated 2026-10-26).

ETA is my hands-on time, not including CI builds (about 20 min per release). One session is about 3–5 hours. Difficulty: 1 easy … 5 very hard. Estimates are rough.

✅ done · 🟡 partly done · ⬜ to do

## Shipped in v0.1

What's in the preview release today.

| | Feature | Notes | Difficulty | ETA |
|---|---|---|---|---|
| ✅ | End-to-end encrypted 1:1 chats | libsignal with post-quantum PQXDH + SPQR. | — | — |
| ✅ | Sealed sender | The relay doesn't learn who sent a message. | — | — |
| ✅ | Size padding | Every message is padded to 1, 4, 16 or 64 KiB. | — | — |
| ✅ | Safety numbers | Compare, mark verified, clear. | — | — |
| ✅ | Changed keys never auto-accepted | A new key shows up as a new, unverified contact. | — | — |
| ✅ | Encrypted vault | Passphrase (Argon2id) plus a device secret. | — | — |
| ✅ | Encrypted local database | SQLCipher; nothing readable on disk. | — | — |
| ✅ | Invites by link, with QR shown | Single use, expire after 24 h. | — | — |
| ✅ | Text chat with delivery status | Failed sends retry when the relay is back. | — | — |
| ✅ | Auto-lock and Lock now | Locks after 5 min without you touching it. | — | — |
| ✅ | Start over | Wipes the device after a forgotten passphrase. | — | — |
| ✅ | PIN or password | Choose at setup, change in Settings. Delays after 5 wrong tries. Verified by you on a Pixel 10a. | — | — |
| ✅ | Fingerprint unlock (Android) | Keystore-backed, toggle in Settings. Verified by you on a Pixel 10a. | — | — |
| ✅ | Purge PIN | Typed at the lock screen, it wipes everything in Veil and destroys the phone's hardware key. Verified by you on a Pixel 10a. | — | — |
| 🟡 | Phone layout fixes | No more content under the status bar, gesture bar or keyboard. Checked at Pixel 10a size; not yet on the device. | — | — |
| ✅ | Screenshot switch | Settings can lift the screenshot block for a moment (Android). Verified by you on a Pixel 10a. | — | — |
| ✅ | Themes | Aurora Glass and Ink & Signal, dark/light, 3 accents, reduce motion. | — | — |
| ✅ | Android hardening | No cloud backup of app data, screenshots blocked. | — | — |
| ✅ | Relay server | TLS 1.3 with pin, quotas, rate limits, expiry, no IPs in logs. | — | — |
| ✅ | Docker deploy | Relay + coturn + firewall unit, Pi guide. | — | — |
| ✅ | Android APK and Windows installer | Built by GitHub Actions, published with SHA-256. | — | — |
| ✅ | CI and supply-chain checks | Tests, fuzzing, Miri, cargo deny/audit/vet, secret scan. | — | — |
| ✅ | Review gate | Final gate passed with conditions; conditions met. | — | — |
| 🟡 | Attachment encryption | Crypto done and tested in the core; not wired into the app. | — | — |
| 🟡 | Relay-only call filter | ICE filter done in the core; calls themselves not built. | — | — |

## Quick wins

Small jobs with a big payoff.

| | Feature | Notes | Difficulty | ETA |
|---|---|---|---|---|
| ✅ | Relay port as a setting | VEIL_PORT in deploy/.env (default 8443). | ●○○○○ | — |
| ✅ | Build installers only on release | Ordinary pushes no longer build them; docs-only pushes skip CI. | ●○○○○ | — |
| 🟡 | Permanent Android signing key | Release side done: each build gets a higher version number. Waiting for you to add the three secrets. | ●○○○○ | 10 min (you) |
| 🟡 | Clean up unused invite tokens | Built and tested; ships in preview.4. | ●○○○○ | — |
| 🟡 | Key-change warning | Built: a new contact with a known name gets a warning. Waiting for your Pixel test (preview.4). | ●●○○○ | — |
| 🟡 | Delete or block a contact | Built and tested; waiting for your Pixel test (preview.4). | ●●○○○ | — |
| 🟡 | Disappearing messages | Built: 5 min to 4 weeks per chat. Waiting for your Pixel test (preview.4). | ●●○○○ | — |
| 🟡 | Read receipts and typing | Built, off by default. Waiting for your Pixel test (preview.4). | ●●○○○ | — |

## Messaging

| | Feature | Notes | Difficulty | ETA |
|---|---|---|---|---|
| ⬜ | Photos and files | Upload/download encrypted chunks via the relay; crypto exists. | ●●●○○ | 4–6 h |
| ⬜ | Voice notes | Mic permission, recording, playback. After attachments. | ●●●○○ | 3–4 h |
| ⬜ | Replies, reactions, edit and delete |  | ●●○○○ | 3–4 h |
| ⬜ | Search messages | Local only, inside the encrypted database. | ●●○○○ | 2–3 h |
| ⬜ | Notifications | No sender or text shown. Android background delivery is the hard part. | ●●●●○ | 1–2 sessions |
| ⬜ | Scan QR with the camera | Camera plugin and permissions on Android. | ●●●○○ | 3–4 h |
| ⬜ | Verify in person by scanning | Scan each other's code to mark verified. After the scanner. | ●●○○○ | 2 h |
| ⬜ | Link previews | Off by default, made by the sender only. | ●●●○○ | 3 h |

## Calls

Phase 6 of the original plan.

| | Feature | Notes | Difficulty | ETA |
|---|---|---|---|---|
| ⬜ | Voice and video calls | WebRTC through your TURN server, with its own review gate. | ●●●●● | 3–5 sessions |
| ⬜ | Direct mode per contact | Optional peer-to-peer for faster calls; reveals your IP to that contact. | ●●●○○ | part of calls |

## Privacy

| | Feature | Notes | Difficulty | ETA |
|---|---|---|---|---|
| ⬜ | Mailbox rotation and unlinkable sending | Stops the relay linking who talks to whom (a known v1 gap). | ●●●●○ | 1–2 sessions |
| ⬜ | Multiple relays | Talk to contacts who use a different relay. | ●●●●○ | 2 sessions |
| ⬜ | Tor or proxy support | Hide your IP from the relay. | ●●●●○ | 1–2 sessions |
| ⬜ | Post-quantum TLS to the relay | Depends on support in the TLS library we use. | ●●●○○ | 2–4 h |

## Security and storage

| | Feature | Notes | Difficulty | ETA |
|---|---|---|---|---|
| ⬜ | Android Keystore for the device secret | Hardware-backed instead of a file. | ●●●●○ | 1 session |
| ⬜ | Encrypted backup and restore | Move to a new phone without losing chats. | ●●●●○ | 1–2 sessions |
| ⬜ | Windows Hello unlock | Fingerprint/face unlock on Windows. | ●●●○○ | 3–4 h |
| ⬜ | Independent security audit | Needs outside experts; I can't do this one. | — | external |

## Platforms

| | Feature | Notes | Difficulty | ETA |
|---|---|---|---|---|
| ⬜ | Linux AppImage and .deb |  | ●●○○○ | 2 h |
| ⬜ | macOS app | Signing needs an Apple developer account. | ●●●○○ | 3 h |
| ⬜ | Windows code signing | No SmartScreen warning. Needs a paid certificate. | ●○○○○ | 1 h |
| ⬜ | iOS app | Needs an Apple account and a Mac build. | ●●●●● | 3+ sessions |
| ⬜ | Same account on phone and PC | Multi-device sync. | ●●●●● | 3+ sessions |
| ⬜ | Group chats | MLS protocol, needs a design decision first. | ●●●●● | 4+ sessions |
| ⬜ | Update check | Opt-in, from your own relay only. | ●●●○○ | 3 h |
| ⬜ | Translations |  | ●●○○○ | 2–3 h |

## Quality

| | Feature | Notes | Difficulty | ETA |
|---|---|---|---|---|
| ⬜ | App tests and accessibility check | Frontend tests, axe audit, XSS test. | ●●●○○ | 1 session |
| ⬜ | Extra failure tests | Fake relay replaying messages, crash in the middle of a write. | ●●○○○ | 2–3 h |
| ⬜ | cargo vet for the app's dependencies |  | ●●○○○ | 2 h |
| ⬜ | Final hardening and review gate | Phase 8 of the original plan. | ●●●●○ | 1–2 sessions |

## Your part

Things only you can do.

| | Feature | Notes | Difficulty | ETA |
|---|---|---|---|---|
| ⬜ | Protect the release settings in GitHub | release environment, tag rule. I'll walk you through it. | — | 5 min |
| ⬜ | Run the relay on your Pi | Confirms the arm64 build works. | — | 30–60 min |
| ⬜ | Try the app on your phone and PC | Tell me what breaks. | — | 15 min |
