# Veil TODO

Status of every feature, for v0.1.0-preview.6 (updated 2026-10-27).

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
| ✅ | Phone layout fixes | Checked by you on a Pixel. Tap highlights, focus rings, scrollbars and dropdowns polished in preview.6. | — | — |
| ✅ | Screenshot switch | Settings can lift the screenshot block for a moment (Android). Verified by you on a Pixel 10a. | — | — |
| ✅ | Themes | Aurora Glass and Ink & Signal, dark/light, 3 accents, reduce motion. | — | — |
| ✅ | Android hardening | No cloud backup of app data, screenshots blocked. | — | — |
| ✅ | Relay server | TLS 1.3 with pin, quotas, rate limits, expiry, no IPs in logs. | — | — |
| ✅ | Docker deploy | Relay + coturn + firewall unit, Pi guide. | — | — |
| ✅ | Android APK and Windows installer | Built by GitHub Actions, published with SHA-256. | — | — |
| ✅ | CI and supply-chain checks | Tests, fuzzing, Miri, cargo deny/audit/vet, secret scan. | — | — |
| ✅ | Review gate | Final gate passed with conditions; conditions met. | — | — |
| ✅ | Attachment encryption | Crypto in the core, now used for photos, files and voice notes (milestone 3). | — | — |
| 🟡 | Relay-only call filter | Done and tested in the core; there are no calls yet, so nothing to try in the app until milestone 6. | — | — |
| 🟡 | Erase everything (Settings) | Preview.6: the Purge PIN's wipe from Settings, behind three confirmations. | — | — |

## Working order

My recommended order, one milestone at a time. Each one: I build it, test it, run the security review where it matters, push, and wait for green CI. Then you run Actions → release with the tag, test on your Pixel and tell me; I update this page. Milestones 0 and 1 are as agreed on 2026-10-25; the order from 2 on is rebuilt from this list (the original wording was lost when my context was reset) and is open to change.

| | Feature | Notes | Difficulty | ETA |
|---|---|---|---|---|
| ✅ | Milestone 0: release setup | Builds only when you start a release, growing version numbers, permanent signing key, relay port in .env. | ●○○○○ | — |
| ✅ | Milestone 1: quick wins | Key-change warning, delete/block, disappearing messages, receipts and typing, invite cleanup. Checked by you on a Pixel. | ●●○○○ | — |
| ✅ | Milestone 2: everyday messaging | Replies, reactions, edit and delete, search, QR scan, verify by scan. Checked by you on a Pixel; swipe-to-reply and three reactions follow in preview.6. | ●●●○○ | — |
| ✅ | Milestone 3: photos, files and voice notes | Photos and files checked by you on a Pixel (preview.5). | ●●●○○ | — |
| 🟡 | Milestone 4: notifications | Work while Veil runs (on screen or in the background), not after it is closed: without Google's push service an app hears the relay only while it runs. | ●●●●○ | — |
| ⬜ | Milestone 5: metadata privacy | Mailbox rotation and unlinkable sending, then Tor or proxy support. Review gate. | ●●●●○ | 2–3 sessions |
| ⬜ | Milestone 6: calls | Voice and video through your TURN server, then Direct mode per contact. Review gate (Phase 6 of the plan). | ●●●●● | 3–5 sessions |
| ⬜ | Milestone 7: backup and more platforms | Encrypted backup and restore, Windows Hello, Linux AppImage/.deb. | ●●●●○ | 2–3 sessions |
| ⬜ | Milestone 8: hardening before 1.0 | App tests and accessibility, extra failure tests, cargo vet for the app, final review gate (Phase 8). | ●●●●○ | 1–2 sessions |
| ⬜ | After 1.0 | Multiple relays, phone + PC on one account, group chats, macOS/iOS, translations, update check, post-quantum TLS. Each is big; we pick per need. | ●●●●● | — |

## Quick wins

Small jobs with a big payoff.

| | Feature | Notes | Difficulty | ETA |
|---|---|---|---|---|
| ✅ | Relay port as a setting | VEIL_PORT in deploy/.env (default 8443). | ●○○○○ | — |
| ✅ | Build installers only on release | Ordinary pushes no longer build them; docs-only pushes skip CI. | ●○○○○ | — |
| ✅ | Permanent Android signing key | Your key is in GitHub. From preview.4 on, updates install over the old app and keep your chats. | ●○○○○ | — |
| ✅ | Clean up unused invite tokens | Automatic: an invite that expires unused gives its relay token back. Nothing to see in the app; covered by tests. | ●○○○○ | — |
| ✅ | Key-change warning | Checked by you. Preview.6: It’s them moves the old conversation into the new contact and removes the old one. | ●●○○○ | — |
| ✅ | Delete or block a contact | Checked by you on a Pixel. | ●●○○○ | — |
| ✅ | Disappearing messages | Checked by you on a Pixel. | ●●○○○ | — |
| ✅ | Read receipts and typing | Checked by you on a Pixel. | ●●○○○ | — |

## Messaging

| | Feature | Notes | Difficulty | ETA |
|---|---|---|---|---|
| ✅ | Photos and files | Checked by you on a Pixel. | ●●●○○ | — |
| 🟡 | Voice notes | Up to 5 minutes, with waveform. Not reported on yet. | ●●●○○ | — |
| ✅ | Replies, reactions, edit and delete | Checked by you. Preview.6: swipe right to reply, hold for actions, up to 3 reactions each, tap a quote to jump. | ●●○○○ | — |
| ✅ | Search messages | Checked by you on a Pixel. | ●●○○○ | — |
| 🟡 | Notifications | Work while Veil runs. Not after it is closed (no Google push service, by design). | ●●●●○ | — |
| ✅ | Scan QR with the camera | Checked by you on a Pixel. | ●●●○○ | — |
| ✅ | Verify in person by scanning | Checked by you on a Pixel. | ●●○○○ | — |
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
| ✅ | Android Keystore for the device secret | Sealed by the phone's secure hardware since preview.2 (ADR-0012). | ●●●●○ | — |
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
