# Veil TODO

Status of every feature, for v0.1.0-preview.9 (updated 2026-10-28).

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
| ✅ | Relay-only call filter | Every call SDP is filtered both ways; your own tailnet TURN server is allowed. Tested with real Chromium calls (preview.8). | — | — |
| ✅ | Erase everything (Settings) | Checked by you on a Pixel (preview.6). | — | — |

## Working order

My recommended order, one milestone at a time. Each one: I build it, test it, run the security review where it matters, push, and wait for green CI. Then you run Actions → release with the tag, test on your Pixel and tell me; I update this page. Milestones 0 and 1 are as agreed on 2026-10-25; the order from 2 on is rebuilt from this list (the original wording was lost when my context was reset) and is open to change.

| | Feature | Notes | Difficulty | ETA |
|---|---|---|---|---|
| ✅ | Milestone 0: release setup | Builds only when you start a release, growing version numbers, permanent signing key, relay port in .env. | ●○○○○ | — |
| ✅ | Milestone 1: quick wins | Key-change warning, delete/block, disappearing messages, receipts and typing, invite cleanup. Checked by you on a Pixel. | ●●○○○ | — |
| ✅ | Milestone 2: everyday messaging | Replies, reactions, edit and delete, search, QR scan, verify by scan. Checked by you on a Pixel; swipe-to-reply and three reactions follow in preview.6. | ●●●○○ | — |
| ✅ | Milestone 3: photos, files and voice notes | Photos and files checked by you on a Pixel (preview.5). | ●●●○○ | — |
| ✅ | Milestone 4: notifications | Checked by you: work while Veil runs, also in the background. Not after swiping Veil away; you decided against push (2026-10-28), so that stays as is. | ●●●●○ | — |
| ⬜ | Milestone 4.5: make it yours | Your request (2026-10-28): colours and look, profile picture and name shown to contacts, per-chat touches, and small preferences. Plan below, waiting for your picks. Review gate for the profile part. | ●●●○○ | 2–4 sessions |
| ⬜ | Milestone 5: metadata privacy | Mailbox rotation and unlinkable sending, then Tor or proxy support. Review gate. | ●●●●○ | 2–3 sessions |
| 🟡 | Milestone 6: calls | Checked by you (preview.8): voice, video, screen sharing, mute and deafen, inside and outside the tailnet. Preview.9 adds the camera in voice calls and the call bubble. Left: call history. Direct mode dropped (it would show your IP to the contact). | ●●●●● | 3–5 h left |
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
| ✅ | Voice notes | Checked by you on a Pixel. Preview.7: the length no longer slips out of the bubble. | ●●●○○ | — |
| ✅ | Replies, reactions, edit and delete | Checked by you, including swipe to reply and three reactions (preview.6). Preview.7: no more dots beside messages, hold instead. | ●●○○○ | — |
| ✅ | Search messages | Checked by you on a Pixel. | ●●○○○ | — |
| ✅ | Notifications | Checked by you: work while Veil runs, also in the background. Not after swiping Veil away (no Google push service, by design; you chose to leave it so). | ●●●●○ | — |
| ✅ | Scan QR with the camera | Checked by you: invites and verify-by-scan both work in the app. | ●●●○○ | — |
| ✅ | Verify in person by scanning | Checked by you on a Pixel. | ●●○○○ | — |
| ⬜ | Link previews | Off by default, made by the sender only. | ●●●○○ | 3 h |

## Calls

Phase 6 of the original plan.

| | Feature | Notes | Difficulty | ETA |
|---|---|---|---|---|
| ✅ | Voice and video calls | Checked by you on a Pixel (preview.8). Preview.9: a Camera button in voice calls turns video on mid-call, and an arrow shrinks the call to a draggable bubble so you can keep chatting. | ●●●●● | — |
| ✅ | Screen sharing | Checked by you: Smooth (1080p, 60 fps) or Light (720p, 30 fps), volume slider for the viewer. From Windows; Android can watch but not share (its WebView cannot capture the screen). | ●●●●○ | — |
| ✅ | Mute and deafen | Checked by you on a Pixel. | ●●○○○ | — |
| ✅ | Calls with people outside your tailnet | Checked by you: Windows outsider through Funnel to your Pixel, after the relay-ip fix. coturn only relays between your own callers, on 4.18.0. | ●●●○○ | — |
| ⬜ | Call history in the chat | Missed, declined and ended calls as lines in the conversation. | ●●○○○ | 2 h |

## Make it yours (Milestone 4.5)

Brainstorm for your request; nothing built yet. Tell me what to keep, drop or add.

| | Feature | Notes | Difficulty | ETA |
|---|---|---|---|---|
| ⬜ | Accent colour picker | Any colour, not just three. Veil adjusts it so text stays readable (contrast check). | ●●○○○ | 2 h |
| ⬜ | Bubble colours and chat wallpaper | Your bubble colour or gradient. Wallpaper from presets or your own photo, kept encrypted on the device, with dim and blur. | ●●●○○ | 3–4 h |
| ⬜ | More looks | Pure-black (AMOLED) dark mode, follow the system's light/dark, text size, compact or roomy spacing, bubble roundness. | ●●○○○ | 2–3 h |
| ⬜ | Per-chat colour and wallpaper | Give a conversation its own colour or wallpaper; only you see it. | ●●○○○ | 2 h |
| ⬜ | Profile picture | Pick and crop a photo. It goes to your contacts end-to-end encrypted, never in the clear to the relay. Metadata stripped, size capped. Choose who sees it: all contacts, or nobody. Needs a protocol addition and a review gate. | ●●●●○ | 1 session |
| ⬜ | Name and short status | Change your display name and an optional one-line status; sent to contacts like the picture. | ●●●○○ | part of profile |
| ⬜ | Nicknames and pictures for contacts | Rename a contact or give them a picture only you see; it overrides theirs. | ●●○○○ | 2 h |
| ⬜ | Your own quick reactions | Choose the six emoji in the reaction bar. | ●○○○○ | 1 h |
| ⬜ | Auto-lock time | 1, 5, 15 or 60 minutes instead of always 5. | ●○○○○ | 1 h |
| ⬜ | Small preferences | Enter sends or adds a line (desktop), 12 or 24 hour clock, haptics on or off, default screen-share quality, ringtone from a few built-in sounds. | ●●○○○ | 2–3 h |
| ⬜ | Mute a chat | No notices from one conversation, for a while or always. | ●●○○○ | 2 h |
| ⬜ | Disguised app icon (Android) | Optional plain icon and name, so Veil does not stand out on the home screen. | ●●●○○ | 3 h |

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
| ✅ | Protect the release settings in GitHub | Done by you (2026-10-29): release environment with you as reviewer, signing key only there, tag and branch rules, fork approval, read-only workflow token. | — | — |
| ✅ | Run the relay on your Pi | Running on your Pi, reached over Tailscale and Funnel. | — | — |
| ✅ | Try the app on your phone and PC | You test every preview on your Pixel and Windows. | — | — |
