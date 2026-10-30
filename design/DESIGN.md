# Veil: Design (Phase 0)

Status: **awaiting approval**. Nothing here is product code. These are static prototypes that the React app (Phase 4) will port token-for-token and component-for-component.

| What | Where |
|---|---|
| Design tokens (themes, modes, accents, bubbles, type, motion) | [`tokens.css`](tokens.css) |
| Mobile prototype (open directly in a browser) | [`mobile.html`](mobile.html) |
| Desktop / tablet prototype | [`desktop.html`](desktop.html) |
| Direction moodboards (chat view only) | [`moodboards/`](moodboards/) |
| Screenshots: 280 PNGs, 2 themes × 2 modes × 3 viewports | [`screenshots/`](screenshots/) ([`manifest.json`](screenshots/manifest.json)) |
| Overview sheets (fastest way to review) | [`screenshots/overview/`](screenshots/overview/) |
| Automated evidence (contrast, axe, targets, motion, CSP, keyboard) | [`CHECKS.md`](CHECKS.md) |
| Capture / check tooling (dev-only) | [`tools/`](tools/) |

**How to review.** Open `mobile.html` or `desktop.html` from disk; no server or build step is needed. Every screen is click-through. Press <kbd>\\</kbd>, or use the **Screens** button bottom-left, to jump to any screen and switch theme, mode or accent. On desktop, <kbd>?</kbd> shows keyboard shortcuts.

---

## 1. Direction and rationale

Two directions were sketched for the chat view ([moodboards](screenshots/moodboards/)):

- **A · Aurora Glass:** deep indigo night, a slow aurora mesh drifting behind frosted glass, gradient sent bubbles, soft glow. Premium and alive.
- **B · Ink & Signal:** matte graphite, hairlines, a single cyan→violet "signal" line, solid bubbles, no glass or glow. Calm and instrument-like, and cheaper to render on low-end Android.

**Decision (owner, Phase 0):** ship **both** as a user setting, **Settings → Appearance → Theme**. Aurora Glass is the default. Theme is an independent axis from **Mode** (System / Dark / Light) and from **Accent** (Aurora / Lagoon / Ember), so 2 × 2 × 3 = 12 combinations, plus 3 bubble styles and 4 text sizes. Every combination is contrast-checked.

Principles that drove the details:

1. **Legibility beats decoration.** Gradients live only in sent bubbles, primary actions and hero moments. Received bubbles, lists and settings are calm surfaces. All text is ≥ 4.5:1, including on every point of every gradient.
2. **Security state is never colour-only.** Verified, unverified, key-changed, relayed and direct each have a distinct icon (shield-check / shield / alert-triangle / shield / eye) *and* words. Connection dots differ by shape (filled / ring + pulse / hollow) *and* are spelled out for screen readers.
3. **Honest copy.** Onboarding includes an explicit "Not protected" list. Direct mode always says "IP visible to {name}". The relay settings say plainly what a relay can see.
4. **Privacy-safe defaults are visible defaults.** Relay-only is marked "Recommended". Link previews, read receipts, typing indicators and LAN discovery are off. Notifications hide the sender and content.
5. **No third-party anything.** Fonts (Inter, JetBrains Mono; SIL OFL 1.1) and the QR encoder (`qrcode-generator`, MIT) are vendored. The prototypes run under a strict CSP with `connect-src 'none'`, and the check suite asserts zero non-local requests.

## 2. Theming model

Attributes on `<html>` drive everything; components only read tokens.

| Attribute | Values | User-facing name |
|---|---|---|
| `data-style` | `aurora` (default) · `ink` | Theme: "Aurora Glass" / "Ink & Signal" |
| `data-theme` | `dark` (default) · `light` (`system` resolves via `prefers-color-scheme`) | Mode |
| `data-accent` | `aurora` · `lagoon` · `ember` · `custom` (app only, ADR-0019: one hue, colours computed and contrast-checked in `color.ts`, set as inline custom properties) | Accent |
| `data-black` | `true` · `false` (app only; only with `data-theme="dark"`) | Pure black (OLED) |
| `data-bubble` | `gradient` (shown as "Gradient") · `soft` ("Solid") · `minimal` | Message bubbles |
| `data-text-size` | `sm` · `md` · `lg` · `xl` (scale 0.9 / 1 / 1.12 / 1.28) | Message text size |
| `data-density` | `regular` · `compact` (app only) | Spacing |
| `data-motion` | `full` · `reduced` | Reduce motion (OR'd with the OS preference) |

What Ink & Signal changes: no ambient mesh or grain; no backdrop blur; solid sent bubbles (`--sent-ink` per accent); radii tightened (cards 14px, buttons 10px); primary buttons become "paper" (text-1 on bg); glows removed; a 2px cyan→violet `--signal-line` at the top of the window. In Ink, "Default" bubble style means solid; Soft and Minimal still change the shape.

## 3. Token reference

Source of truth: [`tokens.css`](tokens.css). Groups:

| Group | Tokens | Notes |
|---|---|---|
| Canvas | `--bg-0` window, `--bg-1` app, `--bg-2` panels | per theme × mode |
| Surfaces | `--surface-1..3`, `--surface-glass`, `--surface-glass-strong`, `--surface-scrim` | glass has a solid fallback (`@supports not (backdrop-filter)` and `prefers-reduced-transparency`) |
| Text | `--text-1` primary, `--text-2` secondary, `--text-3` tertiary (≥ 4.5:1 on every surface), `--text-on-accent`, `--text-on-accent-2` (meta in sent bubbles), `--text-on-warm` | |
| Accent | `--accent`, `--accent-strong`, `--accent-soft`, `--focus` | per accent × mode × theme |
| Status | `--success`, `--warning`, `--danger`, `--danger-strong`, `--info` + `-soft` variants | always paired with icon + text |
| Presence | `--presence-online/away/offline` | dot shape encodes state too |
| Bubbles | `--sent-a/b/c` (gradient stops), `--sent-solid`, `--sent-ink`, `--sent-bg`, `--sent-text`, `--sent-meta`, `--received-*`, `--bubble-radius`, `--bubble-radius-tail`, `--bubble-font-size` | |
| Components | `--btn-radius`, `--btn-primary-bg/fg/shadow`, `--control-on`, `--composer-radius`, `--signal-line` | where the two themes diverge structurally |
| Brand | `--aurora-indigo #4338ff`, `--aurora-violet #8b3dff`, `--aurora-cyan #00b8d9`, `--aurora-warm #ff8f6b` (the one warm accent: unread badges) | |
| Ambient | `--ambient-a..d`, `--noise`, `--noise-opacity` | transparent in Ink |
| Type | `--font-sans` (Inter), `--font-mono` (JetBrains Mono); sizes `--text-2xs` 11 → `--text-3xl` 40; weights 420/520/620/720; `--tracking-*` | safety numbers and keys use mono + tabular numerals |
| Space | `--space-1..16` on a 4px grid | |
| Shape | `--radius-xs 6` → `--radius-2xl 36`, `--radius-pill` | |
| Size | `--tap-min 44px`, avatars 32/44/56/96(/128), `--rail-w 72`, `--list-w 340` (280–480, user-resizable), `--info-w 340`, header 64, bottom nav 64 | |
| Elevation | `--shadow-1..3`, `--glow-accent`, `--glow-success`, `--inner-highlight` | |
| Blur | `--blur-glass 24px`, `--blur-heavy 48px`, `--saturate-glass` | |
| Motion | `--dur-instant 90` · `fast 160` · `base 240` · `slow 420` · `slower 700` · `ambient 48s` · `pulse 2.4s`, `--stagger 40ms`; `--ease-out`, `--ease-in`, `--ease-in-out`, `--ease-spring`, `--ease-spring-soft` | springs use CSS `linear()` with a cubic-bezier fallback |
| Layers | `--z-base … --z-toast` | |

## 4. Motion spec

Rule: **only `transform` and `opacity` are animated.** This is verified by a static audit of every stylesheet in `CHECKS.md` §5. Looping motion pauses when the tab or window is hidden (`visibilitychange` → `.tab-hidden`). Reduced motion (OS setting *or* in-app toggle) collapses every animation to its end state and removes all loops.

| Moment | What moves | Duration / easing |
|---|---|---|
| Ambient drift (Aurora only) | 4 radial blobs translate/scale/rotate | 48–62s, ease-in-out, alternate; paused when hidden; off in reduced motion |
| Send message | bubble rises 16px, scales 0.92 → 1 from bottom-right | `--dur-slow`, `--ease-spring` |
| Receive message | bubble rises from bottom-left | `--dur-slow`, `--ease-spring` |
| Typing indicator | 3 dots bob, staggered 150ms | 1.2s loop |
| Connection pulse | ring scales 1 → 2.1, fades (connecting dot, rail status) | 2.4s loop |
| Avatar → profile | shared element via View Transitions API (`hero-avatar`) | `--dur-slow`, `--ease-spring-soft`; skipped under reduced motion |
| List entry | rows rise 10px, staggered 40ms | `--dur-slow`, `--ease-spring-soft` |
| Key generation | 3 counter-rotating rings, converging particles, breathing glow; fingerprint hex "settles" from random; steps tick | ~2.6s timeline, then core pops (spring) |
| Verified | check badge pops, 3 rings burst outward, copy rises | 0.7s spring + 1.6s burst |
| Switch / radio / swatch | thumb slides, check glyph scales in | `--dur-base`, spring |
| Skeleton shimmer | highlight translates across | 1.6s loop |
| Scanner | frame breathes, scan line sweeps | 2.2–2.4s loops |
| Call audio level | rings scale/fade from avatar | 2.2s loop |
| Panic wipe | press-and-hold fill (`scaleX`) | 2s linear; release cancels |
| Dialog / info panel | pop-in / slide-in | `--dur-slow`, spring-soft |

## 5. Accessibility notes

Evidence is in [`CHECKS.md`](CHECKS.md). Summary of the last run:

- **Contrast:** 2,304 text/background pairs across all 36 theme × mode × accent × bubble combinations, all ≥ 4.5:1. Glass is checked over each ambient colour; gradients are sampled every 5%.
- **axe-core 4.10.3** (WCAG 2.0/2.1/2.2 A + AA): **0 violations** across 244 renders (every screen × mobile/desktop × both themes × both modes).
- **Targets:** every interactive element is ≥ 44×44px. Reaction chips are visually 26px tall but carry an invisible 44×44 hit area (`.reaction::after`). The user's own reaction is marked by a check glyph and a 2px border as well as the accent colour (no colour-only state).
- **Message gestures (ADR-0017):** press and hold a bubble (or right-click) for its actions; swipe it right to reply, with the bubble following the finger up to 80px and a reply glyph fading in. Every gesture has an equivalent without it: right-click with a mouse, and a "Message options" button that appears on keyboard focus (hidden otherwise, owner's choice) and is always there for screen readers; Reply is also in the actions dialog. Focus on a text field shows as a glow around the whole field, never a ring around the bare input. Up to three reactions per person sit on the bubble's lower edge and wrap.
- **Keyboard (desktop):** full Tab order with visible focus rings. <kbd>Ctrl</kbd>+<kbd>K</kbd> search; <kbd>↑</kbd>/<kbd>↓</kbd>/<kbd>Home</kbd>/<kbd>End</kbd> roving focus in lists; <kbd>Alt</kbd>+<kbd>↑/↓</kbd> previous/next chat; <kbd>Ctrl</kbd>+<kbd>I</kbd> info panel; <kbd>Ctrl</kbd>+<kbd>,</kbd> settings; <kbd>Ctrl</kbd>+<kbd>L</kbd> lock; <kbd>Esc</kbd> closes panel/dialog; <kbd>?</kbd> shortcuts. The list resizer is a focusable `role=separator` (arrows ±16px, Home/End). These are automated in `CHECKS.md` §6.
- **Screen readers:** landmarks (nav/main/aside/section), `role=log` + `aria-live=polite` on the message list, `role=status` on connection bars, `role=alert` on key-change warnings, `role=alertdialog` for panic wipe, `aria-current` for navigation. Every icon-only button has a label; conversation rows expose name, verification, connection, unread count, timer, pinned and muted in one label; delivery state is announced ("Sent", "Delivered", "Read", "Queued"). Focus moves to the screen heading on navigation.
- **Not colour alone:** see §1 principle 2. Switches show a check glyph when on; the selected theme and accent show a check.
- **Text size:** the in-app scale (to 1.28×) applies to message text; UI text follows browser zoom.
- **Known gaps for Phase 4:**
  - With reduced motion, the panic hold-to-wipe fill appears immediately while the 1.2s hold still applies. A textual countdown should be added.
  - At tablet portrait (768px), the chat header's verification line wraps to two lines.
  - Light mode has no high-contrast variant yet.

## 6. Component inventory → React (Phase 4)

| Prototype (`proto/ui.js` / CSS class) | React component | Notes |
|---|---|---|
| `.ambient` | `<AmbientBackdrop>` | hidden in Ink; pauses on `visibilitychange` |
| `.glass`, `.card` | `<Surface variant="glass\|card\|strong">` | solid fallback |
| `.btn*`, `.icon-btn` | `<Button>`, `<IconButton>` | `variant: primary/secondary/ghost/danger/danger-ghost/warning`; label required on IconButton |
| `avatar()` / `.conn` | `<Avatar>`, `<PresenceDot>` | `state: online/connecting/offline` |
| `.badge`, `chip()`, `.timer-chip`, `verifiedMark()` | `<Badge>`, `<Chip>`, `<TimerBadge>`, `<VerifiedMark>` | |
| `convRow()` / `convList()` | `<ConversationRow>`, `<ConversationList>` | roving focus, sections Pinned/All |
| `contactsList()` | `<ContactList>` | grouped Verified / Not verified |
| `.row`, `toggleRow()`, `linkRow()` | `<ListRow>`, `<ToggleRow>`, `<LinkRow>` | |
| `.switch`, `segmented()`, `.radio-card`, `.swatch`, `.theme-card`, `.range` | `<Switch>`, `<Segmented>`, `<RadioCard>`, `<AccentSwatch>`, `<ThemeCard>`, `<Slider>` | native inputs underneath |
| `.input`, `.meter` | `<TextField>`, `<PassphraseField>` + `<StrengthMeter>` | strength estimate computed in Rust in the app |
| `.banner`, `.conn-bar` | `<Banner tone>`, `<ConnectionBar state>` | |
| `chatHeader()` | `<ChatHeader>` | transport sub-line: Relayed/Direct/Connecting/Offline |
| `.msgs`, `msg()`, `bubble()`, `meta()` | `<MessageList>`, `<MessageBubble>`, `<MessageMeta>` | **plain text only**; status icons + SR text |
| `.reply`, `reactions()` | `<ReplyQuote>`, `<ReactionBar>` | |
| `.att-img`, `.att-file`, `.voice`, `.progress` | `<ImageAttachment>`, `<FileAttachment>`, `<VoiceNote>`, `<Progress>` | progress via `scaleX` |
| `.day-sep`, `.sys-msg` | `<DateSeparator>`, `<SystemMessage tone>` | key-change uses `role=alert` |
| `.typing-bubble`, `dots()` | `<TypingIndicator>` | |
| `composer()`, `.composer-locked` | `<Composer>`, `<ComposerLocked>` | Enter sends, Shift+Enter newline |
| `.skel*` | `<Skeleton>` | |
| `.state` | `<EmptyState>`, `<ErrorState>` | |
| `qr()`, `.qr-card` | `<QrCode>` | encoder moves to Rust core in the app |
| `.safety-grid` | `<SafetyNumber>` | 12 × 5 digits |
| `.scanner` | `<QrScanner>` | camera frames never leave the device |
| `.verified-burst` | `<VerifiedCelebration>` | |
| `.keygen-orb`, `.steps` | `<KeyGenAnimation>`, `<StepList>` | driven by real progress events from Rust |
| `callContent()`, `.transport-chip`, `.call-ctl` | `<CallScreen>`, `<TransportChip>`, `<CallControls>` | Direct chip always names who sees the IP |
| `.call-min`, `.call-bubble` (app only, ADR-0018) | `<CallScreen>` minimize, `<CallBubble>` | Arrow at the top left; the bubble is a 120×168 card (their picture or avatar, time, End) dragged with `transform` only, snapping to the nearer side; no transition with reduced motion |
| `.call-state`, `.share-sheet`, `.stream-volume` (app only, ADR-0018) | `<CallScreen>` pills, `<ShareSheet>`, stream volume | Mute, deafen and sharing are icon + words in a glass pill, the same on both ends; the quality bubble is a radio list (Smooth 1080p60, Light 720p30); the volume bar sets only the shared screen's sound |
| `.hue-swatches`, `.hue-swatch`, `.hue-dot` (app only, ADR-0019) | `<HuePicker>` | Twelve named hue swatches plus a slider for any hue, saved once when let go (native `change`); "App accent" (×) first for a chat's own colour; the checked swatch has a ring, not only a colour |
| `.wp-tiles`, `.wp-tile`, `.chat-wallpaper`, `.look-preview` (app only, ADR-0019) | `<WallpaperPicker>`, `<ChatWallpaper>`, `<LookPreview>` | None/Default, six token-drawn presets (Dusk, Aurora, Grid, Dots, Waves, Paper) or a photo, with Dim (0–80 %) and Blur (0–24 px); leaving a photo asks first, and focus returns to the group afterwards. A photo is chosen with its own button, "Use a photo…", so arrow keys in the group never open a file chooser; the photo in use appears as "Your photo" in the group; over a wallpaper, notices and day separators get an opaque `--surface-2` pill, and the header, banners (tint over `--bg-1`), connection bar, recording bar and composer field get opaque backgrounds, so the key-change warning stays readable over any photo; the wallpaper sits behind the chat at `z-index: -1` inside an isolated `.chat-screen` |
| `.profile-head`, `.cropper`, `.crop-view`, `.contact-head` (app only, ADR-0020) | `<ProfileCard>`, `<PictureCropper>`, contact header | Your picture, name, status, and "Who sees your picture" (All contacts / Verified / Nobody) in Settings. The cropper is a 240 px circle: drag or use the arrow keys to move, and a slider to zoom (the image moves only by `transform`). The contact page shows any key-change warning first, then their picture, the shown name, "Calls themself …" when theirs differs, and their status, labelled and quoted ("Status: “…”") so it cannot pass for a Veil notice. When a contact's shown name changes because they renamed themselves, a `.sys-msg` line says so in the chat. The crop view is `role="group"` with a visible hint. A GIF skips the cropper and is used as it is (at most 48 KB; the circle crops it with `object-fit: cover`). With reduced motion, avatars show a GIF's first frame. The nickname, a picture only you see, and "Hide my picture from …" are on the same page |
| `.dialog`, `.scrim`, `.hold-btn` | `<Dialog>`, `<AlertDialog>`, `<HoldToConfirm>` | focus trap in the app |
| Mobile shell: `.m-appbar`, `.m-topbar`, `.m-nav`, `.m-fab` | `<AppBar>`, `<TopBar>`, `<BottomNav>`, `<Fab>` | |
| Desktop shell: `.rail`, `.pane-list`, `.resizer`, `.pane-main`, `.pane-info` | `<Rail>`, `<ListPane>`, `<PaneResizer>`, `<MainPane>`, `<InfoPanel>` | info panel overlays below 1180px |
| `.logo` | `<Logo>` | |

## 7. Screen list

The canonical list is in [`proto/screens.js`](proto/screens.js): 30 mobile and 31 desktop screens. They cover onboarding (welcome, key generation, passphrase, what's protected); lock; the conversation list; chat in four flavours (verified/rich, direct mode, new unverified, key-changed); contacts; pairing (my code, scan, verified); contact profile; safety number (unverified and verified); voice call (relayed) and video call (direct); settings (root, privacy, appearance, relays, security, panic wipe confirmation); and the states empty, loading, reconnecting, offline with a failed message, and relay unreachable. Desktop adds a keyboard-shortcuts dialog.

## 8. Prototype engineering notes

- Strict CSP with no inline script or style; dynamic values go through CSSOM (`style.setProperty`), the same discipline the app will use.
- `html\`\`` in `ui.js` escapes every interpolation, mirroring React's text rendering. User-typed messages are inserted with `textContent`.
- `localStorage` stores only prototype conveniences (theme, accent, list width), wrapped in try/catch, and is ignored in capture mode.
- Screenshots are deterministic: `tools/capture.mjs` uses `?capture=1`, settles animations, and fails on any console error, CSP violation or non-local request.
- **Size note:** the 280 lossless PNGs total about 70 MB, mostly because Aurora's film grain doesn't compress. Lossy palette reduction visibly bands photos and shifts status colours, so it is unusable for visual-regression baselines. Proposal: move `design/screenshots/**` to **Git LFS** before Phase 4 adds baselines (needs your OK).

## 9. Delivery note recorded for later phases

Owner request (Phase 0): **after everything works, is checked and has passed the code-reviewer gate, the final step is to compile the Android app to an `.apk` with a GitHub Actions workflow and publish it under this repository's GitHub Releases.** Planned shape:
- Tauri 2 Android build on `ubuntu-latest` with the Android SDK/NDK.
- A release keystore held only in GitHub Actions encrypted secrets, never in the repo.
- SHA-256 checksums attached to the release.
- Tag-triggered release.

The exact workflow and signing setup will be confirmed with you when we reach it.
