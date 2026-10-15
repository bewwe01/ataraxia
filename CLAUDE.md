# CLAUDE.md: Veil conventions

Veil is an end-to-end encrypted P2P messenger:
- Rust core: `crates/core`, `crates/wire`, `crates/client`;
- untrusted relay: `crates/relay`;
- Tauri 2 + React/TypeScript app: `app/`.

License **AGPL-3.0-only**; the repository is public.

Read before changing anything security-relevant: `docs/THREAT_MODEL.md`, `docs/PROTOCOL.md`, `docs/INVARIANTS.md`, `docs/ARCHITECTURE.md` (ADRs). UI work follows `design/DESIGN.md` and `design/tokens.css`.

## Non-negotiables

1. **No custom cryptography.** Use libsignal (sessions, sealed sender, fingerprints), RustCrypto (`chacha20poly1305` incl. `aead::stream`, `hkdf`, `sha2`, `argon2`), `ed25519-dalek` / `x25519-dalek`. A new primitive or composition needs an ADR in `docs/ARCHITECTURE.md` first.
2. **Keys stay in Rust.** The webview never receives key material, raw ciphertext, or file paths into the vault. IPC returns display data only.
3. **The relay is hostile.** Verify everything from it; never send it identity keys, addresses, names, contact lists or plaintext.
4. **Relay-only by default.** Never emit a non-`typ relay` ICE candidate unless Direct mode is on for that contact (INV-NET-1).
5. **Never auto-accept a changed identity key** (INV-ID-2).
6. **No plaintext at rest, in logs, temp files, crash dumps, clipboard or notifications.**
7. **No panics on untrusted input.** Use `Result` everywhere on the boundary; no `unwrap`/`expect`/indexing on untrusted data. `#![forbid(unsafe_code)]` in all our crates.
8. **No network requests except the configured relay/TURN.** No CDNs, analytics, fonts, link previews (unless the user enables them), update checks to third parties.
9. Every security claim needs a test or a written argument in `docs/INVARIANTS.md`. Never weaken a test to make it pass.

## Rust conventions

- Edition 2024, workspace lints: `clippy::all`, `clippy::pedantic` (selectively allowed), `unwrap_used`, `expect_used`, `indexing_slicing`, `panic` **denied** in non-test code of `core`, `wire` and `relay`.
- Secret types wrap `secrecy::SecretBox` / `zeroize::Zeroizing`. They must **not** derive `Debug`, `Clone` or `Serialize`; implement a redacting `Debug` if needed.
- Constant-time comparisons (`subtle::ConstantTimeEq`) for MACs, tokens and fingerprints.
- Errors: `thiserror` enums per crate; error messages must not include secret or user content.
- Logging: `tracing`, with **no** message bodies, keys, tokens, mailbox IDs or sizes in any log level. Use the redaction helpers.
- Wire types live in `crates/wire`, versioned (`v` field), strict decoding (reject unknown fields), size limits before parsing.
- Tests:
  - unit tests next to code;
  - `proptest` for round-trips, ordering and nonce uniqueness;
  - known-answer vectors under `tests/vectors/`;
  - `cargo fuzz` targets in `fuzz/` with committed corpora.
- libsignal is pinned to an exact git tag (ADR-0001). Upgrades are a dedicated PR with the Spike A checks re-run.

## TypeScript / React conventions

- `strict: true`, `noUncheckedIndexedAccess`, no `any`. Lint bans `dangerouslySetInnerHTML`, `innerHTML`, `eval`, `new Function`, string `setTimeout`.
- Components map 1:1 to `design/DESIGN.md` §6. Use only design tokens (CSS variables); no raw colours. Animate only `transform`/`opacity`; respect `data-motion` and `prefers-reduced-motion`.
- All IPC goes through one typed module (`app/src/ipc.ts`) mirroring the Rust command list. No direct `invoke` elsewhere.
- Accessibility: ≥ 44 px targets, labels on icon buttons, no colour-only state, axe clean.

## Commands

| Task | Command |
|---|---|
| Rust format / lint / test | `cargo fmt --all --check` · `cargo clippy --workspace --all-targets -- -D warnings` · `cargo test --workspace` |
| Supply chain | `cargo deny check` · `cargo audit` · `cargo vet` · `pnpm audit --prod` |
| Fuzz (local, short) | `cargo +nightly fuzz run <target> -- -max_total_time=60` |
| Frontend | `pnpm -C app typecheck` · `pnpm -C app lint` · `pnpm -C app test` · `pnpm -C app e2e` |
| Design checks | `cd design/tools && pnpm install && node check.mjs` |
| Linux build deps (Ubuntu 24.04) | `libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev libssl-dev protobuf-compiler clang cmake` |

## Process

- Work in phases (see `docs/ARCHITECTURE.md`). Each phase ends with tests, an updated `docs/TEST_REPORT.md` (real command output), and for Phases 2, 3, 6 and 8 the **code-reviewer agent gate** (`docs/REVIEW_REPORT.md`, saved verbatim; fix every Critical/High, re-review).
- Commit messages: imperative summary line, body explains *why*. Never commit secrets, keystores or `.env` files.
- GitHub Actions: pin by full commit SHA, `permissions: contents: read` unless more is required, `persist-credentials: false`.
