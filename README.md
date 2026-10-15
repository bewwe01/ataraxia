# Veil (working name)

An end-to-end encrypted peer-to-peer messenger: React + TypeScript UI, Rust core, Tauri 2 shell for desktop and Android, and an untrusted relay.

**Status: Phase 1 (docs + spikes), awaiting approval.** Phase 0 design approved. No product code yet.

- Design rationale, tokens, motion, accessibility and component inventory: [`design/DESIGN.md`](design/DESIGN.md)
- Prototypes (open directly in a browser): [`design/mobile.html`](design/mobile.html), [`design/desktop.html`](design/desktop.html)
- Screenshot overviews: [`design/screenshots/overview/`](design/screenshots/overview/)
- Automated design checks: [`design/CHECKS.md`](design/CHECKS.md)
- Threat model, protocol, architecture, invariants, spike findings: [`docs/`](docs/)
- Contributor conventions: [`CLAUDE.md`](CLAUDE.md)

Nothing in this repository has had an independent security audit. Do not rely on it for sensitive communication.

## License

Veil is free software under the **GNU Affero General Public License v3.0 only** ([`LICENSE`](LICENSE)). It builds on [libsignal](https://github.com/signalapp/libsignal) (AGPL-3.0); Signal does not support use of libsignal outside its own apps. Bundled fonts are under the SIL Open Font License 1.1, and the design prototype's QR encoder is MIT ([`design/assets/fonts/`](design/assets/fonts/), [`design/vendor/`](design/vendor/)).
