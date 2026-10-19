# supply-chain (cargo vet, INV-SUP-3)

- **Imports:** audit sets published by Bytecode Alliance, Embark, Google, ISRG, Mozilla and Zcash (`config.toml`, pinned in `imports.lock`).
- **Exemptions:** every crate that no imported audit covered was exempted instead of being audited by us: at Phase 2 (2026-10-15), and again for the Phase 3 relay dependencies (2026-10-19: tokio, tungstenite, rustls/ring, redb, rcgen and others). That includes libsignal, spqr and libcrux. **This is a known gap:** Veil has not yet reviewed these crates itself.
- **Current:** `cargo vet --locked` → 43 fully audited, 5 partially audited, 207 exempted (2026-10-19).
- **Effect:** `cargo vet --locked` (in CI) fails on any new or bumped crate until it is audited, or exempted in a reviewed commit.
- Shrink the exemptions with `cargo vet suggest` and `cargo vet certify`, then `cargo vet prune`.
