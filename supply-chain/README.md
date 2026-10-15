# supply-chain (cargo vet, INV-SUP-3)

- **Imports:** audit sets published by Bytecode Alliance, Embark, Google, ISRG, Mozilla and Zcash (`config.toml`, pinned in `imports.lock`).
- **Exemptions:** every crate that no imported audit covered was exempted at Phase 2 (2026-10-15) instead of being audited by us. That includes libsignal, spqr and libcrux. **This is a known gap:** Veil has not yet reviewed these crates itself.
- **Effect:** `cargo vet --locked` (in CI) fails on any new or bumped crate until it is audited, or exempted in a reviewed commit.
- Shrink the exemptions with `cargo vet suggest` and `cargo vet certify`, then `cargo vet prune`.
