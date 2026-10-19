# Veil: Test report

Real command output only. Updated at the end of every phase. Earlier phases' entries are kept for history.

## Phase 4: client, app, release (2026-10-19), after final gate round 1

Final gate round 1 returned **FAIL** (5 High). All five Highs, the Mediums and the Lows are addressed. Each new behavioural test was checked against a mutant that reverts its fix.

| Finding | Fix | Evidence |
|---|---|---|
| P4-1 relay can stall the actor | Every relay round trip runs through `Actor::interruptible`: a lock request (`Client::lock` sets a flag and wakes the actor) or the auto-lock deadline cancels it. `sync` skips `seq <= last`, stops when nothing advances, and does at most 16 batches, then continues on the next tick | `lock_preempts_a_stalled_relay`: a tarpit relay holds `unlock` in connect; `lock()` must finish within 3 s (mutant without the interrupt: fails, "lock waited for the relay"). Stale-`seq` replay: code argument, no fake-relay test |
| P4-2 background events postponed auto-lock | Only user-caused commands count as activity (setup, unlock, send, invite, verify, rename, and a new `touch` that the UI sends on pointer/key input, at most every 20 s). Refreshes, `mark_read`, `me` do not | `incoming_traffic_does_not_postpone_auto_lock` (auto-lock 3 s, a message every 200 ms plus UI refreshes; must lock; `touch` keeps it open). Mutant counting every command: fails |
| P4-3 setup not crash-safe | Without a header, setup first wipes debris (DB, journal/WAL, device secret, keyring entry); the device secret and header are written via temp file + fsync + rename. New `reset` command and "Start over" on the unlock screen, with confirmation | `setup_recovers_from_debris_and_reset_starts_over` |
| P4-4 Android backups | `app/android/harden.py` sets `allowBackup=false` and backup/transfer rules excluding every domain; CI checks the built APK's manifest with `aapt2` | CI `android` job step "Check the hardening reached the APK" (first run pending at time of writing) |
| P4-5 signing key exposure | Build jobs have no secrets and produce an unsigned APK. Signing runs only for a `v*` tag / tagged dispatch, in `environment: release`, with no checkout and no project code | workflow review |
| P4-6 message loss between commits | `SqlBackend::apply` uses a savepoint; `process` and pairing wrap the core's commit and the app rows in one savepoint. The introduction envelope is stored with the contact and retried | existing E2E test; crash-injection test not written |
| P4-7 app tree outside gates | `release.yml` job `app-supply-chain` (deny + audit on `app/src-tauri`), `pnpm audit --prod`, `--locked` builds | CI (first run pending) |
| P4-8 screenshots | FLAG_SECURE via `harden.py` | script tested on a template-shaped project; not checked on a device |
| P4-9 docs | THREAT_MODEL "who you talk to" corrected; onboarding text; ADR-0011; INVARIANTS rows | docs |
| P4-10 to P4-14 | token before `TakeInvite`; invisible/bidi characters stripped from names; IPv6 URLs bracketed and unbalanced brackets refused; UI clears state on lock, send guard, rejection handlers; tag validated; deposit retries capped at 20 | `host_port_parsing` extended |
| P4-15 relay bucket race | Both upload-token buckets checked and taken under both locks; `allow` results acted on | relay tests pass |

```text
$ cargo fmt --all --check                                             # FMT_OK
$ cargo clippy --workspace --all-targets --locked -- -D warnings      # exit 0
$ cargo test --workspace --locked
  veil_client unit 4 | lock_and_setup 3 | pair_and_message 1
  veil_core 74 | secrets 3 | session 22 (+1 ignored)
  veil_relay lib 25 | logs 1 | relay 24 | smoke 0 (+2 ignored) | veil_wire 5
$ cargo deny check                    # advisories ok, bans ok, licenses ok, sources ok
$ cargo vet --locked                  # Vetting Succeeded (48 fully audited, 16 partially audited, 217 exempted)
$ (app) tsc --noEmit; node scripts/lint.mjs; vite build     # lint: 9 files clean; built
$ (app/src-tauri) cargo clippy --all-targets --locked -- -D warnings   # exit 0
```

Not verified here: the app has not been run on a real Android phone or Windows machine by me; the CI builds produce the binaries. There is no frontend test suite.

## Phase 3: after review round 4 conditions (2026-10-19)

Review round 4 returned **PASS WITH CONDITIONS** (no Critical or High). All five conditions and the Lows are addressed. Each new test was mutation-checked.

| Finding | Fix | Test (mutant that fails it) |
|---|---|---|
| P3R4-1 disk sizing | README and `.env.example` give the full bound: 7.4 M token rows (about 1.2 GB), 1 M upload tokens (about 160 MB), roughly 23 GB worst case with the defaults | docs |
| P3R4-2 CI job wrong | Step 2 polls for the rule; step 3 moves `/etc/veil-turn.nft` aside so the rule genuinely cannot load, then expects Docker to refuse. README wording: "Docker loads the rule when it starts and refuses to start if it cannot". | CI `firewall-unit` (first run pending) |
| P3R4-3 rule lost on nftables start/stop | New drop-in `nftables-veil-turn.conf`: `ExecStartPost`, `ExecReload` (after the distribution's reload) and `ExecStopPost` re-load the rule. The unit drops `PartOf`/`ReloadPropagatedFrom`. | CI `firewall-unit` step 2: stop, start from inactive, restart, reload, stop; the rule must be present after each (first run pending) |
| P3R4-4 low cap breaks fetches | `set_per_source_connections` only scales allowances up (factor ≥ 1) | `a_low_connection_cap_keeps_full_fetches_working` (n = 1 and 8; the unclamped factor fails it) |
| P3R4-5 unbounded `BlobPut` re-sends | Upload-token record counts puts; more than chunks + 16 → `QuotaExceeded`. Schema version 4. README and THREAT_MODEL name the path. | `chunk_resends_per_token_are_bounded` (no bound → fails) |
| P3R4-6 "no-op" wording | Reworded: only *empty* changes and acks are skipped | docs |
| P3R4-7 M7/M8 survived | `floor_rows_are_released_correctly` (M7 now fails it); `foreign_schema_is_refused` extended with a lone `STATS` counter (M8 now fails it) | as named |
| P3R4-8 doc gaps | README L9/L255 retention wording; PROTOCOL §14 Ack row | docs |
| P3R4-9 update path | README "Updates" explains the schema refusal and how to reset only the database | docs |
| P3R4-10 upload buckets | Peek both buckets before spending; refund both on a quota refusal | covered by the `upload_tokens_are_limited_per_source` path; the refund itself has no dedicated test |

```text
$ cargo fmt --all --check; cargo clippy --workspace --all-targets --locked -- -D warnings   # exit 0
$ cargo test --workspace --locked
  veil_core 74 | secrets 3 | session 22 (+1 ignored) | veil_relay lib 25 | logs 1 | relay 24 | smoke 0 (+2 ignored) | veil_wire 5
```

To save budget, no separate round 5 was run. The final review gate covers these fixes together with the Phase 4 client and app.

## Phase 3: after review round 3 conditions (2026-10-19)

Review round 3 returned **PASS WITH CONDITIONS**: no Critical or High findings, four Medium conditions and five Lows (`docs/REVIEW_REPORT.md`). All nine are addressed. Each new test was mutation-checked.

| Finding | Fix | Test (mutant that fails it) |
|---|---|---|
| **C1 / P3R3-1** relay-wide token caps are a lockout | Every mailbox keeps a **floor** of 64 delivery tokens; only rows beyond the floor count against the relay-wide 1 000 000. Upload-token cap raised to 1 000 000 (about 160 MB) and the per-source upload rate lowered to 1/min, so the cap needs about 680 sources. README and THREAT_MODEL give the number of sources each relay-wide limit needs. | `token_floor_survives_a_full_relay_wide_cap` (floor removed → fails) |
| **C2 / P3R3-2** per-source limits not configurable | `Config::set_per_source_connections(n)` scales every per-source allowance (creation, upload tokens, response share) by n/32; `VEIL_MAX_CONN_PER_SOURCE` uses it. README and `.env.example` corrected. | `per_source_limits_scale_with_the_connection_cap` (creation not scaled → fails) |
| **C3 / P3R3-3** no-op writes keep the writer busy | `update_tokens` and `ack` that change nothing do not commit; `UpdateTokens` and `Ack` are limited to 20, then 1/s per mailbox. The residual, real writes into one's own mailboxes, is documented with the review's numbers. | `no_op_writes_do_not_commit` (a test-only commit counter; removing either early return → fails); `token_changes_and_acks_are_rate_limited_per_mailbox` (either limit removed → fails) |
| **C4 / P3R3-4** "never by IP" false; keys kept forever | The five texts are corrected (PROTOCOL, THREAT_MODEL, ARCHITECTURE, `limits.rs`, `server.rs`). `KeyedLimiter::prune` drops refilled buckets on every sweep, for all keyed limiters. | `limits::tests::prune_forgets_refilled_buckets`; `source_keys_are_forgotten_after_refill` (no prune call → fails) |
| P3R3-5 systemd unit stops Docker; nftables flush drops the rule | Unit: `After=`/`PartOf=`/`ReloadPropagatedFrom=nftables.service`, `ExecReload`, tolerant `ExecStop`; no `RequiredBy`. New Docker drop-in `docker-veil-turn.conf`: `ExecStartPre=nft list table inet veil_turn`. | New CI job `firewall-unit` on a systemd runner: restart and reload nftables (flush ruleset) and the rule stays; stop the unit and Docker stays up; Docker refuses to start without the rule. *Not run here (no systemd); pending its first CI run.* |
| P3R3-6 gitleaks allowlist too wide | Only `generic-api-key`, only in `Cargo.lock`, and only when the match is two quoted crate names | Repo: no leaks. Negative test: a 40-hex `api_key` and a Heroku key in a `Cargo.lock` are reported (generic + heroku), and a crate-name pair outside a `Cargo.lock` is reported. |
| P3R3-7 schema check incomplete | An unversioned database must have every record table **and** `STATS` empty to be stamped | `foreign_schema_is_refused` extended: a lone orphan token row with no counters, and a lone upload token, are both refused (dropping `TOKENS` from the check → fails) |
| P3R3-8 untested claims, stale rows | `upload_tokens_are_limited_per_source` (R3-M13 now fails it); `over_cap_mailboxes_can_shrink_but_not_grow` (R3-M6 now fails it); PROTOCOL §14 lists the new limits; INV-LOG-1 cites M3/M4/M8/M9 | as named |
| P3R3-9 refused creations spend the source allowance | Check the relay-wide bucket without spending first (`Limiter::would_allow`); refund the source token if the relay-wide bucket empties in between (`KeyedLimiter::refund`) | `refused_creations_do_not_spend_the_source_allowance`. Removing both layers → fails. Each layer alone survives by design, since they cover the same case (the refund is for the race). `limits::tests::refund_returns_a_token`. |

### Format, lint, tests, supply chain

```text
$ cargo fmt --all --check                                         # exit 0
$ cargo clippy --workspace --all-targets --locked -- -D warnings  # exit 0
$ cargo test --workspace --locked                                 # exit 0
  veil_core 74 | secrets 3 | session 22 (+1 ignored) | veil_relay lib 23 | logs 1 | relay 23 | smoke 0 (+2 ignored) | veil_wire 5
$ cargo deny --locked check   → advisories ok, bans ok, licenses ok, sources ok
$ cargo vet --locked          → Vetting Succeeded (43 fully audited, 5 partially audited, 207 exempted)
$ gitleaks git --redact --exit-code 1 .   (8.30.1, repo .gitleaks.toml) → no leaks found
```

### Deployed stack (image rebuilt at these changes; schema version 3)

```text
smoke deployed_relay_round_trip ... ok
-y -c client↔client          Total lost packets 0 (0.000000%)
-c -e 10.0.0.1               channel bind: error 403 (Forbidden IP)
wrong password               ERROR: Cannot complete Allocation
host listener :40000         Total lost packets 5 (100%); udp packets received = 0
Docker-published :40001      Total lost packets 5 (100%)
relay log lines: 1; coturn lines other than the firewall-drop line: 0
docker compose stop relay: 340 ms, exit 0
```

There was no local soak this round, because the disk here had 2.6 GB free. CI's `relay-deploy` soaks 1.1 GB.

## Phase 3: after review round 2 fixes (2026-10-19)

Review round 2 returned **FAIL**: P3-1 and P3-2 were confirmed fixed; one new High, four Medium, four Low (`docs/REVIEW_REPORT.md`). Each new test was mutation-checked the same way as before.

| Finding | Fix | Test (mutant that fails it) |
|---|---|---|
| **P3R2-1 (High)** upload tokens and token rows outside every cap | Relay-wide caps: 20 000 live upload tokens and 1 000 000 delivery-token rows, counted in `STATS` in the same transaction, released on completion, expiry, removal, delete and idle expiry. Upload tokens are also limited per source (30, then 1 per 30 s). | `upload_tokens_are_capped_and_released` (no cap → fails; completion not freeing → fails); `token_rows_are_capped_relay_wide` (no cap → fails; delete not freeing → fails) |
| P3R2-2 one source holds the response budget | Per-source share of 8 MiB (in memory, keyed by the source key, dropped at zero), on top of the relay-wide 64 MiB | `one_source_cannot_hold_the_response_budget`: 31 non-reading connections pipelining 5 full fetches each from 127.0.0.1; a client from 127.0.0.2 still fetches. Without the share it fails. |
| P3R2-3 creation budget drained by reconnecting | Per-source creation limit (10, then 1/min), checked before the relay-wide one; never-authenticated mailboxes expire after 24 h | `mailbox_creation_is_limited_per_source` (no per-source check → fails); `never_authenticated_mailboxes_expire_early` (touch not marking → fails) |
| P3R2-4 log test blind to `?id` and derived sizes | The test requires **no log line at all** during the session (besides the canary); the needle search stays as a second check | M8 (`m = ?id` in `Store::deposit`) and M9 (`bytes = value.len()`) both fail it now |
| P3R2-5 nft rule misses Docker-published services | Chain at `priority mangle` (before Docker's dstnat). A systemd unit `veil-turn-firewall.service` loads it at boot, `RequiredBy=docker.service`. | CI probe adds a Docker-published UDP echo service (`-p 40001:3480/udp turnutils_peer`) and requires 5/5 lost. The same step **fails** with the old `priority filter` rule (exit 1). |
| P3R2-6 revoked connection still gets pushes | Subscribers carry the auth key; `notify` sends only to the mailbox's current key and drops the rest; `DeleteMailbox` drops all subscribers; a failed re-check unsubscribes | `deleting_a_mailbox_revokes_other_connections` (extended: no pushes after re-creation); `pushes_follow_the_current_mailbox_key` (idle expiry on a test clock, re-creation from another source). No key filter → fails; no filter and no drop → both fail. |
| P3R2-7 IPv6 clients may share one source behind Docker's proxy | `VEIL_MAX_CONN_PER_SOURCE` (1–1024), documented in README and `.env.example`; not reproduced here (no IPv6) | — |
| P3R2-8 inaccurate figures | Disk: apparent 3.4× vs allocated about 2× now stated as such; INV-ROB-1 says the soak covers filling, not mass expiry; `Store::sweep` doc says what it counts | — |
| P3R2-9 no schema version | `STATS["schema"] = 2`; another version, or an unversioned database holding data, is refused with `StoreError::Schema`; an empty one is stamped. The mailbox record gained a field, so the version matters now. | `foreign_schema_is_refused` (accepting another version → fails) |

### Format, lint, tests

```text
$ cargo fmt --all --check                                         # exit 0
$ cargo clippy --workspace --all-targets --locked -- -D warnings  # exit 0
$ cargo test --workspace --locked                                 # exit 0 (condensed as before)
     Running unittests src/lib.rs (veil_core)       test result: ok. 74 passed; 0 failed
     Running tests/secrets.rs                       test result: ok. 3 passed; 0 failed
     Running tests/session.rs                       test result: ok. 22 passed; 0 failed; 1 ignored
     Running unittests src/lib.rs (veil_relay)      test result: ok. 18 passed; 0 failed
     Running tests/logs.rs                          test result: ok. 1 passed; 0 failed
     Running tests/relay.rs                         test result: ok. 18 passed; 0 failed
     Running tests/smoke.rs                         test result: ok. 0 passed; 0 failed; 2 ignored
     Running unittests src/lib.rs (veil_wire)       test result: ok. 5 passed; 0 failed
```

### Deployed stack (rebuilt image at the round-2 fixes, firewall rule at `priority mangle`)

```text
coturn, relay-minted credentials:
  -y -c (client↔client)                       Total lost packets 0 (0.000000%)
  -c -e 10.0.0.1                              channel bind: error 403 (Forbidden IP)
  wrong password                              ERROR: Cannot complete Allocation
  -c -e <host IP> -r 40000 (host listener)    Total lost packets 5 (100%); listener: udp packets received = 0
  -c -e <host IP> -r 40001 (Docker-published) Total lost packets 5 (100%)
  same, rule at priority filter (round-1)     Total lost packets 0 (0.000000%) → CI step exit=1
relay log lines after smoke + probes: 1; coturn lines other than the firewall-drop line: 0
soak: deposited 9600 × 64 KiB (600 MiB) into 2 mailboxes in 20.166669228s; docker stats 96.36MiB / 512MiB
  +128 s after the soak: OOMKilled=false Restarts=0 Running=true; docker stats 96.11MiB / 512MiB; smoke round trip ok
docker compose stop relay: stopped in 299 ms, ExitCode=0, "veil-relay stopped"
```

**Still not verified:**
- the systemd unit on a real systemd host (this sandbox has no systemd);
- arm64 / Raspberry Pi;
- a real home router (option B);
- IPv6 clients behind Docker's proxy (P3R2-7);
- the `relay-deploy` job on GitHub's runners with these changes (pending the push).

The P3R2-9 refusal is proven by the unit test only. A deployed volume from the previous image opened normally, because the smoke tests had deleted their mailboxes, so the database was empty, and an empty database is stamped.

## Phase 3: after review round 1 fixes (2026-10-19)

Review round 1 returned **FAIL**: 2 High, 6 Medium, 5 Low (`docs/REVIEW_REPORT.md`). Every finding was addressed. Each new test was mutation-checked: the fix was reverted or broken by hand, the test failed, the fix was restored.

| Finding | Fix | Test (mutant that fails it) |
|---|---|---|
| **P3-1 (High)** OOM: redb 1 GiB cache + full-table sweep | Explicit page cache (64 MiB, `VEIL_DB_CACHE_MB`). Expiry index table `kind ‖ due ‖ id`; sweep reads only due keys, 256 per write transaction. | `store::tests::sweep_touches_only_due_records` (nothing due → 0 records read; 300 due → 300 read in 2 batches). Container soak in CI (`deployed_relay_soak` + inspect). |
| **P3-2 (High)** `FF…` token rows escape deletion | `prefix_end = prefix ‖ FF×33` covers every suffix ≤ 32 bytes | `ff_prefixed_tokens_are_deleted_with_their_mailbox` (delete and idle paths). Restoring the `FF×16` bound fails it. `nothing_is_left_behind` (no row in any table, index included) |
| P3-3 no write timeout | 30 s timeout on every write; `max_write_buffer_size`; relay-wide 64 MiB response budget for `Fetch`/`BlobGet` | `a_client_that_stops_reading_is_dropped` (removing the timeout fails it after 15 s); `responses_draw_on_a_relay_wide_budget` |
| P3-4 one host takes every slot | In-memory per-source cap (32; IPv4 address or IPv6 /64), forgotten at zero; 30 s pre-authentication timeout | `connections_are_capped_per_source_and_must_authenticate` (disabling the cap fails it; disabling the pre-auth timeout fails it) |
| P3-5 creation budget drained by bad requests | Per-connection creation limit; validate key and id before spending the relay-wide budget | `mailbox_creation_budget_cannot_be_drained_by_bad_requests` (spending the global budget first fails it) |
| P3-6 log test blind to blocking threads | Own test binary with a **global** subscriber; positive control from `spawn_blocking`; session adds blobs, TURN and delete | `tests/logs.rs`: M3 (log in handler) and M4 (log in `Store::deposit`) both fail it |
| P3-7 TLS 1.2 test vacuous | Probe verifier does real TLS 1.2 signature checks; asserts the server's `protocol_version` alert; positive control | Server offering TLS 1.2 too (M5) fails `tls_is_1_3_only_and_pinned` |
| P3-8 coturn relays to every host port | Required host rule `deploy/firewall/veil-turn.nft`: coturn relay sockets → this host's addresses only to the relay port range. Private-address `allowed-peer-ip` dropped. README and THREAT_MODEL corrected (TURN is open to anyone) | CI probe: host UDP listener on port 40000 must receive 0; without the rule the same script fails (5 received, exit 1) |
| P3-9 SIGTERM ignored | SIGTERM handled alongside SIGINT | CI: `docker compose stop relay` ≤ 5 s, exit 0, "veil-relay stopped" logged |
| P3-10 abandoned uploads hold quota 30 days | Incomplete blob expires with its upload token; complete blob gets the TTL from completion | `abandoned_uploads_expire_with_their_token` |
| P3-11 delete leaves other connections authed | Connections remember the auth key; every use re-checks it | `deleting_a_mailbox_revokes_other_connections` (dropping the re-check fails it) |
| P3-12 raw TURN secret not zeroized | `std::fs::read(..).map(Zeroizing::new)` | code review |
| P3-13 inaccurate docs | README, THREAT_MODEL §5, PROTOCOL §6.3/§14, ADR-0010 and INVARIANTS corrected | — |

Found while fixing:
- Frame-rate refusals replied with id 0, the push id, so clients could not match them. They now echo the request id (`frame_rate_limit_echoes_the_request_id`).
- The on-disk size measurement below led to lower default caps (envelopes 1 GiB, blobs 4 GiB; were 4 and 20).
- My earlier `turnutils_uclient -r veil` was a wrong flag (`-r` is the peer port, not the realm). It did not change any earlier result: `-y` ignores it, and the 403 checks fail on the address first. It is removed.

### Format, lint, tests

```text
$ cargo fmt --all --check                                         # exit 0
$ cargo clippy --workspace --all-targets --locked -- -D warnings  # exit 0
$ cargo test --workspace --locked                                 # exit 0 (condensed as before)
     Running unittests src/lib.rs (veil_core)       test result: ok. 74 passed; 0 failed
     Running tests/secrets.rs                       test result: ok. 3 passed; 0 failed
     Running tests/session.rs                       test result: ok. 22 passed; 0 failed; 1 ignored
     Running unittests src/lib.rs (veil_relay)      test result: ok. 14 passed; 0 failed
     Running tests/logs.rs                          test result: ok. 1 passed; 0 failed
     Running tests/relay.rs                         test result: ok. 15 passed; 0 failed
     Running tests/smoke.rs                         test result: ok. 0 passed; 0 failed; 2 ignored
     Running unittests src/lib.rs (veil_wire)       test result: ok. 5 passed; 0 failed
```

### Memory and expiry (the reviewer's benchmark crate, real `veil_relay::store::Store`)

Run in `docker run --memory=512m --memory-swap=512m` (distroless), with the DB on disk. A first attempt with the DB on tmpfs was OOM-killed during the fill, because tmpfs pages count against the writing container's memory; that run is discarded.

```text
fill 9600 × 64 KiB:   filled 9600 in 10.252428829s     VmHWM:   70880 kB   exit=0   (before: VmHWM 1086124 kB)
db.redb size:          2155876352 bytes  (≈ 3.4× the 630 MiB payload)
sweep, nothing due:    sweep removed 0 in 1.538018ms; second sweep 1.379357ms   VmHWM: 3608 kB   (before: 980 ms, 1053444 kB, OOMKilled under 512m)
expire all:            expire removed 9600 in 767.80085ms   VmHWM: 36340 kB   exit=0
```

### Deployed stack (`deploy/`, rebuilt image, run as the CI job runs it)

```text
SPKI SHA-256 pin: caa4da4a…; 2 running
smoke deployed_relay_round_trip ... ok
coturn, firewall rule loaded:
  -y -c (client↔client)         Total lost packets 0 (0.000000%)
  -c -e 10.0.0.1                channel bind: error 403 (Forbidden IP)
  wrong password                ERROR: Cannot complete Allocation
  -c -e <host IP> -r 40000      host listener: udp packets received = 0     nft counter: packets 1 … drop
  same probe, rule removed      udp packets received = 5   → CI step exit=1
relay logs: 1 line (startup); coturn logs: only "udp send: Operation not permitted" (the firewall drop; no address)
soak: deposited 9600 × 64 KiB (600 MiB) into 2 mailboxes in 20.192327591s
  +103 s: OOMKilled=false Restarts=0 Running=true; docker stats 91.57MiB / 512MiB; smoke round trip ok
docker compose stop relay: stopped in 533 ms, ExitCode=0, log "veil-relay stopped"   (before: 10.3 s, exit 137)
restart on the 600 MiB database: smoke ok; 2.715MiB in use; volume 1.2G
```

Locally the soak used 600 MiB because the disk here had only about 4 GB free. CI soaks 1.1 GB (with `VEIL_QUOTA_ENVELOPES_MB=2048`).

**Still not verified:**
- arm64 / Raspberry Pi;
- a home NAT deployment (hairpin) with the narrowed `allowed-peer-ip`;
- soak runs longer than a few minutes;
- the `relay-deploy` job on GitHub's runners with these changes (pending the push).

## Phase 3: relay, wire protocol, deployment (2026-10-19), before review

Local, Ubuntu 24.04 container, rustc 1.97.0, Docker 29.8.2.

### Format, lint, tests

```text
$ cargo fmt --all --check                                         # exit 0
$ cargo clippy --workspace --all-targets --locked -- -D warnings  # exit 0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.33s
$ cargo test --workspace --locked                                 # exit 0 (condensed: each "Running" line joined to its result line; doc-test lines omitted)
     Running unittests src/lib.rs (veil_core)       test result: ok. 74 passed; 0 failed
     Running tests/secrets.rs                       test result: ok. 3 passed; 0 failed
     Running tests/session.rs                       test result: ok. 22 passed; 0 failed; 1 ignored
     Running unittests src/lib.rs (veil_relay)      test result: ok. 10 passed; 0 failed
     Running tests/relay.rs                         test result: ok. 10 passed; 0 failed
     Running tests/smoke.rs                         test result: ok. 0 passed; 0 failed; 1 ignored
     Running unittests src/lib.rs (veil_wire)       test result: ok. 5 passed; 0 failed
```

The ignored session test is the Phase 2 timing benchmark. The ignored smoke test needs a running relay; its results against the container are below.

Relay integration tests (`crates/relay/tests/relay.rs`, each against the real TLS + WebSocket server on 127.0.0.1 with a fresh self-signed certificate and a pinning client):

```text
test pairing_and_messages_through_the_relay_reveal_no_identity ... ok   # INV-META-1, INV-META-2 (DB), INV-PAIR-2, INV-ID-1
test mailbox_authentication_is_strict ... ok                            # bad sig, replayed nonce, stale time, foreign nonce, no auth
test deposits_need_a_token_and_trigger_pushes ... ok
test deposits_are_rate_limited_per_token ... ok
test blobs_upload_resume_and_download ... ok
test turn_credentials ... ok
test tls_is_1_3_only_and_pinned ... ok                                  # INV-NET-2 (relay side)
test hostile_frames_are_refused_without_harm ... ok                     # INV-ROB-1
test mailbox_creation_is_rate_limited ... ok
test relay_logs_nothing_about_clients ... ok                            # INV-META-2 / INV-LOG-1 (logs)
```

Relay unit tests:

```text
test limits::tests::bucket_bursts_then_refills ... ok
test limits::tests::key_count_is_bounded ... ok
test store::tests::mailbox_tokens_deposit_fetch_ack ... ok
test store::tests::envelope_bytes_are_capped_and_released ... ok
test store::tests::invites_are_single_use_and_capped ... ok
test store::tests::blobs_bind_tokens_and_complete ... ok
test store::tests::sweep_expires_everything_on_time ... ok
test tls::tests::generate_load_and_pin ... ok
test turn::tests::format_and_mac ... ok
test turn::tests::hmac_sha1_rfc2202 ... ok
```

Wire unit tests: `roundtrip_and_validation`, `strict_decoding_rejects_unknown_and_trailing_fields`, `server_frames_are_validated_too`, `auth_message_layout`, `arbitrary_bytes_never_panic` (proptest).

**Mutation checks** (each mutant applied by hand, test run, mutant reverted):
- Logging the mailbox id at debug level in the deposit handler → `relay_logs_nothing_about_clients` fails.
- Dropping the byte release in the idle-mailbox sweep → `envelope_bytes_are_capped_and_released` fails.
- Dropping the byte release in `delete_mailbox` → `envelope_bytes_are_capped_and_released` fails.

### Fuzzing (cargo-fuzz 0.13.2, nightly-2026-10-01, `-O`)

New target `wire_frames`. It decodes arbitrary bytes as both client and server frames, and requires every accepted frame to re-encode byte-identically and pass validation again.

```text
$ cargo +nightly-2026-10-01 fuzz run -O wire_frames corpus/wire_frames -- -max_total_time=180 -max_len=70000 -rss_limit_mb=2048
#1202	INITED cov: 1814 ft: 5546 corp: 1180/280Kb exec/s: 0 rss: 63Mb
#6395687	DONE   cov: 1825 ft: 5717 corp: 1238/341Kb lim: 70000 exec/s: 35335 rss: 496Mb
Done 6395687 runs in 181 second(s)
$ cargo +nightly-2026-10-01 fuzz cmin -O wire_frames corpus/wire_frames -- -max_len=70000 -rss_limit_mb=2048
MERGE-OUTER: 1217 new files with 5728 new features added; 1836 new coverage edges
```

0 crashes. The minimised corpus (1 217 files) is committed. An earlier 180 s run on the first corpus gave 7.6 M runs, also with 0 crashes. `wire_frames` is in the CI smoke matrix (60 s) and in `fuzz-nightly.yml`.

### Container deployment (`deploy/`)

The image was built from `deploy/Dockerfile` (45.2 MB, distroless). This sandbox's egress needs a proxy CA, so the build used a scratch copy that adds only `COPY --from=ca ca-bundle.crt` and `CARGO_HTTP_CAINFO`; the committed Dockerfile is otherwise unchanged. `docker compose` then ran relay + coturn exactly as `deploy/README.md` describes.

```text
$ docker compose run --rm relay gen-cert /data/tls localhost 127.0.0.1
SPKI SHA-256 pin: a6e41d74b9038135052bf6551b725d256f8685a03d23dfdc0cc4f57ce53889e3
$ docker compose run --rm relay gen-cert /data/tls other.name          # exit 1, key kept
veil-relay: a key already exists there; delete it first to rotate (clients must re-pin)
$ VEIL_SMOKE_ADDR=127.0.0.1:8443 VEIL_SMOKE_PIN=a6e4… cargo test -p veil-relay --test smoke -- --ignored
test result: ok. 1 passed; 0 failed      # wrong pin refused; mailbox, token, deposit, fetch, 3 TURN creds, delete
# coturn with relay-minted credentials (turnutils_uclient from the pinned coturn image), external IP 192.0.2.2:
-y -c -n 20 -m 1 -l 170 (valid creds, client↔client through two allocations)
    INFO: Total lost packets 0 (0.000000%), total send dropped 0 (0.000000%)
-c -e 10.0.0.1 (peer in a denied range)        INFO: channel bind: error 403 (Forbidden IP)
-c -e 192.168.1.1                               INFO: channel bind: error 403 (Forbidden IP)
-y with a wrong password                        ERROR: Cannot complete Allocation
-y with no credentials                          ERROR: Cannot complete Allocation
$ docker compose logs relay | wc -l   → 1   (startup line: listen, pin, turn=true)
$ docker compose logs coturn | wc -l  → 0
```

The gen-cert refusal message shown is from the current build. The first container build printed the older generic "cannot read or write the certificate/key files", which led to the clearer `TlsError::Exists`.

Container checks:
- relay: uid 65532, read-only root, `CapDrop=[ALL]`, `no-new-privileges`;
- coturn: uid 65534, read-only root, `CapAdd=[NET_BIND_SERVICE]` and effective capabilities `0000000000000000` at runtime. `NET_BIND_SERVICE` stays only because `/usr/bin/turnserver` carries it as a file capability (`security.capability` xattr, bit 10), without which exec fails with EPERM, as observed;
- the TURN secret is not in coturn's `/proc/1/cmdline` or `/proc/1/environ` (0 matches).

CI job `relay-deploy` repeats these steps on every push. coturn's per-user quota (4 allocations) is real: the first attempt, which reused one credential for all three checks, hit `486 Allocation Quota Reached`, so the smoke test now mints a fresh credential per check.

**Not verified:** an arm64 (Raspberry Pi) build or run; the image is only built for amd64 here. There is also no load or soak test.

### Supply chain

```text
$ cargo deny --locked check      → advisories ok, bans ok, licenses ok, sources ok
$ cargo audit --deny warnings    → Scanning Cargo.lock for vulnerabilities (263 crate dependencies), exit 0
                                   (the first attempt failed on a crates.io 503 during the yank check; the retry passed)
$ cargo vet --locked             → Vetting Succeeded (43 fully audited, 5 partially audited, 207 exempted)
```

The Phase 3 relay dependencies are exempted, not reviewed by us (`supply-chain/README.md`).

### Known limits after Phase 3

- **Relay TLS is not post-quantum** (*ring* has no ML-KEM; ADR-0010). Message content is PQ end to end; relay-visible metadata is exposed to harvest-now-decrypt-later.
- **Open mailbox creation:** anyone can exhaust the storage caps, which denies new deposits (THREAT_MODEL §5). The caps bound disk use.
- ~~**No load or soak test** of the relay; the sweeper scans all envelopes once a minute (fine at Pi scale, untested at large scale).~~ *Wrong: review round 1 (P3-1) showed the full scan plus redb's 1 GiB default cache OOM-kills the relay at about 600 MB stored. Fixed; see the next section up.*
- **Plain `turn:`** by default; `turns:` needs a publicly trusted certificate.
- **arm64 image not built or tested** here.
- The ≥ 1 h nightly fuzz runs still have no recorded run.
- Client-side halves of INV-NET-2, INV-META-1 (real transport) and INV-LOG-1 come in Phase 4.

## Phase 2: after review round 5 conditions (2026-10-19)

Review round 5 returned **PASS WITH CONDITIONS**: it verified the round-4 fixes (including byte-identical seed regeneration, and that the Kyber change is equivalent to libsignal's own `generate`), with nothing Critical, High or Medium open. It raised five Lows and a nit.

| Finding | Outcome |
|---|---|
| R5-1 Kyber step / bad-proof branch reached only once per fixture | **Fixed.** New `cfg(fuzzing)` hook `fuzz_has_invite`. Both targets rebuild the fixture as soon as an input has consumed Bob's re-key invite, so the Kyber step and both proof branches stay reachable for later inputs. The `contact_plaintext` seed writer now checks the invite's fate: a valid proof consumes it, a bad proof and an unknown id leave it. Temporary probe (reverted): in 60 s, `contact_inner` rebuilt once after consumption; `contact_plaintext` rebuilt twice after consumption and twice periodically. |
| R5-2 coverage figures did not reproduce | **Fixed.** The round-4 `-runs=0` rows are struck through and "no jump" is corrected (see above). A throwaway fixture is now built and dropped at start-up, so setup *and* teardown are in the baseline. New figures, with commands: |
| R5-3 nothing pinned the injected-RNG Kyber key | **Fixed.** `pairing_tests::invite_keys_come_only_from_the_callers_rng`: same seeds give a byte-identical sealed package and Kyber key. Mutation check: reverting to `KyberPreKeyRecord::generate` fails it. |
| R5-4 RNG contract undocumented | **Fixed.** Doc comments on `Account::create`, `create_invite` and `redeem_invite`, plus PROTOCOL §4.2 "Randomness": callers must pass an OS-seeded CSPRNG, which now also supplies the ML-KEM prekey. |
| R5-5 stale seed writer | **Fixed.** `write_contact_inner_seeds` (round 2) deleted. Only the harness writer remains. |
| N1 misplaced doc comment | **Fixed.** |

Reproducible figures (committed build; scratch corpus copies under the session scratchpad; `cargo +nightly-2026-10-01 fuzz run -O <t> <copy> -- …`; 0 crashes):

| Measurement | contact_inner | contact_plaintext |
|---|---|---|
| `-runs=0`, committed corpus minus the `seed-*` files | INITED 9378 | INITED 10 828 |
| `-runs=0`, committed corpus | INITED 9750, which reviewer round 6 showed is the **low mode** of a bimodal figure: 9886–9920 in 30 of 35 runs, 9744–9798 in 5 (R6-N1). **The genuine seeds add ~370–540 edges.** | INITED 10 896 (**the re-key seeds add ~70**) |
| `-max_total_time=180` | 49 300 runs, 9795 → 9952 | 15 931 runs, 10 897 → 10 954 |
| Steps of ≥ 15 edges | **+119 at run 765:** per reviewer round 6 (R6-N1), this is a low-mode INITED (9795) catching up to the usual ~9912. Earlier note, kept: a re-run with `-runs=3000 -print_pcs=1` started at INITED 9912 and showed no such step. The new PCs there are libsignal's skipped-message-key handling, i.e. real fuzz progress | +16 at run 4396; no step at any re-pair |

`cargo test --workspace --locked`: 74 / 3 / 22 (+1 ignored: the `seed-body-*` writer) / 0, all pass. The unit count went from 73 (+1 ignored) to 74 (+0): one new test, and the stale ignored writer was deleted. Clippy is clean, normal and `--cfg fuzzing`.

## Phase 2: after review round 4 conditions (2026-10-19)

Review round 4 returned **PASS WITH CONDITIONS**: nothing Critical, High or Medium, and three Lows (R4-1 to R4-3). Two of the three were mistakes in my round-3 report: the deferral reasons were wrong, and a test I reported as added never landed.

| Finding | Outcome |
|---|---|
| R4-1 the R3-1/R3-2 deferral reasons were false | **Corrected, and R3-1/R3-2 are now fixed, not deferred.** (a) The Kyber prekey of an invite is now generated from the caller's CSPRNG (`kem::KeyPair::generate` plus `KyberPreKeyRecord::new`) instead of libsignal's internal OsRng, so every invite key comes from one injected source. (b) The fuzz fixture (`fuzz_targets/pairing.rs`) pairs from a fixed-seed `StdRng`; `assert_deterministic` checks that two pairings give byte-identical state. (c) Seeds are written by the targets themselves (`VEIL_WRITE_SEEDS=…`), and each is replayed on a fresh fixture before it is written: all 5 genuine `contact_inner` seeds open (4 Whisper, plus 1 PreKey that redeems Bob's live re-key invite through PQXDH and the Kyber step); the `contact_plaintext` re-key seeds take their branches (valid proof → accepted and consumed, bad proof → `AuthFailed`, unknown id → ignored). (d) Both targets return on empty input *before* touching the fixture, so setup coverage is in the INITED baseline. |
| R4-2 canonicalisation/dedupe untested | **Fixed.** Assertion added to `candidate_case_and_extensions_canonicalised`. The script now asserts that its edit applied. Mutation check: reverting component canonicalisation, extension-number canonicalisation or dedupe each fails the test. The comment now says "first *valid* occurrence wins". |
| R4-3 `gen.py` docstring | **Fixed.** `gen.py` and the generated header now give the exact regenerate command, including `rustfmt`. Regenerated: only the header lines changed. |

Fuzzing (scratch corpus copies, 0 crashes):

| Target | Duration | Runs | INITED cov → end | Notes |
|---|---|---|---|---|
| ~~contact_inner, before / with the genuine seeds (`-runs=0`)~~ | n/a | n/a | ~~3429 → 6028~~ | *Withdrawn (review round 5, R5-2): measured on an intermediate harness build that built the fixture during libFuzzer's discarded empty run. Does not reproduce on the committed build; see the round-5 section.* |
| contact_inner | 150 s | 46 432 | 9877 → 9910 | Baseline includes setup and the seeds |
| ~~contact_plaintext, before / with the re-key seeds (`-runs=0`)~~ | n/a | n/a | ~~6068 → 6246~~ | *Withdrawn (R5-2), same reason.* |
| contact_plaintext | 150 s | 14 152 | 10 803 → 10 952 | No *setup* jump across seven re-pairs. *Correction (R5-2): "no jump" was not quite true; the reviewer measured +66 edges at the first re-pair, from tearing down the old fixture. Fixed in round 5 by dropping a throwaway fixture at start-up.* |

`cargo test --workspace --locked`: 73 (+1 ignored) / 3 / 22 (+1 ignored) / 0, all pass. Clippy is clean, including `--cfg fuzzing`.

## Phase 2: after review round 3 conditions (2026-10-19)

Review round 3 returned **PASS WITH CONDITIONS**: nothing Critical, High or Medium open, no regressions, and five new Lows (R3-1 to R3-5).

| Finding | Outcome |
|---|---|
| R3-1 `contact_plaintext` coverage inflated; invite-proof branches unreachable | *Superseded in round 4: the reasons given here were wrong (R4-1), and the item is now fixed, not deferred.* **Claim corrected; deeper reach deferred to Phase 8.** Re-measured over 300 s on a scratch corpus: `INITED cov 6275` → `6282` just before the re-pair at input #2001 → jump to `10171` (setup code that libFuzzer credits to that input) → `10356` at the end. **The gain driven by fuzz input is small; the earlier "4325 → 10 057" was mostly setup.** Pairing twice at start-up was tried and did *not* move the jump, so the change was reverted, not kept. The invite-proof branches need a live random invite id and proof, which no committed corpus can hold; they are covered by the mutation-checked unit test `known_contact_rekey_invite_paths`. |
| R3-2 `contact_inner` seeds come from another pairing | *Superseded in round 4: the reason given here was wrong (R4-1), and the item is now fixed.* **Deferred to Phase 8.** A deterministic pairing is impossible from the harness: libsignal's `KyberPreKeyRecord::generate` draws from its own OS RNG. Documented in the target. |
| R3-3 the `::` rule was not pinned by a test | **Fixed.** `a=mid:x::` added. Mutation check: allowing unspecified addresses again fails `addresses_outside_candidates_removed` on that input. |
| R3-4 STUN caveat missing in PROTOCOL §8 | **Fixed in the docs; the end-to-end check is Phase 6.** PROTOCOL §8 and INV-NET-1 now say the SDP filter cannot stop the WebRTC stack's own STUN checks; only `iceTransportPolicy: relay` (and the `webrtc-rs` configuration on Linux) can. |
| R3-5 vectors job tied to Python 3.12 | **Fixed.** `requirements.txt` now also pins the CPython 3.13 `cffi` wheel. Verified: a fresh 3.13 venv installs with `--require-hashes` and regenerates byte-identical vectors. |
| Round-2 nits | Candidate numbers are re-emitted canonically (`+1` → `1`), each candidate extension is kept at most once, and PROTOCOL §6 now states that a bucket with fewer than 2 bytes of slack is skipped. *Correction (review round 4, R4-2): this row originally said "test added". That was false: the scripted edit adding the assertion silently failed to apply. The test was added in round 4; see below.* |

```
$ cargo clippy --workspace --all-targets -- -D warnings   # clean
$ cargo test --workspace --locked                          # 73 (+1 ignored) / 3 / 22 (+1 ignored) / 0, all passed
```

## Phase 2: after review round 2 conditions (2026-10-19)

Review round 2 returned **PASS WITH CONDITIONS**: the round-1 Highs are confirmed fixed, there are no new Critical or High findings, one new Medium (N1) and eight new Lows (N2–N9). All of them were addressed. Local: Ubuntu 24.04, rustc 1.97.0.

```
$ cargo fmt --all --check                                   # exit 0
$ cargo clippy --workspace --all-targets -- -D warnings     # clean
$ RUSTFLAGS="--cfg fuzzing" cargo clippy -p veil-core --lib -- -D warnings   # clean (fuzz-only hooks; now a CI job)
$ cargo test --workspace --locked
test result: ok. 73 passed; 0 failed; 1 ignored; ...   # unit (src/); the ignored one writes fuzz seeds
test result: ok. 3 passed; 0 failed; ...                # tests/secrets.rs
test result: ok. 22 passed; 0 failed; 1 ignored; ...    # tests/session.rs; the ignored one writes fuzz seeds
test result: ok. 0 passed; 0 failed; ...                # doctests
$ cargo deny --locked check      # advisories ok, bans ok, licenses ok, sources ok
$ cargo audit --deny warnings    # exit 0 (one documented ignore)
$ cargo vet --locked             # Vetting Succeeded (36 fully audited, 2 partially audited, 159 exempted)
```

| Finding | Change and evidence |
|---|---|
| N1 `contact_plaintext` never reached content handling | The hook pads its input like real content (raw mode is chosen by the first byte); 18 seeds, one per body variant, plus re-key intros; the pair is re-created every 2 000 inputs so the ratchet cannot wedge. 600 s: 54 824 runs, 0 crashes. *Correction (review round 3, R3-1): the "cov 4325 → 10 057" stated here mostly came from the mid-run re-pairing at input #2001; see the round-3 section for the honest figure.* |
| N2 INV-PAIR-1 test did not isolate the identity check | The attacker re-signs both prekeys. The test now **fails when the identity check is removed** (mutation-checked) |
| N3 re-key path untested | `pairing_tests::known_contact_rekey_invite_paths`: valid proof consumes; bad, foreign-bound or expired proofs are refused with no state change; unknown id is ignored |
| N4 docs | PROTOCOL §8 rewritten for the allowlist filter; mDNS is dropped in every mode (code, docs and `ice.rs` header now agree); ADR-0009 records the `groupId` filler composition, *Proposed, owner approval pending* |
| N5 secrets | Decoded attachment keys, mailbox capabilities, invite proofs and re-key links are zeroized on drop. `InviteRecordPb` lost `Clone`/`PartialEq`. `Opened`'s `Debug` prints no address or key |
| N6 `inout` audit | The AI-written audit was replaced by a documented **exemption**. Its note is corrected: libsignal's AES-CBC/PKCS7 does use the changed function |
| N7 largest valid text could not be sealed as a first message | Probe: the PreKey phase fits 63 203 bytes and the Whisper phase 63 488. `MAX_BODY_LEN` is now 61 KiB. `largest_valid_content_always_seals` seals the largest `Text`, `Edit`, ICE and SDP content in both phases |
| N8 `contact_inner` wasted inputs | The type selector is weighted to PreKey/Whisper; genuine PreKey (2 030 B, with Kyber) and Whisper seeds. 420 s: **127 480 runs, cov 8748**, 0 crashes |
| N9 weak oracles, stale numbers | The ICE proptest and the fuzz target check output with an independent substring scan; loopback is allowed only on the exact rebuilt `o=` line. INV numbers corrected. CI now regenerates the vectors with the hash-pinned Python oracle and diffs them |
| M3 remainder | v3 PreKey message → `UnsupportedVersion`; certificate for another device id → `AuthFailed` |
| L2 nit | `::ffff:0:a.b.c.d` (IPv4-translated) is judged by its IPv4 |

- **Fuzzing found another real gap.** The stricter `ice_sdp` oracle found that `v=`, `t=` and `b=` lines were passed through verbatim (a fuzz input carried `::` in a `v=` line).
- **The fix.** Those lines are now validated, and a kept `a=` line with any IP literal, `::` included, rejects the SDP. The input is seeded as `corpus/ice_sdp/regress-v-line`.
- **Re-run:** 300 s, **4 518 572 runs**, 0 crashes. `realistic_offer_passes` still passes.

Still open, unchanged: the ≥ 1 h nightly fuzz runs have not run yet; libsignal's key types are not zeroized; 159 cargo-vet exemptions; **no independent audit**.

## Phase 2: after review round 1 fixes (2026-10-19)

Review round 1 returned **FAIL** (3 High, 5 Medium, 8 Low; see [`REVIEW_REPORT.md`](REVIEW_REPORT.md)). Every finding was fixed with a regression test, or documented below where it is out of Phase 2's reach. Local: Ubuntu 24.04, rustc 1.97.0.

### Format, lint, tests

```
$ cargo fmt --all --check                                   # no output, exit 0
$ cargo clippy --workspace --all-targets -- -D warnings     # no warnings
$ cargo test --workspace --locked
test result: ok. 72 passed; 0 failed; ...   # unit (src/), was 59
test result: ok. 3 passed; 0 failed; ...    # tests/secrets.rs
test result: ok. 21 passed; 0 failed; ...   # tests/session.rs, was 14
test result: ok. 0 passed; 0 failed; ...    # doctests
```

96 tests, up from 76. Regression tests per finding:

| Finding | Test(s) |
|---|---|
| H1 envelope size leak | `relay_learns_only_the_bucket`; `every_bit_flip_rejected_and_state_unchanged` now also covers the sealed-sender version byte |
| H2 non-atomic commit | `failed_commit_changes_nothing_and_retry_succeeds` (also asserts one backend batch per transaction) |
| H3 / M1 / L2 / L3 ICE filter | `relay_only_sdp_never_leaks` (proptest over whole SDPs; also run with `PROPTEST_CASES=20000`), `addresses_outside_candidates_removed`, `candidate_case_and_extensions_canonicalised`, `relay_candidates_must_be_public`, `direct_drops_private_and_mdns`, `dtls_validation`, `realistic_offer_passes` |
| M2 Debug leaks | `debug_output_never_contains_content_or_secrets` |
| M3 untested downgrade / certificate claims | `downgraded_messages_refused`, `certificate_key_must_match_sealing_key` |
| M4 rollback after decrypt | `account::rollback_tests::*`. **Mutation check:** with `transact` changed to commit on error, both tests fail; restored afterwards |
| M5 fuzzing depth | new fuzz targets `contact_inner`, `contact_plaintext` (below) |
| L1 vault KDF cost | `tampered_cost_parameters_refused_before_kdf` |
| L4 chunk re-encryption | `encrypt_chunk` made private; `every_encryption_uses_a_fresh_key` |
| L5 sealed-sender v2 | exact `0x11` version byte required (bit-flip test) |
| L6 silent invite deletion | `delete_invite` now fails the transaction |
| L7 weak tests | `every_body_variant_roundtrips`, `strangers_and_self_addressed_envelopes_dropped`, `pairing_tests::package_with_swapped_identity_or_signature_refused`, `pairing_tests::one_time_prekeys_deleted`, `safety::tests::known_answer`, `attachment::tests::known_answer_multi_chunk` |
| L8 CI | gitleaks pinned by SHA-256; fuzz lockfile `--locked` check; crash inputs printed on failure; nightly 1 h fuzz workflow |

The new known-answer vectors come from `crates/core/tests/vectors/gen.py`. Its fingerprint code reproduces libsignal's own published vector (`300354477692869396892869876765458257569162576843440918079131`) before emitting Veil's.

### Fuzzing (cargo-fuzz 0.13.2, nightly-2026-10-01, `-O`)

| Target | Duration | Runs | Final coverage (cov / ft) | Crashes |
|---|---|---|---|---|
| contact_inner (new) | 600 s | 172,491 | 8391 / 10661 | 0 |
| contact_plaintext (new) | 600 s | 9,427 | 4325 / 6193 | 0 |
| ice_sdp (new output check) | 300 s | 3,800,321 | — | 0 after the fix below |
| envelope_unframe (framing v2) | 20 s | 9,438,043 | — | 0 |

- **Fuzzing found a real bug.** The strengthened `ice_sdp` check found that the `m=` line tail was passed through unvalidated (`m=application 9 UDP/DTLS/SCT typ relay raddr 05.0.0.2 …`). This is fixed and seeded into the corpus.
- **Coverage.** The old `account_open` target peaked at 794 edges because random input never passes the sealed-sender MAC. The two new targets act as an authenticated contact.
- **Throughput is low.** `contact_plaintext` manages about 16 inputs per second, since every input does real sealing and decryption.
- **No 1-hour runs yet.** The ≥ 1 h runs (`fuzz-nightly.yml`) are scheduled but have not run yet. INV-MSG-5 therefore stays *partial*.

### Miri (pure modules, after the envelope and ICE rewrites)

```
$ PROPTEST_CASES=4 MIRIFLAGS=-Zmiri-disable-isolation cargo +nightly-2026-10-01 miri test -p veil-core --lib -- padding:: envelope:: ice:: trust:: content::
test result: ok. 31 passed; 0 failed; 0 ignored; 0 measured; 41 filtered out; finished in 219.41s
```

### Supply chain

```
$ cargo deny --locked check
advisories ok, bans ok, licenses ok, sources ok
$ cargo audit --deny warnings     # 1338 advisories, 203 crates; exit 0 with the one documented ignore
$ cargo vet --locked
Vetting Succeeded (36 fully audited, 3 partially audited, 158 exempted)
```

`inout 0.2.3` was yanked upstream on 2026-10-16, which turned CI red (run 39252191570). The lockfile now uses 0.2.4. Its delta audit in `supply-chain/audits.toml` was written by the AI agent and is marked as **not yet confirmed by a human**.

### Known limits that remain

- libsignal's `IdentityKeyPair` / `PrivateKey` are `Copy` and are not zeroized.
- A PreKey (first) message never fits the 1 KiB bucket, so the relay can tell a session's first messages by their 4 KiB size.
- 158 crates are only exempted in cargo vet, libsignal among them.
- There has been **no independent audit.** An independent security audit is required before real-world sensitive use.

## Phase 2: crypto core `veil-core` (2026-10-15), before review

Local: Ubuntu 24.04, rustc 1.97.0, libsignal v0.105.0 @ 4beb029d. CI: run [38761908514](https://github.com/bewwe01/ataraxia/actions/runs/38761908514) on commit cfa8d58.

### Format, lint, tests

```
$ cargo fmt --all --check                                   # no output, exit 0
$ cargo clippy --workspace --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.57s
$ cargo test --workspace
test result: ok. 59 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 16.99s   # unit (src/)
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.49s     # tests/secrets.rs
test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 17.76s   # tests/session.rs
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s     # doctests
```

76 tests in total. The test-to-invariant map is in [`INVARIANTS.md`](INVARIANTS.md). The headline tests:
- `pqxdh_and_spqr_are_active`: v4 PQXDH with a 1569-byte ML-KEM ciphertext, then SPQR data on every message.
- `every_bit_flip_rejected_and_state_unchanged`: every bit of an envelope is flipped one at a time; each is rejected and the genuine message still opens.
- `ratchet_properties::shuffled_dropped_duplicated`: proptest of random order, drops and duplicates.
- `keys_and_nonce_prefixes_unique`: 10^6 attachment keys and nonces, no repeats.
- Known-answer vectors for address, fingerprint, vault unlock and attachments, generated by an independent Python oracle (`crates/core/tests/vectors/gen.py`: argon2-cffi plus pyca/cryptography).

### Fuzzing (cargo-fuzz 0.13.2, nightly-2026-10-01, `-O`, 180 s per target)

| Target | Runs | Final coverage (cov / ft) | Crashes |
|---|---|---|---|
| envelope_unframe | 69,015,391 (+34,490,888 after seeding) | 56 / 71 | 0 |
| content_decode | 8,618,420 | 1384 / 4213 | 0 |
| invite_link | 32,396,284 | 302 / 703 | 0 |
| vault_header | 54,466,831 (+3,048,175 after seeding) | 893 / 1545 | 0 |
| ice_sdp | 20,185,863 | 157 / 407 | 0 |
| account_open | 2,381,226 (+3,594,666 after seeding) | 794 / 1649 | 0 |

The minimized corpora are committed under `crates/core/fuzz/corpus/`. CI repeats a 60 s smoke run per target. This is short: the planned ≥ 1 h nightly runs (INV-MSG-5) are not set up yet.

### Miri (pure modules)

```
$ PROPTEST_CASES=4 MIRIFLAGS=-Zmiri-disable-isolation cargo +nightly-2026-10-01 miri test -p veil-core --lib -- padding:: envelope:: ice:: trust:: content::
test result: ok. 26 passed; 0 failed; 0 ignored; 0 measured; 33 filtered out; finished in 554.63s
```

Miri does not run modules that call into libsignal or Argon2; they are too slow under the interpreter.

### Supply chain

```
$ cargo deny --locked check
advisories ok, bans ok, licenses ok, sources ok
$ cargo audit --deny warnings          # 1329 advisories, 203 crates; exit 0 with one documented ignore (RUSTSEC-2026-0173)
$ cargo vet --locked
Vetting Succeeded (36 fully audited, 2 partially audited, 159 exempted)
```

The 159 exemptions are unreviewed by us (see [`supply-chain/README.md`](../supply-chain/README.md)).

### Known limits after Phase 2

- libsignal's `IdentityKeyPair` / `PrivateKey` are `Copy` and are not zeroized on drop. Veil cannot fix this without patching libsignal.
- Two claims are argument-only, not tested:
  - INV-MSG-6, because there is no API to forge a certificate under a foreign key. The check was confirmed in libsignal `sealed_sender.rs` (constant-time comparison of the certificate key with the message key).
  - The INV-CRY-3 v3-message rejection, because libsignal cannot produce a v3 message.
- Only the core part of each invariant is covered. The relay, UI, calls and OS-keystore parts are tested in later phases (see [`INVARIANTS.md`](INVARIANTS.md)).
- There has been no independent audit.

## Phase 1: spikes (2026-10-15)

### Spike A: libsignal (local, Ubuntu 24.04, rustc 1.97.0)

`cd spikes/libsignal && cargo run --release`

```
# cargo run --release  (2026-10-15, rustc 1.97.0, libsignal v0.105.0 @ 4beb029d)
PASS PQXDH: Alice processes Bob's bundle (EC + signed Kyber1024 prekey) (Ok(()))
PASS first message is PreKeySignalMessage v4+ with ML-KEM ciphertext (version 4, KEM ciphertext 1569 bytes)
PASS Bob decrypts first message
PASS 40 alternating messages decrypt (Double Ratchet steps)
PASS SPQR triple ratchet active: post-quantum ratchet data present in messages (40/40 messages carried SPQR data)
PASS bit-flip at every byte of a SignalMessage is rejected (105/105 rejected)
PASS genuine message still decrypts after tamper attempts
PASS replayed message is rejected (Err(DuplicatedMessage(2, 1)))
PASS out-of-order delivery (reverse order) decrypts
PASS changed identity key is refused (UntrustedIdentity) (Err(UntrustedIdentity(ProtocolAddress { name: "bob", device_id: DeviceId(1) })))
PASS bundle with forged Kyber prekey signature is rejected (Err(SignatureValidationFailed))
ALL CHECKS PASSED

# crypto-relevant dependencies (cargo tree -e normal)
aes v0.9.3
aes-gcm-siv v0.12.1
curve25519-dalek v5.0.0
curve25519-dalek-derive v0.1.1 (proc-macro)
hkdf v0.13.0
hmac v0.13.0
libcrux-hacl-rs v0.0.5
libcrux-hmac v0.0.8
libcrux-intrinsics v0.0.8
libcrux-macros v0.0.3 (proc-macro)
libcrux-ml-kem v0.0.10
libcrux-platform v0.0.3
libcrux-secrets v0.0.6
libcrux-sha2 v0.0.8
libcrux-sha3 v0.0.10
libcrux-traits v0.0.8
libsignal-core v0.1.0 (https://github.com/signalapp/libsignal?tag=v0.105.0#4beb029d)
libsignal-debug v0.105.0 (https://github.com/signalapp/libsignal?tag=v0.105.0#4beb029d)
libsignal-protocol v0.1.0 (https://github.com/signalapp/libsignal?tag=v0.105.0#4beb029d)
sha2 v0.11.1
signal-crypto v0.1.0 (https://github.com/signalapp/libsignal?tag=v0.105.0#4beb029d)
spqr v1.6.0 (https://github.com/signalapp/SparsePostQuantumRatchet.git?tag=v1.6.0#06959b47)
subtle v2.6.1
veil-spike-libsignal v0.0.0 (/home/user/ataraxia/spikes/libsignal)
x25519-dalek v3.0.0
zeroize v1.9.1
zeroize_derive v1.5.0 (proc-macro)
total unique crates: 117
```

### Spike B: WebRTC in Tauri/WebKitGTK (local, Xvfb)

`VEIL_PROBE_EXIT=1 xvfb-run -a spikes/webrtc-probe/src-tauri/target/release/veil-webrtc-probe` (and with `VEIL_ENABLE_WEBRTC=1`)

```
# mode: default
VEIL_PROBE_INFO webkit enable-webrtc default=false media-stream default=true
VEIL_PROBE_RESULT {"userAgent":"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/60.5 Safari/605.1.15","origin":"tauri://localhost","secureContext":true,"RTCPeerConnection":"undefined","RTCDataChannel":"undefined","getUserMedia":true,"RTCRtpScriptTransform":"undefined","mediaDeviceKinds":[]}
# mode: enabled
VEIL_PROBE_INFO webkit enable-webrtc default=false media-stream default=true
VEIL_PROBE_INFO set enable-webrtc=true enable-media-stream=true
VEIL_PROBE_RESULT {"userAgent":"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/60.5 Safari/605.1.15","origin":"tauri://localhost","secureContext":true,"RTCPeerConnection":"undefined","RTCDataChannel":"undefined","getUserMedia":true,"RTCRtpScriptTransform":"undefined","mediaDeviceKinds":[]}
```

This is a negative result: WebRTC is unavailable in the Linux webview. See `docs/SPIKES.md` §B and ADR-0003.

### Spike C: Tauri 2 on Android (GitHub Actions, emulator)

GitHub Actions `spike-android`, run 38746889576 (conclusion: **success**). Excerpt of the job log:

```
android_version=14
abi=x86_64
webview_versionName=113.0.5672.136
Performing Streamed Install
Success
Status: ok
LaunchState: COLD
TotalTime: 3613
I VeilProbe: veil_webrtc_probe_lib: VEIL_PROBE_RESULT {"userAgent":"Mozilla/5.0 (Linux; Android 14; sdk_gphone64_x86_64 Build/UE1A.230829.050; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/113.0.5672.136 Mobile Safari/537.36","origin":"http://tauri.localhost","secureContext":true,"RTCPeerConnection":"function","RTCDataChannel":"function","getUserMedia":true,"RTCRtpScriptTransform":"undefined","loopbackAll":{"ok":true,"ms":1431,"candidates":{"a":["host/udp","host/udp"],"b":["host/udp","host/udp"]},"fingerprintInSdp":true},"relayPolicyAccepted":true,"generateCertificate":true,"mediaDeviceKinds":["audioinput","videoinput","audiooutput"]}
=== libsignal spike on device
PASS PQXDH: Alice processes Bob's bundle (EC + signed Kyber1024 prekey) (Ok(()))
PASS first message is PreKeySignalMessage v4+ with ML-KEM ciphertext (version 4, KEM ciphertext 1569 bytes)
PASS Bob decrypts first message
PASS 40 alternating messages decrypt (Double Ratchet steps)
PASS SPQR triple ratchet active: post-quantum ratchet data present in messages (40/40 messages carried SPQR data)
PASS bit-flip at every byte of a SignalMessage is rejected (105/105 rejected)
PASS genuine message still decrypts after tamper attempts
PASS replayed message is rejected (Err(DuplicatedMessage(2, 1)))
PASS out-of-order delivery (reverse order) decrypts
PASS changed identity key is refused (UntrustedIdentity) (Err(UntrustedIdentity(ProtocolAddress { name: "bob", device_id: DeviceId(1) })))
PASS bundle with forged Kyber prekey signature is rejected (Err(SignatureValidationFailed))
ALL CHECKS PASSED
```

Also from that run: `target/aarch64-linux-android/release/veil-spike-libsignal: ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /system/bin/linker64`.

Earlier runs, kept for honesty:
- 38741826807 failed: Android rejects app version `0.0.0`.
- 38742060429 failed: APK and libsignal Android builds succeeded, then "No space left on device" while fetching the emulator image.
- 38744023740 failed: the probe page never reported, because the eval-navigation was lost on Android. libsignal passed 11/11 on the device in that run.

## Phase 0: design checks (2026-10-15)

`cd design/tools && node capture.mjs && node check.mjs`

- `capture.mjs`: `OK: 280 screenshots, 0 console errors, 0 CSP violations, 0 network requests`
- `check.mjs`: `PASS`. The full report is in [`design/CHECKS.md`](../design/CHECKS.md):
  - 2,304 contrast pairs ≥ 4.5:1;
  - axe: 0 violations across 244 renders;
  - all targets ≥ 44 px;
  - motion uses transform/opacity only, and nothing runs under reduced motion;
  - 0 network requests;
  - 7/7 keyboard interactions pass.
