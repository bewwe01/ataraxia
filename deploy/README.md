# Running a Veil relay

The relay is the only server in Veil. It stores end-to-end-encrypted envelopes until the recipient
fetches them, holds single-use invites and encrypted attachment chunks, and mints short-lived TURN
credentials. coturn, next to it, forwards encrypted call media when two phones can't reach each other
directly, which in Veil's default relay-only mode is always.

**What the relay can see:** connection times, envelope sizes (padded to 1, 4, 16 or 64 KiB) and
counts, random mailbox IDs, and, for as long as a connection is open, the IP addresses of connected
devices. It never sees message content, names, contact lists or identity keys, and it never writes
IP addresses to disk or logs (`docs/THREAT_MODEL.md`, `docs/INVARIANTS.md` INV-META-1, INV-LOG-1).
The person who runs the relay, or anyone who controls the machine, can still watch traffic at the
network level, so run it on hardware you control. This software has not had an independent security
audit.

## What you need

* A Raspberry Pi 4 or 5 running a **64-bit** OS (Raspberry Pi OS Lite 64-bit or Ubuntu Server), or
  any small Linux VPS with 1 GB RAM. The relay's memory is bounded by its database cache
  (`VEIL_DB_CACHE_MB`, default 64). Measured with 600 MiB of queued messages: 92 MiB in use, under a
  container limit of 512 MiB.
* Docker Engine with the compose plugin: `curl -fsSL https://get.docker.com | sh` or your distro's
  packages.
* About 2 GB of disk for the build, plus room for the database.
  * Queued messages and attachments are capped at 1 GiB and 4 GiB by default (`VEIL_QUOTA_ENVELOPES_MB`,
    `VEIL_QUOTA_BLOBS_MB` in `.env`).
  * The database file is larger than what it stores. Measured with 630 MB of queued messages: the
    file's apparent size was 2.16 GB (redb grows in large steps), and about 2× the payload was
    actually allocated. Budget **3.5× the caps** to be safe, about 18 GB free for the defaults, and
    lower the caps on a small SD card.
  * Two kinds of small records are capped separately, so they cannot grow without bound either:
    - delivery-token rows: at most 1 000 000 relay-wide, about 165 MB;
    - live upload tokens: at most 20 000, about 3 MB.
  * Anyone who can reach the relay can create a mailbox, so these caps are what keep a stranger from
    filling the disk. When a cap is reached, new deposits are refused until old data expires (see
    *Known limits*).
* `nftables` on the host (standard on Raspberry Pi OS, Debian and Ubuntu) for the TURN firewall rule.

The image builds for `amd64` and `arm64` from the same Dockerfile (base images are pinned by
multi-arch digest). It has been built and tested on amd64 only. The first build on a Pi compiles
the relay from source and will take a while.

## Choose how phones reach the relay

| Option | Good for | Needs |
|---|---|---|
| **A. VPS with a public IP** | Easiest; works from any network | A VPS (~€4/month) |
| **B. Pi at home, port forwarding** | No monthly cost | Router access, a public IPv4 (not CGNAT), dynamic DNS |
| **C. Pi at home over Tailscale** | No open ports at home | Tailscale on the Pi **and on every phone/PC**, always on |

Ports, for A and B:

| Port | Protocol | Purpose |
|---|---|---|
| 8443 | TCP | Relay (TLS 1.3, WebSocket) |
| 3478 | UDP + TCP | TURN |
| 49160–49259 | UDP | TURN relay ports (one per call leg) |

**B. Home Pi:**
1. Give the Pi a fixed LAN address (a DHCP reservation in the router).
2. Forward the ports above to it.
3. Set up dynamic DNS (e.g. your router's DDNS client, or duckdns.org) so a name follows your home
   IP.

If your ISP uses CGNAT (the router's WAN address starts with 100.64–100.127, or differs from what
whatismyip shows), forwarding cannot work: use A or C.

**C. Tailscale:** nothing is exposed to the internet, and phones reach the Pi through the tailnet.
The trade-off: Tailscale's coordination service learns which of your devices exist and when they're
online (not what they send), and every device needs the Tailscale app running. Use the Pi's tailnet
address (`tailscale ip -4`, `100.x.y.z`) everywhere below.

## Set up

From a clone of this repository, on the Pi or VPS:

```sh
cd deploy
cp .env.example .env
nano .env          # set TURN_EXTERNAL_IP and VEIL_TURN_URLS (see below)

# Shared secret between the relay and coturn. Never commit it; it's in .gitignore.
mkdir -m 0700 secrets
openssl rand -hex 32 > secrets/turn_secret
chmod 0644 secrets/turn_secret   # the containers run as non-root users; the 0700 directory keeps it private

docker compose build
```

Set `.env`:

* **A (VPS):** `TURN_EXTERNAL_IP=<public IP>` and
  `VEIL_TURN_URLS=turn:<public IP or name>:3478?transport=udp,turn:<public IP or name>:3478?transport=tcp`.
* **B (home Pi):** `TURN_EXTERNAL_IP=<home public IP>/<Pi LAN IP>`, e.g. `203.0.113.7/192.168.1.20`,
  and use your DDNS name in `VEIL_TURN_URLS`. If your home IP changes, update `.env` and run
  `docker compose up -d` again. (coturn needs the IP itself, not a name.)
* **C (Tailscale):** `TURN_EXTERNAL_IP=100.x.y.z` and `VEIL_TURN_URLS=turn:100.x.y.z:3478?transport=udp,turn:100.x.y.z:3478?transport=tcp`.

Create the relay's TLS key and certificate. List every name or IP clients will use:

```sh
docker compose run --rm relay gen-cert /data/tls relay.example.org 203.0.113.7
```

This prints the relay's **SPKI pin**, for example:

```text
SPKI SHA-256 pin: fc529ccbf03c507f8d5497ee3686fbc5b3463164cfb8b627edd9a98958d99982
```

Write it down. Clients trust the relay **only** by this pin, not by any certificate authority, so a
self-signed certificate is fine and no domain or Let's Encrypt is needed. In the app (Phase 4) you
enter the relay address and this pin once; it's also embedded in invite QR codes. You can print it
again any time:

```sh
docker compose run --rm relay pin /data/tls/cert.pem /data/tls/key.pem
```

Install the TURN firewall rule (**required**, see *Hardening* for why) so that it loads on every
boot, before Docker starts:

```sh
sudo install -m 0644 firewall/veil-turn.nft /etc/veil-turn.nft
sudo install -m 0644 firewall/veil-turn-firewall.service /etc/systemd/system/
sudo install -D -m 0644 firewall/docker-veil-turn.conf /etc/systemd/system/docker.service.d/veil-turn.conf
sudo systemctl daemon-reload
sudo systemctl enable --now veil-turn-firewall
sudo systemctl restart docker          # picks up the drop-in
sudo nft list table inet veil_turn     # shows the rule
```

It only stops coturn's relay sockets from reaching services on this host, including services that
Docker publishes; nothing else changes. Two safeguards:
- The rule is re-applied whenever `nftables.service` starts, restarts or reloads. Debian's default
  `/etc/nftables.conf` begins with `flush ruleset`, which would otherwise drop it.
- The Docker drop-in refuses to start Docker if the rule is not loaded, so coturn never runs
  without it.

Stopping the firewall unit does not stop Docker or your other containers.

Start everything:

```sh
docker compose up -d
docker compose ps        # both services "running"
docker compose logs relay
```

The relay logs one startup line (listen address, pin, whether TURN is on), one line on shutdown,
and nothing about clients. coturn's logging is switched off, because its logs would contain client
IP addresses. Its only output is the address-free line `udp send: Operation not permitted`,
printed when the firewall rule blocks a relay packet.

### Check it from another machine (optional)

With Rust installed and a clone of this repository:

```sh
VEIL_SMOKE_ADDR=<relay ip>:8443 VEIL_SMOKE_PIN=<pin> \
  cargo test -p veil-relay --test smoke -- --ignored
```

This connects with a wrong pin (must be refused), then with the right one. It creates a mailbox,
deposits and fetches a test envelope, asks for TURN credentials and deletes the mailbox.

`deployed_relay_soak` (same variables plus `VEIL_SOAK_MB=600`) loads that many megabytes of
messages, to check memory on your hardware. It only uses space up to the caps, and the messages
expire after 14 days. Run it only on a relay you are about to reset.

## Running it

* **Updates:** `git pull && docker compose build && docker compose up -d`. Data and the TLS key live
  in the `veil_relay-data` volume and survive rebuilds.
* **Backups:** the only thing worth backing up is the TLS key (`/data/tls/key.pem` in the volume).
  If you lose it, every client must re-pin a new relay. Queued messages are ciphertext and expire on
  their own. Copy the key out with `docker cp $(docker compose ps -q relay):/data/tls ./tls-backup`,
  store it offline and encrypted, and delete the local copy.
* **Rotating the TLS key:** `gen-cert` refuses to overwrite an existing key. The simplest reset is
  `docker compose down && docker volume rm veil_relay-data`, which also drops queued messages and
  mailboxes. Then run `gen-cert` again and give clients the new pin.
* **Rotating the TURN secret:** write a new `secrets/turn_secret`, then `docker compose up -d
  --force-recreate`. Calls in progress drop.
* **Firewall (VPS):** allow only the ports in the table above, e.g. with `ufw`. Note that Docker's
  published ports bypass `ufw` rules; the relay's 8443 is meant to be public anyway.
* **Debugging coturn:** temporarily replace `no-stdout-log` and `syslog` in `coturn/turnserver.conf`
  with `verbose`, recreate, and switch back when done: those logs contain IP addresses.

## Hardening that's already in place

* **Relay container:** distroless base, no shell, uid 65532, read-only root filesystem, all
  capabilities dropped, `no-new-privileges`, memory and PID limits. The only writable path is
  `/data`.
* **coturn container:**
  * uid 65534, read-only root, `no-new-privileges`.
  * All capabilities dropped except `NET_BIND_SERVICE`, which stays in the bounding set only
    because the image's `turnserver` binary carries it as a file capability. Its effective set at
    runtime is empty.
  * The secret is written to a tmpfs config file (mode 0600) by a shell builtin, so it never
    appears in a process's arguments or environment.
* **TURN:**
  * Allocations need relay-minted credentials (HMAC, 1 h lifetime), which the relay gives to any
    authenticated mailbox. Mailbox creation is open, so in practice **anyone can use your TURN
    server**, like any public TURN service. Per-user and total quotas, a bandwidth cap, no CLI and
    no TCP relay endpoints limit what they can do.
  * Peers in private, loopback, link-local, CGNAT/Tailscale, documentation and multicast ranges are
    refused (tested: `403 Forbidden IP`), so nobody can use your TURN server to reach your LAN or
    tailnet.
  * The one exception is the server's own `TURN_EXTERNAL_IP`, because both legs of a call are
    relayed through it. Without the firewall rule, that exception would let anyone send UDP to
    *every* service listening on that address (DNS, Pi-hole, WireGuard, ...).
  * `firewall/veil-turn.nft` restricts coturn's relay sockets, towards this host's own addresses, to
    the relay port range. It runs before Docker's NAT, so services Docker publishes are covered too.
  * Tested in CI:
    - a host UDP service received 0 of 5 relayed packets;
    - a Docker-published UDP service lost 5 of 5 with the rule, and was reachable when the rule ran
      after Docker's NAT, as the first version did;
    - calls still relay with 0 loss.
  * Option B (`public/private` external IP): the review reproduced the coturn side, and calls relay
    through the public address without router hairpin NAT. A real home router was not tested.
* **Relay connections:**
  * Each connection's source (IPv4 address or IPv6 /64) is kept in memory only, never logged or
    stored, to bound what one host can take:
    - at most 32 concurrent connections;
    - at most 8 MiB of the 64 MiB response budget;
    - 10 mailbox creations, then 1 per minute;
    - 30 upload tokens, then 1 per minute.
  * The rate buckets keyed by source are dropped once they refill (within about 10 min for
    creation and 30 min for upload tokens). A memory image of the relay therefore holds the
    addresses of currently connected clients and of recently active ones, not of everyone since
    it started.
  * If clients reach the relay through something that hides their address, they all count as one
    source. That happens behind a reverse proxy, and behind Docker's userland proxy for IPv6
    clients of this IPv4-only container. Raise `VEIL_MAX_CONN_PER_SOURCE` then: every per-source
    allowance above scales with it (64 doubles them all). Better still, let real addresses
    through, for example with IPv6 enabled on the Docker network.
  * Each mailbox can always hold 64 delivery tokens, however full the relay-wide cap for tokens
    beyond that is. Token changes and acknowledgements are limited to 20, then 1 per second, per
    mailbox, and requests that change nothing are not written.
  * A connection must authenticate a mailbox, or deliver, upload or download something, within 30 s.
  * Every write to a client has a 30 s timeout.
  * A mailbox that is never authenticated is deleted after 24 h; an authenticated one after 60
    days without use.
  * `docker stop` shuts the relay down cleanly (SIGTERM).

## Known limits

* **No post-quantum TLS** between apps and relay yet (the relay uses rustls with *ring*, which has no
  ML-KEM). Message *content* is post-quantum protected end to end (PQXDH + SPQR), but the metadata
  the relay sees could be recorded today and decrypted by a future quantum attacker who also
  recorded the traffic. See ADR-0010 in `docs/ARCHITECTURE.md`.
* **Plain `turn:`, not `turns:`.** Call media is DTLS-SRTP-encrypted end to end, but an on-path
  observer can see that you're using TURN. `turns:` requires a certificate from a public CA, because
  WebRTC doesn't accept pinned certificates for TURN.
* **IP addresses in memory.** The relay must hold connected clients' IP addresses in memory while
  they're connected, and coturn must hold them for the length of a call. Neither writes them
  anywhere.
* **Open mailbox creation.** The relay doesn't know who its users are, by design, so anyone can
  create mailboxes and use up the storage caps. That stops new messages and uploads, but it can't
  read or delete anything already stored. Rate limits don't really slow it down: with many tokens per
  mailbox, an attacker can fill the caps as fast as their uplink allows.
* **Denial of service.** These are denials of service, not data exposure. Each relay-wide limit
  needs this many attacking sources, with the defaults (IPv6 makes sources cheap: one /48 holds
  65 536 /64s):

  | Limit | Sources needed | Effect while exhausted |
  |---|---|---|
  | Delivery tokens beyond each mailbox's 64 | **1**, over about 37 h of mailbox creation | Mailboxes with more than 64 tokens (about 64 contacts) cannot add more. Everyone keeps 64. |
  | Connection slots (1 024) | 32 | New connections refused |
  | Response budget (64 MiB) | 11 | Large fetches and downloads refused |
  | Mailbox creation (20, then 1 per second) | about 60, continuously | Onboarding and mailbox rotation refused |
  | Upload tokens (1 000 000 live) | about 680 | Attachment uploads refused |

  One host can also keep the database writer busy with real writes into its own mailboxes: deposits
  with its own tokens, up to the per-connection frame limits. The review measured a victim's
  deposit latency rising from 3.4 ms to 62 ms under a comparable load, on a fast disk. On an SD
  card it would be worse.
* **Not audited.** Treat this as a carefully built but independently unverified system.
