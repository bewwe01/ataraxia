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
  any small Linux VPS. 1 GB RAM is plenty.
* Docker Engine with the compose plugin: `curl -fsSL https://get.docker.com | sh` or your distro's
  packages.
* About 2 GB of disk for the build, plus space for queued messages and attachments (capped by the
  relay's quotas).

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

Start everything:

```sh
docker compose up -d
docker compose ps        # both services "running"
docker compose logs relay
```

The relay logs one startup line (listen address, pin, whether TURN is on) and nothing about clients.
coturn is configured to log nothing at all, because its logs would contain client IP addresses.

### Check it from another machine (optional)

With Rust installed and a clone of this repository:

```sh
VEIL_SMOKE_ADDR=<relay ip>:8443 VEIL_SMOKE_PIN=<pin> \
  cargo test -p veil-relay --test smoke -- --ignored
```

This connects with a wrong pin (must be refused), then with the right one. It creates a mailbox,
deposits and fetches a test envelope, asks for TURN credentials and deletes the mailbox.

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
  * Only clients holding relay-minted credentials (HMAC, 1 h lifetime, authenticated mailboxes only)
    can allocate.
  * No CLI and no TCP relay endpoints. Quotas per user and in total, plus a bandwidth cap.
  * Peers in private, loopback, link-local, CGNAT/Tailscale, documentation and multicast ranges are
    refused (tested: `403 Forbidden IP`), so nobody can use your TURN server to reach your LAN or
    tailnet.
  * The only exception is the server's own `TURN_EXTERNAL_IP`, which relayed calls need.

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
* **Not audited.** Treat this as a carefully built but independently unverified system.
