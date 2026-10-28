#!/bin/sh
# Builds coturn's runtime config on a tmpfs so the shared TURN secret never appears on a command
# line (visible in /proc) or in the image, then starts turnserver.
set -eu

: "${TURN_EXTERNAL_IP:?set TURN_EXTERNAL_IP in deploy/.env}"
secret=$(cat /run/secrets/turn_secret)
case "$secret" in
  '' | *[!0-9A-Za-z]*) echo "coturn: the TURN secret must be letters and digits only" >&2; exit 1 ;;
esac
if [ "${#secret}" -lt 32 ]; then
  echo "coturn: the TURN secret must be at least 32 characters" >&2
  exit 1
fi

public=${TURN_EXTERNAL_IP%%/*}
# The address of this machine that the advertised one leads to: the part after "/", or the only
# one. Relays must use it whatever address a client came in on: through Tailscale Funnel clients
# arrive on 127.0.0.1, and coturn would otherwise relay from loopback while advertising this
# address, so their calls never connect (ADR-0018).
local_ip=${TURN_EXTERNAL_IP#*/}

umask 077
conf=/run/coturn/turnserver.conf
cat /etc/coturn/veil.conf > "$conf"
# printf is a shell builtin: the secret is not passed to any process's argv.
printf 'static-auth-secret=%s\n' "$secret" >> "$conf"
printf 'external-ip=%s\n' "$TURN_EXTERNAL_IP" >> "$conf"
printf 'relay-ip=%s\n' "$local_ip" >> "$conf"
# Both call legs are relayed through this server, so peers must reach the address it advertises
# even when that lies inside a denied range (LAN or Tailscale deployments). This also lets anyone
# with TURN credentials send UDP to *any* port on that address, so deploy/firewall/veil-turn.nft
# is required: it limits coturn's relay sockets to the relay port range on this host (P3-8).
printf 'allowed-peer-ip=%s\n' "$public" >> "$conf"
unset secret

exec turnserver -c "$conf"
