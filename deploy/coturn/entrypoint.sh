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
private=${TURN_EXTERNAL_IP#*/}

umask 077
conf=/run/coturn/turnserver.conf
cat /etc/coturn/veil.conf > "$conf"
# printf is a shell builtin: the secret is not passed to any process's argv.
printf 'static-auth-secret=%s\n' "$secret" >> "$conf"
printf 'external-ip=%s\n' "$TURN_EXTERNAL_IP" >> "$conf"
# Both call legs are relayed through this server, so peers must reach its own address even when it
# lies inside a denied range (LAN or Tailscale deployments).
printf 'allowed-peer-ip=%s\n' "$public" >> "$conf"
if [ "$private" != "$TURN_EXTERNAL_IP" ]; then
  printf 'allowed-peer-ip=%s\n' "$private" >> "$conf"
fi
unset secret

exec turnserver -c "$conf"
