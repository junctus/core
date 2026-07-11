#!/usr/bin/env bash
#
# Install a neo relay/exit node as a systemd service.
#
#   sudo ANNOUNCE_ADDR=<public-host:port> [BIND=0.0.0.0:443] [EXIT=1] \
#     ./install.sh /path/to/neo
#
# ANNOUNCE_ADDR is the address clients and the seed will dial (your public IP and
# the relay port). BIND is what the process listens on. EXIT=1 offers clearnet
# exit (egress under this server's IP — expect possible abuse complaints); set
# EXIT=0 for a forward-only relay.
#
# The port in ANNOUNCE_ADDR/BIND must be open inbound in your firewall/security
# group, both for client connections and for the seed's dial-back health check —
# a relay is only attested (and thus listed) once that dial-back succeeds.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"

BIN_SRC="${1:?usage: sudo ANNOUNCE_ADDR=host:port ./install.sh <neo-binary>}"
[[ -x "$BIN_SRC" ]] || { echo "not an executable: $BIN_SRC"; exit 1; }
ANNOUNCE_ADDR="${ANNOUNCE_ADDR:?set ANNOUNCE_ADDR=<public-host:port>}"
BIND="${BIND:-0.0.0.0:443}"
if [[ "${EXIT:-1}" == "1" ]]; then EXIT_FLAG="--exit"; else EXIT_FLAG=""; fi

echo ">> installing neo binary to /usr/local/bin/neo"
install -m 0755 "$BIN_SRC" /usr/local/bin/neo

echo ">> creating neo-relay system user and state dir"
if ! id neo-relay >/dev/null 2>&1; then
  useradd --system --home /var/lib/neo-relay --shell /usr/sbin/nologin neo-relay
fi
install -d -o neo-relay -g neo-relay -m 0750 /var/lib/neo-relay

echo ">> generating the relay identity (if absent)"
# Create the identity up front, owned by the service user, so its node id can be
# printed deterministically. The relay would otherwise create it on first boot.
if [[ ! -f /var/lib/neo-relay/relay.key ]]; then
  sudo -u neo-relay /usr/local/bin/neo identity generate \
    --output /var/lib/neo-relay/relay.key >/dev/null
fi
NODE_ID="$(/usr/local/bin/neo identity show --identity /var/lib/neo-relay/relay.key 2>/dev/null \
  | awk -F': ' '/node id/{print $2; exit}')"

echo ">> installing systemd service"
sed -e "s|__ANNOUNCE_ADDR__|${ANNOUNCE_ADDR}|g" \
    -e "s|__BIND__|${BIND}|g" \
    -e "s|__EXIT__|${EXIT_FLAG}|g" \
    "$HERE/neo-relay.service" > /etc/systemd/system/neo-relay.service
systemctl daemon-reload
systemctl enable --now neo-relay.service

sleep 2
cat <<EOF

============================================================
 neo relay installed.

   role        : $([[ -n "$EXIT_FLAG" ]] && echo "relay + clearnet exit" || echo "forward-only relay")
   listen      : ${BIND}
   advertised  : ${ANNOUNCE_ADDR}
   node id     : ${NODE_ID}

 The relay registers with the baked-in discovery seeds automatically.

 IMPORTANT — open the relay port inbound in your firewall / cloud security
 group (the port in ${ANNOUNCE_ADDR}). It is needed both for client
 connections AND for the seed's dial-back health check; until it succeeds the
 relay is registered but NOT attested, so it will not appear in snapshots.

 Status:  systemctl status neo-relay
 Logs:    journalctl -u neo-relay -f
 Check:   neo snapshot   # should list this relay once the port is open
============================================================
EOF
