#!/usr/bin/env bash
#
# Install the neo discovery seed on Ubuntu (22.04+), fronted by Caddy TLS at
# discovery.junctus.org. Run as root on the target server:
#
#   sudo DOMAIN=discovery.junctus.org ./install.sh /path/to/neo-x86_64-unknown-linux-gnu
#
# The positional arg is the release `neo` binary built by scripts/build-release.sh
# (or `cargo build --release -p neo-cli` on the box itself). This installs a
# hardened systemd service and a Caddy site, starts them, and prints the witness
# public key you bake into clients.
#
set -euo pipefail

DOMAIN="${DOMAIN:-discovery.junctus.org}"
BIN_SRC="${1:-}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $EUID -ne 0 ]]; then echo "run as root" >&2; exit 1; fi
if [[ -z "$BIN_SRC" || ! -x "$BIN_SRC" ]]; then
  echo "usage: sudo DOMAIN=$DOMAIN $0 /path/to/neo-linux-binary" >&2
  exit 2
fi

echo ">> installing neo binary to /usr/local/bin/neo"
install -m 0755 "$BIN_SRC" /usr/local/bin/neo

echo ">> creating neo-seed system user and state dir"
if ! id neo-seed >/dev/null 2>&1; then
  useradd --system --home /var/lib/neo-seed --shell /usr/sbin/nologin neo-seed
fi
install -d -o neo-seed -g neo-seed -m 0750 /var/lib/neo-seed

echo ">> generating the witness identity (if absent)"
# Create the witness key up front, owned by the service user. The seed would
# also create it on first boot, but generating it here lets us read the witness
# public key deterministically — no dependence on the service being up yet.
if [[ ! -f /var/lib/neo-seed/witness.key ]]; then
  sudo -u neo-seed /usr/local/bin/neo identity generate \
    --output /var/lib/neo-seed/witness.key >/dev/null
fi

# The witness public key clients must trust — read straight from the key file.
WITNESS="$(/usr/local/bin/neo identity show \
  --identity /var/lib/neo-seed/witness.key --witness-only)"

echo ">> installing systemd service"
install -m 0644 "$HERE/neo-seed.service" /etc/systemd/system/neo-seed.service
systemctl daemon-reload
systemctl enable --now neo-seed.service

echo ">> installing Caddy (if absent) and the discovery site"
if ! command -v caddy >/dev/null 2>&1; then
  apt-get update
  apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update
  apt-get install -y caddy
fi

# The caddy package runs the service as the `caddy` user, so its access-log dir
# must be writable by that user — created here, after the package has added it.
install -d -o caddy -g caddy -m 0750 /var/log/caddy

# Install our site config. If the domain isn't the default, patch it in.
sed "s/discovery\.junctus\.org/${DOMAIN//./\\.}/g" "$HERE/Caddyfile" > /etc/caddy/Caddyfile
systemctl restart caddy

# Persist the trust info so the operator can find it again later.
cat > /var/lib/neo-seed/trust.txt <<TRUST
# neo discovery trust bundle for ${DOMAIN}
NEO_MIRRORS="https://${DOMAIN}"
NEO_WITNESSES="${WITNESS}"
TRUST

cat <<EOF

============================================================
 neo discovery seed installed.

   domain      : https://${DOMAIN}
   snapshot    : https://${DOMAIN}/snapshot
   health      : https://${DOMAIN}/healthz
   witness key : ${WITNESS}

 The witness key was generated automatically and saved to
 /var/lib/neo-seed/trust.txt. The seed is already serving.

 NEXT STEP — make clients trust this seed. Either:

   • Bake it in: add the witness key to BAKED_WITNESSES in
     platforms/desktop/src/defaults.rs, and confirm BAKED_MIRRORS
     contains https://${DOMAIN}, then rebuild and distribute clients.

   • Or, for testing, have users run:
       export NEO_MIRRORS="https://${DOMAIN}"
       export NEO_WITNESSES="${WITNESS}"
       neo run

 Check status:  systemctl status neo-seed caddy
 Logs:          journalctl -u neo-seed -f
============================================================
EOF
