# Discovery seed — `discovery.junctus.org`

An ultra-cheap **discovery seed**: it helps neo nodes find each other and serves
**no user traffic**. A $5/mo VPS with 1 vCPU / 1 GB is plenty. It holds only
public, signed relay records in memory — nothing sensitive persists except its
own witness key.

## What it does

1. Relays `POST /register` their signed [`PeerRecord`]s.
2. The seed **verifies** each record (self-certifying id + node signature) and
   **dial-back health-checks** it (completes a neo handshake to prove the
   operator controls both the advertised address and the key).
3. The seed **attests** the healthy set by signing a snapshot as a *witness*.
4. Clients `GET /snapshot`, verify the witness signature(s), and connect — they
   never learn *which* relay a given client will use, because everyone fetches
   the whole set.

Because snapshots are witness-signed, this box is **untrusted for integrity**:
Caddy, a CDN, or a mirror cannot forge or edit a snapshot a client will accept.
Run several independent seeds and require a k-of-n witness threshold to remove
any single operator (including you) as a trust root.

## Endpoints

| Route | Purpose |
|-------|---------|
| `GET /snapshot`  | Current witness-signed relay snapshot (binary). |
| `GET /healthz`   | Liveness + attested relay count. |
| `GET /witness`   | This seed's witness public key (hex) — bake into clients. |
| `POST /register` | A relay submits its signed record (per-IP rate limited). |

## Install

On a fresh Ubuntu 22.04+ server with DNS `A`/`AAAA` for the domain pointing at it:

```bash
# 1. Get a Linux binary onto the box (either build target):
#    - from a dev machine:  scripts/build-release.sh linux   (needs Docker)
#    - or on the server:    cargo build --release -p neo-cli
# 2. Run the installer with the binary path:
sudo DOMAIN=discovery.junctus.org ./install.sh ./neo-x86_64-unknown-linux-gnu
```

The installer creates a hardened `neo-seed` systemd service (localhost:8899),
installs Caddy with automatic HTTPS for the domain, starts both, and prints the
**witness key** to bake into clients.

## After install: make clients trust it

Add the printed witness key to `BAKED_WITNESSES` in
`platforms/desktop/src/defaults.rs` (and confirm `BAKED_MIRRORS` has your
domain), then rebuild and distribute clients. For quick testing without a
rebuild:

```bash
export NEO_MIRRORS="https://discovery.junctus.org"
export NEO_WITNESSES="<witness key hex from install output or GET /witness>"
neo run           # zero-config client: discovers a relay and connects
```

## Operations

```bash
systemctl status neo-seed caddy
journalctl -u neo-seed -f
curl -s https://discovery.junctus.org/healthz
```

The witness key lives at `/var/lib/neo-seed/witness.key` (mode 0600, owned by
`neo-seed`). Back it up: regenerating it changes the identity clients trust.

[`PeerRecord`]: ../../core/crates/neo-discovery/src/lib.rs
