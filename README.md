# neo

A dispersed, post-quantum, verifiable, censorship-resistant privacy overlay — a "new kind of VPN".

> **Status:** the network is **live** — a discovery seed (discovery.junctus.org) and two attested
> relay/exit nodes run in production, and a native macOS VPN client ([`../neo-mac`](../neo-mac)) connects
> and browses through them. M0–M25, M28, and M36 are shipped and tested: the core, the frontier tier
> (anonymous credits, VRF paths, committee exit, PIR + ZK shuffle), streaming/NAT/DoH bootstrap, three
> rounds of internal security review with every finding fixed, and — the flagship — a **complete,
> adversarially-verified malicious-secure two-party MPC-TLS crypto stack** (M24) that now **runs live**
> against a real TLS 1.3 server (M45 ✅ — interop-verified against stock `rustls`, both semi-honest and
> malicious engines). The one gate before real-world use is the **external cryptography audit**.
> **Not audited** — do not rely on neo for real-world safety. See
> [`docs/MILESTONES.md`](docs/MILESTONES.md) for status.

## What makes it different

neo is not a Tor / Nym / WireGuard clone. Its core mechanism is **information slicing**: a flow is
encrypted and split via **k-of-n coding** into shares that travel *disjoint* multi-hop paths, so any
single node — or any group smaller than `k` — only ever holds a meaningless fragment. On top of that:

- **Fresh route + exit per request** — no two requests share a path.
- **Mixnet timing defense** — cover traffic + per-hop timing mixing to resist a global observer.
- **Post-quantum from day one** — PQ-hybrid handshakes and onion packets.
- **Committee exit (MPC-TLS)** — a k-of-n committee jointly performs each clearnet request, so no
  single node knows destination + content or is the sole originator.
- **Malicious-secure two-party MPC-TLS** — a complete, adversarially-verified 2PC stack (KOS malicious
  OT → authenticated garbling → SPDZ field arithmetic → the EC-point→pre-master bridge → HKDF key
  schedule, all under 2PC) so a TLS session's key and plaintext are *never assembled at one party*. Built
  and tested; live-session integration and the external audit are the remaining gates.
- **Anonymous bandwidth credits** — unlinkable, token-free credits that resist Sybil attacks and
  free-riding at once.
- **Verifiable privacy** — PIR/oblivious discovery, VRF-unbiasable paths, ZK verifiable shuffle.

There are real, honest limits (the anonymity trilemma; "no responsible exit" is fully achievable only
inside the overlay; a young network has a small anonymity set). See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Repository layout

```
core/crates/      the shared Rust engine (all platforms use this)
platforms/desktop the macOS + Linux daemon/CLI (one cfg-gated binary)
platforms/ios     Swift app + NEPacketTunnelProvider (consumes the core via xcframework)
platforms/android Kotlin app + VpnService (consumes the core via cargo-ndk)
deploy/discovery/ one-command discovery-seed deployment (systemd + Caddy)
docs/             see the index below
```

The shipping GUI/app clients live in sibling repos, on the same shared Rust core (`neo-netstack` +
`neo-node`):
- [`../neo-mac`](../neo-mac) — a **React Native** app shipping **macOS + Android (APK)** today (iOS from
  the same tree); the furthest-along client — connects and browses.
- [`../neo-linux`](../neo-linux) — a Rust **terminal app + systemd service** (ships a `.deb`) that routes
  a whole machine's traffic, one onion circuit per flow.

## Docs

| Doc | What |
|-----|------|
| [`ARCHITECTURE.md`](docs/ARCHITECTURE.md) | the design, the crate map, the request flow |
| [`MILESTONES.md`](docs/MILESTONES.md) | roadmap and live status (M0–M36 + audit gate) |
| [`PROTOCOL.md`](docs/PROTOCOL.md) | the per-flow wire pipeline and exit models |
| [`CRYPTO.md`](docs/CRYPTO.md) | primitives and the constructions built on them |
| [`DISCOVERY.md`](docs/DISCOVERY.md) | zero-config discovery, witnessed snapshots, Sybil/eclipse |
| [`THREAT_MODEL.md`](docs/THREAT_MODEL.md) | adversaries, answers, honest limits |
| [`SECURITY_REVIEW.md`](docs/SECURITY_REVIEW.md) | the living internal security review — cumulative findings across all rounds + their fixes |

## Build

```sh
cargo build
cargo test
cargo run -p neo-cli -- identity generate
```

## Run the network

`neo` finds the network with zero configuration — the only thing a client needs baked in (or via
`NEO_MIRRORS`/`NEO_WITNESSES`) is a discovery seed to bootstrap from. Deploy a seed at your own domain
with [`deploy/discovery/`](deploy/discovery/) (one command), or run the whole thing locally:

```sh
# 1. A discovery seed (finds peers, serves no user traffic).
neo seed --witness witness.key
export NEO_MIRRORS="http://127.0.0.1:8899"
export NEO_WITNESSES="$(neo identity show --identity witness.key --witness-only)"

# 2. A few relays that register with the seed and forward onion traffic.
neo run --relay --listen 127.0.0.1:9001 --announce-addr 127.0.0.1:9001 --identity r1.key
neo run --relay --listen 127.0.0.1:9002 --announce-addr 127.0.0.1:9002 --identity r2.key

# 3. Inspect what the seed attests, or route a message through a discovered circuit.
neo snapshot
neo send --message "no relay on this path can read me" --hops 2
```

Each relay peels one Sphinx layer and forwards to the next; only the exit sees the payload.
`neo run` with no flags is a zero-config client that discovers and connects to a relay.

## Run a relay or exit node

Relays *are* the network — anyone can run one, and more relays mean more paths and stronger
anonymity. A **relay** forwards onion traffic (it can never read it); an **exit** additionally
egresses the last hop to the clearnet under its own IP. Both register with the discovery seed
automatically and need no coordination with anyone.

### One command (systemd / Linux)

[`deploy/relay/`](deploy/relay/) installs a hardened `neo-relay.service` — dedicated system
user, `ProtectSystem=strict`, `MemoryDenyWriteExecute`, and binds `:443` via
`CAP_NET_BIND_SERVICE` without running as root:

```sh
cargo build --release -p neo-cli                       # build on the target OS
sudo ANNOUNCE_ADDR=<your-public-ip>:443 EXIT=1 \
  deploy/relay/install.sh target/release/neo
```

- **`ANNOUNCE_ADDR`** — the public `host:port` clients and the seed will dial (required).
- **`BIND`** — what the process listens on (default `0.0.0.0:443`).
- **`EXIT`** — `1` for a relay **+ clearnet exit** (egress under your IP; expect the occasional
  abuse complaint), `0` for a **forward-only relay** (near-zero abuse risk).

The identity persists at `/var/lib/neo-relay/relay.key`, so the relay keeps a stable node id —
and its attested listing — across restarts. **Never delete it.**

### Open the ports

Two inbound TCP ports must be open in your firewall / cloud security group:

- **The relay port** (the one in `ANNOUNCE_ADDR`, e.g. `443`) — for client connections and for
  the seed's **dial-back health check** (until it succeeds the relay is registered but *not*
  attested, so it won't appear in snapshots).
- **`9700`** — every relay also runs the networked 2PC-TLS co-processor endpoint (see below).
  Override the address with `--mpc2pc-listen`.

### Verify and manage

```sh
neo snapshot                     # your relay should be listed once the port is open
systemctl status neo-relay
journalctl -u neo-relay -f
```

### Manual (no systemd)

```sh
neo run --relay --exit --listen 0.0.0.0:443 --announce-addr <public-ip>:443 \
  --identity relay.key
```

Drop `--exit` for a forward-only relay. The baked-in seeds find the public network; point at
your own with `NEO_MIRRORS`/`NEO_WITNESSES`. On a low-RAM VPS the default LTO release profile
can OOM — build with `CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16`.

### The 2PC-TLS co-processor endpoint (always on)

Every relay serves a networked two-party 2PC-TLS endpoint in-process on **`0.0.0.0:9700`** —
running a relay means running this. Peers connect with `neo mpc2pc --connect <relay-ip>:9700`
(add `--full` for the whole networked handshake key agreement). Override the bind with
`--mpc2pc-listen <addr>` (or `MPC2PC=<addr>` to `install.sh`). Keep port `9700` open inbound.

## License

AGPL-3.0-or-later (placeholder — revisit before any release).
