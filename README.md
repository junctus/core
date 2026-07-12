# neo

A dispersed, post-quantum, verifiable, censorship-resistant privacy overlay — a "new kind of VPN".

> **Status:** the network **runs end to end** — zero-config discovery finds relays
> ([`docs/DISCOVERY.md`](docs/DISCOVERY.md)) and real onion traffic is forwarded through live multi-hop
> circuits with a layered return path. The core (M0–M9), the frontier tier (M10–M13: anonymous
> credits, VRF paths, committee exit, PIR + ZK shuffle), and the hardening/expansion tier (M14–M20:
> a full internal security review with every finding fixed, plus streaming, NAT traversal, DoH
> bootstrap) all have working, tested implementations. **Not audited** — do not rely on neo for
> real-world safety. See [`docs/MILESTONES.md`](docs/MILESTONES.md) for status and
> [`docs/SECURITY_ANALYSIS.md`](docs/SECURITY_ANALYSIS.md) for the review.

## What makes it different

neo is not a Tor / Nym / WireGuard clone. Its core mechanism is **information slicing**: a flow is
encrypted and split via **k-of-n coding** into shares that travel *disjoint* multi-hop paths, so any
single node — or any group smaller than `k` — only ever holds a meaningless fragment. On top of that:

- **Fresh route + exit per request** — no two requests share a path.
- **Mixnet timing defense** — cover traffic + per-hop timing mixing to resist a global observer.
- **Post-quantum from day one** — PQ-hybrid handshakes and onion packets.
- **Committee exit (MPC-TLS)** — a k-of-n committee jointly performs each clearnet request, so no
  single node knows destination + content or is the sole originator.
- **Anonymous bandwidth credits** — unlinkable, token-free credits that resist Sybil attacks and
  free-riding at once.
- **Verifiable privacy** — PIR/oblivious discovery, VRF-unbiasable paths, ZK proof-of-mixing.

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

## Docs

| Doc | What |
|-----|------|
| [`ARCHITECTURE.md`](docs/ARCHITECTURE.md) | the design, the crate map, the request flow |
| [`MILESTONES.md`](docs/MILESTONES.md) | roadmap and live status (M0–M20 + audit gate) |
| [`PROTOCOL.md`](docs/PROTOCOL.md) | the per-flow wire pipeline and exit models |
| [`CRYPTO.md`](docs/CRYPTO.md) | primitives and the constructions built on them |
| [`DISCOVERY.md`](docs/DISCOVERY.md) | zero-config discovery, witnessed snapshots, Sybil/eclipse |
| [`MONETIZATION.md`](docs/MONETIZATION.md) | economic sustainability without breaking unlinkability |
| [`THREAT_MODEL.md`](docs/THREAT_MODEL.md) | adversaries, answers, honest limits |
| [`SECURITY_ANALYSIS.md`](docs/SECURITY_ANALYSIS.md) | the adversarial internal review and its fixes |
| [`SECURITY_REVIEW_4.md`](docs/SECURITY_REVIEW_4.md) | full-codebase review: findings, verdicts, fixes |

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

## License

AGPL-3.0-or-later (placeholder — revisit before any release).
