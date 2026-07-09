# neo

A dispersed, post-quantum, verifiable, censorship-resistant privacy overlay — a "new kind of VPN".

> **Status:** M0–M9 core mechanisms implemented and tested — full Sphinx, PQ-hybrid handshake,
> information slicing, timing mixing, obfuscated transport, exit policy, a real libp2p stack, and the
> mobile FFI. The network now **runs end to end**: zero-config discovery finds relays
> ([`docs/DISCOVERY.md`](docs/DISCOVERY.md)) and real onion traffic is forwarded through live
> multi-hop circuits. The frontier tier (M10–M13) has working, tested cores
> ([`docs/FRONTIER.md`](docs/FRONTIER.md)). **Not audited** — do not rely on neo for real-world safety.
> See [`docs/MILESTONES.md`](docs/MILESTONES.md).

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
inside the overlay; a young network has a small anonymity set). See `docs/ARCHITECTURE.md`.

## Repository layout

```
core/crates/      the shared Rust engine (all platforms use this)
platforms/desktop the macOS + Linux daemon/CLI (one cfg-gated binary)
platforms/ios     Swift app + NEPacketTunnelProvider (consumes the core via xcframework)
platforms/android Kotlin app + VpnService (consumes the core via cargo-ndk)
docs/             threat model, architecture, protocol, crypto notes
```

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
