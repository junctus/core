# neo

A dispersed, post-quantum, verifiable, censorship-resistant privacy overlay — a "new kind of VPN".

> **Status:** the network is **live** — a discovery seed (discovery.junctus.org) and two attested
> relay/exit nodes run in production, and a native macOS VPN client ([`../neo-mac`](../neo-mac)) connects
> and browses through them. M0–M25, M28, and M36 are shipped and tested: the core, the frontier tier
> (anonymous credits, VRF paths, committee exit, PIR + ZK shuffle), streaming/NAT/DoH bootstrap, three
> rounds of internal security review with every finding fixed, and — the flagship — a **complete,
> adversarially-verified malicious-secure two-party MPC-TLS crypto stack** (M24). The two gates before
> real-world use are the **external cryptography audit** and **live MPC-TLS integration** (the crypto is
> built; wiring it to a real TLS session is systems work). **Not audited** — do not rely on neo for
> real-world safety. See [`docs/MILESTONES.md`](docs/MILESTONES.md) for status.

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

The native **macOS VPN app** (the furthest-along client — connects and browses today) lives in the
sibling repo [`../neo-mac`](../neo-mac): a UniFFI-bound core inside a NetworkExtension packet tunnel.

## Docs

| Doc | What |
|-----|------|
| [`ARCHITECTURE.md`](docs/ARCHITECTURE.md) | the design, the crate map, the request flow |
| [`MILESTONES.md`](docs/MILESTONES.md) | roadmap and live status (M0–M36 + audit gate) |
| [`PROTOCOL.md`](docs/PROTOCOL.md) | the per-flow wire pipeline and exit models |
| [`CRYPTO.md`](docs/CRYPTO.md) | primitives and the constructions built on them |
| [`DISCOVERY.md`](docs/DISCOVERY.md) | zero-config discovery, witnessed snapshots, Sybil/eclipse |
| [`MONETIZATION.md`](docs/MONETIZATION.md) | economic sustainability without breaking unlinkability |
| [`THREAT_MODEL.md`](docs/THREAT_MODEL.md) | adversaries, answers, honest limits |
| [`SECURITY_ANALYSIS.md`](docs/SECURITY_ANALYSIS.md) | the standing internal review + fix ledger |
| [`SECURITY_REVIEW_3.md`](docs/SECURITY_REVIEW_3.md), [`SECURITY_REVIEW_4.md`](docs/SECURITY_REVIEW_4.md) | point-in-time review rounds (findings, verdicts, fixes) |

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
