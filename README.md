# neo

A dispersed, post-quantum, verifiable, censorship-resistant privacy overlay — a "new kind of VPN".

> **Status:** M0–M9 core mechanisms implemented and tested — full Sphinx, PQ-hybrid handshake,
> information slicing, timing mixing, obfuscated transport, exit policy, a real libp2p stack, and the
> mobile FFI. **Not audited** — do not rely on neo for real-world safety. The frontier tier
> (M10–M13) is next. See [`docs/MILESTONES.md`](docs/MILESTONES.md).

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

## License

AGPL-3.0-or-later (placeholder — revisit before any release).
