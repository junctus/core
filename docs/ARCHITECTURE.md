# neo — architecture

The durable in-repo design summary. Status lives in [`MILESTONES.md`](MILESTONES.md); this file is the
shape of the system.

## What neo is

An information-sliced, onion-layered, timing-mixed, discovery-bootstrapped, post-quantum overlay VPN
with a verifiable-not-trusted privacy layer: a cryptographic committee exit, anonymous bandwidth
credits, VRF-unbiasable paths, PIR discovery, and a ZK proof-of-mixing — on desktop, with a mobile FFI.

## Two layers (kept separate)

- **Substrate — `libp2p`:** discovery + adjacent-node connectivity only — Kademlia DHT, Noise/yamux
  over TCP, and NAT traversal (AutoNAT + Circuit Relay v2 + DCUtR). libp2p routing (DHT lookups) is
  used for **discovery only, never user data**.
- **neo routing — our own protocol on top:** PQ-sliced, onion-layered (Sphinx), timing-mixed multi-hop
  circuits over an authenticated per-hop session, with fresh-per-request paths and committee exits.

## How a request flows (the composed pipeline)

```
client
  │  pay: earn an unlinkable bandwidth credit by relaying, spend it to send   [neo-credits]
  ▼
  discover a relay set — from a witness-signed snapshot, or by NodeId via PIR [neo-discovery/seed]
  │
  ▼
  select a verifiable, unbiasable path (commit + beacon VRF)                   [neo-verify, neo-routing]
  │
  ▼
  encrypt → slice k-of-n (per-share MAC) → wrap each share in a Sphinx onion   [neo-crypto, neo-slicing]
  │  each hop: PQ-hybrid handshake (3-msg, key-confirmed) → link session       [neo-crypto]
  ▼
  forward hop-by-hop; only the exit sees a share; a return path layers back    [neo-node]
  ▼
  exit: overlay peer, rotating clearnet exit, or a k-of-n MPC committee        [neo-routing, neo-mpc]
```

No relay ever holds a complete, readable flow (slicing over node-disjoint paths); no hop learns more
than its next hop (Sphinx); no minority of an exit committee can read the request (threshold VSS).

## Crates

| Crate | Role | Milestones |
|-------|------|-----------|
| `neo-core` | shared types, config, PQ-hybrid `NodeIdentity` (self-certifying `NodeId`) | M0 |
| `neo-crypto` | PQ-hybrid key-confirmed handshake, session AEAD, Sphinx (Lioness payload) | M1 · M2 |
| `neo-slicing` | encrypt-then-slice k-of-n with per-share authentication | M3 |
| `neo-mix` | Poisson timing mixing + cover traffic | M5 |
| `neo-routing` | node-disjoint multipath, VRF-seeded paths, rotating exit policy | M2 · M7 · M11 |
| `neo-transport` | pluggable length-obfuscated / QUIC transport | M6 |
| `neo-discovery` | signed records, witnessed snapshots, libp2p DHT, NAT traversal, PIR, DoH bootstrap | M4 · M4.5 · M16 · M13 · M18 |
| `neo-seed` | witnessed discovery seed (verify + dial-back + snapshot HTTP service) | M4.5 |
| `neo-credits` | anonymous bandwidth credits (VOPRF) + proof-of-relay earning | M10 |
| `neo-mpc` | committee exit: threshold request sharing + verifiable (Feldman VSS) key custody | M12 · M20 |
| `neo-verify` | VRF, unbiasable selection, 2-server PIR, oblivious lookup, ZK verifiable shuffle | M11 · M13 · M19 |
| `neo-dataplane` | TUN I/O + packet mux | M1 |
| `neo-node` | the engine: wires it together, runs roles, onion forwarding + streaming | M1 · M4.6 · M15 |
| `neo-ffi` | UniFFI bindings for mobile shells | M8 |

## Deep dives

- [`DISCOVERY.md`](DISCOVERY.md) — zero-config discovery, witnessed snapshots, Sybil/eclipse/enumeration.
- [`PROTOCOL.md`](PROTOCOL.md) — the per-flow wire pipeline and exit models.
- [`CRYPTO.md`](CRYPTO.md) — primitives and the higher-level constructions built on them.
- [`SECURITY_ANALYSIS.md`](SECURITY_ANALYSIS.md) — the adversarial internal review and its fixes.
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — adversaries, answers, and honest limits.

## Honest constraints

1. **Anonymity trilemma** — strong anonymity + low latency + low overhead: pick two. neo pays a
   latency/bandwidth tax by design, tuned by the `PrivacyLevel` dial.
2. **"No responsible exit"** is fully achievable only *inside* the overlay. For the open web it is
   diffused/rotated per request (statistical) and, at the strongest setting, split across an MPC
   committee (cryptographic) — reduced, never zero, because some node must speak to the destination.
3. **Small network = weak anonymity** until the crowd grows.
4. **Sybil** is answered by bandwidth credits, not fully solved; first contact needs a seed set.
5. **Mobile** throttles the dial on battery/cellular; phones are never mandatory relays or committee
   members.
6. **Not audited.** No one should rely on neo for real safety before the external audit gate.
