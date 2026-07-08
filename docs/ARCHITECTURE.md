# neo — architecture

> Companion to the approved milestone plan. This file is the durable in-repo summary.

## What neo is

An information-sliced, onion-layered, timing-mixed, DHT-discovered, DPI-camouflaged, post-quantum
overlay VPN with a cryptographic committee exit, anonymous bandwidth credits, and verifiable
(not merely trusted) privacy — on desktop and mobile.

## Two layers (keep them separate)

- **Substrate — `libp2p`:** discovery + point-to-point connectivity only (Kademlia DHT, QUIC links,
  Noise, NAT traversal via DCUtR + Relay v2), between *adjacent* nodes.
- **neo routing — our own protocol on top:** PQ-sliced + onion-layered + timing-mixed multi-hop
  circuits, fresh-per-request VRF-selected paths, committee exits. libp2p's own routing (Kademlia
  content lookups, gossipsub) is used for **discovery only, never user data**, and all traffic runs
  **behind the obfuscating transport, never raw** (libp2p's wire protocol is itself fingerprintable).

## Crates

| Crate | Role | Milestone |
|-------|------|-----------|
| `neo-core` | shared types, config, PQ-hybrid-ready identity | M0 |
| `neo-crypto` | PQ-hybrid Noise, onion layering, Sphinx packets | M0/M2 |
| `neo-slicing` | k-of-n encrypt-then-slice + reassembly | M3 |
| `neo-mix` | cover traffic + Poisson timing mixing | M5 |
| `neo-routing` | disjoint multipath, VRF per-request paths/exits | M2/M7/M11 |
| `neo-transport` | pluggable DPI-resistant transport (wraps libp2p) | M6 |
| `neo-discovery` | libp2p DHT + NAT traversal; PIR lookups | M4/M13 |
| `neo-credits` | anonymous bandwidth credits (Sybil + incentives) | M10 |
| `neo-mpc` | committee / MPC-TLS exit | M12 |
| `neo-verify` | VRF + PIR + ZK proof-of-mixing primitives | M11/M13 |
| `neo-dataplane` | TUN I/O + packet/flow mux | M1 |
| `neo-node` | engine: wires it together, runs roles | M1+ |
| `neo-ffi` | UniFFI bindings for mobile shells | M8 |

## Honest constraints

1. **Anonymity trilemma** — strong anonymity + low latency + low overhead: pick two. neo pays a
   latency/bandwidth tax by design, managed by the `PrivacyLevel` dial.
2. **"No responsible exit"** is fully achievable only *inside* the overlay. For the open web it is
   diffused/rotated per request (statistical) and, at the strongest setting, split across an MPC-TLS
   committee (cryptographic) — reduced, never zero, because some node must speak to the destination.
3. **Small network = weak anonymity** until the crowd grows.
4. **Sybil** is answered by bandwidth credits, not fully solved; bootstrap may need a seed set.
5. **Mobile** throttles the dial on battery/cellular; phones are never mandatory relays or committee
   members.
6. **Not audited.** No one should rely on neo for real safety before an external audit.
