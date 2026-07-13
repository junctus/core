# neo — architecture

The durable in-repo design summary. Status lives in [`MILESTONES.md`](MILESTONES.md); this file is the
shape of the system.

## What neo is

An information-sliced, onion-layered, timing-mixed, discovery-bootstrapped, post-quantum overlay VPN
with a verifiable-not-trusted privacy layer: a cryptographic committee exit (up to a complete,
adversarially-verified malicious-secure two-party MPC-TLS crypto stack), anonymous bandwidth credits,
VRF-unbiasable paths, PIR discovery, and a ZK verifiable shuffle — live on a desktop/macOS client, with
a mobile FFI.

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
than its next hop (Sphinx); no minority of an exit committee can read the request (threshold VSS), and
the committee *decrypt* path assembles the key/plaintext at no single party (M28) — and it is the exit
path the running node actually uses today (that or a plain TCP splice). The full two-party **MPC-TLS**
send path (a TLS session whose key is never assembled at one party) is a complete, adversarially-verified
**crypto stack** (M24) that **completes real TLS 1.3 handshakes against a live server** (M45 —
interop-verified against stock `rustls`, both semi-honest and malicious engines, with real X.509
chain-building + KeyUpdate). But it is a **tested capability, not yet wired into the runtime data plane**:
nothing in `neo-node`/the CLI drives `mpc_tls::live` today, so live user traffic still egresses via the
committee-exit or TCP-splice path. Wiring 2PC-TLS as the actual send path (a client + relay jointly
playing the TLS client) is a distinct integration step. All audit-gated.

## Crates

| Crate | Role | Milestones |
|-------|------|-----------|
| `neo-core` | shared types, config, PQ-hybrid `NodeIdentity` (self-certifying `NodeId`) | M0 |
| `neo-crypto` | PQ-hybrid key-confirmed handshake, session AEAD, Sphinx (Lioness payload) | M1 · M2 |
| `neo-slicing` | encrypt-then-slice k-of-n with per-share authentication | M3 |
| `neo-mix` | Poisson timing mixing + cover traffic | M5 |
| `neo-routing` | node-disjoint multipath, VRF-seeded paths, rotating exit policy | M2 · M7 · M11 |
| `neo-transport` | length-obfuscated / QUIC transport + REALITY authenticate/decoy split, in-ClientHello codec, decoy reverse-proxy | M6 · M23 · M27 |
| `neo-discovery` | signed records, witnessed snapshots, libp2p DHT, NAT traversal, PIR, DoH bootstrap | M4 · M4.5 · M16 · M13 · M18 |
| `neo-seed` | witnessed discovery seed (verify + dial-back + snapshot HTTP service) | M4.5 · M36 |
| `neo-credits` | anonymous bandwidth credits (VOPRF) + proof-of-relay earning | M10 · M17 |
| `neo-mpc` | committee exit + threshold-decrypt custody, **and the malicious-secure two-party MPC-TLS crypto stack** (KOS OT, authenticated garbling, SPDZ, ECtF→pre-master, HKDF under 2PC) | M12 · M20 · M22 · M24 |
| `neo-verify` | VRF, unbiasable selection, 2-server PIR, oblivious lookup, ZK verifiable shuffle | M11 · M13 · M19 |
| `neo-dataplane` | TUN I/O + packet mux | M1 |
| `neo-netstack` | userspace TCP/IP stack (smoltcp) — the TUN → TCP-flow gateway (tun2socks) the VPN clients ride on | M21 |
| `neo-node` | the engine: wires it together, runs roles, onion forwarding, persistent circuit tunnels + stream mux | M1 · M4.6 · M15 · M21 |
| `neo-ffi` | UniFFI bindings for mobile / desktop-app shells (e.g. `../neo-mac`) | M8 |

## Deep dives

- [`DISCOVERY.md`](DISCOVERY.md) — zero-config discovery, witnessed snapshots, Sybil/eclipse/enumeration.
- [`PROTOCOL.md`](PROTOCOL.md) — the per-flow wire pipeline and exit models.
- [`CRYPTO.md`](CRYPTO.md) — primitives and the higher-level constructions built on them.
- [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md) — the living internal security review (cumulative findings + fixes).
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
