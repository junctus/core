# neo — protocol notes

> Wire formats are versioned (domain-tagged); nothing here is frozen yet. This describes what runs
> today; see [`ARCHITECTURE.md`](ARCHITECTURE.md) for the shape and [`CRYPTO.md`](CRYPTO.md) for the
> primitives.

## Per-flow pipeline

```
plaintext
  → AEAD-encrypt (key carried end-to-end, PQ-hybrid session)      [neo-crypto]
  → slice into n shares, any k reconstruct, per-share MAC         [neo-slicing]   (encrypt-then-slice)
  → wrap each share in a fixed-size Sphinx onion                  [neo-crypto]
  → assign each share a node-disjoint path                        [neo-routing]   (VRF-seeded, M11)
  → per-hop Poisson timing mix + cover traffic                    [neo-mix]
  → carry over an authenticated per-hop session (3-msg handshake) [neo-crypto]
```

Reassembly is the reverse: collect ≥ k authentic shares → decode → decrypt. Fewer than k, or a bad
share (MAC fails, treated as an erasure), are routed around; below the threshold, reassembly fails.

## Onion data plane (M4.6 / M15)

Runs between live processes, not just in tests:

- **Forward:** the sender builds a Sphinx circuit from discovered relays (id + routing key + address
  from the signed `PeerRecord`) and hands the onion to the first hop over its session. Each relay
  `process()`es one layer, resolves the next hop from its verified snapshot, dials it, and forwards;
  the terminal hop delivers. Only the exit sees the payload; no hop learns more than its next hop.
- **Return (M15):** since Sphinx already makes the forward payload confidential to the exit, only the
  reverse direction is layered — each hop derives a return-path stream key from the Sphinx shared
  secret it already computes, so the response comes back onion-encrypted and no middle relay reads it.
- **Replay:** a relay keeps one lifetime replay cache; a packet replayed on a new connection is
  rejected. Frame sizes are bounded (64 KiB).

## Routing

- **Per request:** a fresh randomized set of node-disjoint paths and a fresh exit; no two requests
  share a full route, and no *concurrent* route shares any hop (including the exit). Uniqueness is
  probabilistic at finite scale.
- **VRF (M11):** a commit-then-VRF seed makes path selection verifiably unbiasable — neither the client
  nor the beacon can grind it — so an adversary can't herd clients onto controlled paths.

## Exit models

- **Overlay (neo ↔ neo):** sliced end-to-end; no reassembly at any relay; no responsible exit, ever.
- **Clearnet, statistical (M7):** rotating per-request exits reassemble just-in-time; responsibility is
  diffused and rotated, not eliminated.
- **Clearnet, cryptographic (M12/M20):** a k-of-n committee holds the request under threshold /
  verifiable secret sharing; no minority can reconstruct destination + content.

## Discovery

Zero-configuration: a client fetches a **witness-signed snapshot** of the relay set from any (untrusted)
mirror and verifies k-of-n witness signatures — fetching the whole set leaks nothing about which relay
it will use. Relays discover each other over a hardened libp2p Kademlia DHT. First contact bootstraps
from baked seeds or a **DoH-fetched, signed bootstrap record** (M18); PIR / oblivious lookup (M13) hide
*what* is looked up. Discovery never carries user data. Full detail in [`DISCOVERY.md`](DISCOVERY.md).
