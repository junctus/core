# neo — protocol notes (draft)

> Draft, filled in as milestones land. Wire formats are versioned; nothing here is stable yet.

## Per-flow pipeline

```
plaintext
  → encrypt (AEAD; keys PQ-hybrid)                      [neo-crypto]
  → slice into n shares, any k reconstruct              [neo-slicing]  (encrypt-then-slice)
  → wrap each share in an onion/Sphinx packet           [neo-crypto]
  → assign each share a node-disjoint path (fresh/req)  [neo-routing]  (VRF-selected, M11)
  → per-hop timing mix + cover traffic                  [neo-mix]
  → send over the obfuscating transport                 [neo-transport]
```

Reassembly is the reverse: collect ≥ k shares → decode → decrypt. Fewer than k shares are useless.

## Routing

- **Per request:** a fresh randomized set of node-disjoint paths and a fresh exit. No two requests
  share a full route; no *concurrent* full-route reuse. Uniqueness is probabilistic at finite scale.
- **VRF (M11):** path selection becomes verifiably unbiasable so an adversary can't herd clients.

## Exit models

- **Overlay (neo ↔ neo):** sliced end-to-end; no reassembly at any relay; no responsible exit, ever.
- **Clearnet, statistical (M7):** rotating per-request exits reassemble just-in-time; responsibility
  is diffused and rotated, not eliminated.
- **Clearnet, cryptographic (M12):** a k-of-n MPC-TLS committee jointly performs the request; no
  single member knows destination + content or is the sole originator.

## Discovery

Trackerless Kademlia DHT over libp2p; DoH rendezvous. PIR/oblivious lookups (M13) hide *what* is
being looked up. Discovery never carries user data.
