# neo — milestones

The build roadmap and its live status. Core milestones (M0–M9) come first and each is independently
demoable; the four frontier capabilities (M10–M13) are sequenced last because they are research-grade
— none blocks a usable product. See `docs/ARCHITECTURE.md` for the design and the honest constraints.

**Status legend:** ✅ done · 🔨 next / in progress · ⬜ pending

**Reality check:** this is a multi-quarter (realistically ~12–18 month) program. The near-term target
is **M1** — the first version where packets actually flow through neo. Nothing here is audited; do not
rely on neo for real-world safety until the audit gate.

---

## Core

### M0 — Foundation ✅ (CI still outstanding)
Toolchain, repo skeleton, and the shared identity/config, with post-quantum crypto baked in from the
start.
- [x] Rust toolchain (rustup + stable)
- [x] Monorepo + Cargo workspace (`core/crates/*`, `platforms/desktop`)
- [x] `neo-core`: errors, `NodeConfig` + `PrivacyLevel`, **PQ-hybrid `NodeIdentity`** (Ed25519 + X25519 + ML-KEM-768)
- [x] `neo` CLI: `identity generate` (writes a `0600` key file)
- [x] `cargo build` / `test` / `clippy -D warnings` / `fmt` all green
- [ ] CI (build + test + clippy + fmt on push)

### M1 — MVP tunnel ✅ (TUN bridge needs root; QUIC deferred to M6)
PQ-hybrid handshake + encrypted session between two peers.
- Done: signed hybrid AKE (ephemeral X25519 + ML-KEM-768, Ed25519-authenticated) in `neo-crypto`;
  directional ChaCha20-Poly1305 session with replay protection; `neo run --listen/--connect` doing a
  real handshake + encrypted ping/pong over TCP (**demoed live between two processes**).
  `neo-dataplane` has the packet abstraction + in-memory link (tested) and a `tun-rs` TUN wrapper
  (compiles under the `tun` feature).
- Deferred: bridging real OS traffic through the TUN device (needs root + two hosts); the QUIC /
  obfuscated transport, which is M6 — M1 uses plain TCP for now.
- Tests: handshake agreement, tamper + replay rejection, TCP handshake/ping-pong.

### M2 — Onion routing ✅
Per-hop layered encryption + node-disjoint path selection.
- Done: `neo-crypto::onion` — each hop peels exactly one X25519 layer and learns only the next hop;
  `neo-routing` — fresh-per-request path selection and mutually node-disjoint multipaths for shares.
- Deferred: full Sphinx properties (fixed-size padding, bitwise unlinkability, replay tags) and a
  per-hop PQ KEM (the end-to-end session is already PQ via M1).
- Tests: 3-hop peel to payload, wrong-hop rejection, path distinctness/disjointness.

### M3 — Information slicing ✅ (novel core, part 1)
Encrypt-then-slice into k-of-n shares, with reassembly.
- Done: `neo-slicing` — AEAD-encrypt, Reed-Solomon k-of-n, share (de)serialization, reassemble+decrypt.
- Tests: any-k recovery, sub-threshold failure, tamper + wrong-key rejection, empty plaintext.
- End-to-end: `neo-node`'s integration test runs **M3 → M2 → M3** (slice → onion over disjoint paths
  → peel at each hop → reassemble + decrypt), proving no single relay holds a complete, readable flow.

### M4 — Decentralization ⬜
Trackerless discovery + NAT traversal via libp2p (Kademlia DHT, DCUtR hole-punch, Relay v2 fallback).
- Crates: `neo-discovery`, `neo-transport`.

### M5 — Timing defense ⬜ (novel core, part 2)
Cover traffic + per-hop Poisson timing mixing, scaled by the adaptive privacy dial.
- Crates: `neo-mix`.
- Done when: added latency/bandwidth is measured and cover traffic is statistically indistinguishable
  from real traffic.

### M6 — Unblockable ⬜
Pluggable obfuscation ladder — QUIC → MASQUE/HTTP-3 → Snowflake-style WebRTC → (REALITY later) —
wrapping all libp2p traffic (its wire protocol is DPI-fingerprintable); DoH rendezvous.
- Crates: `neo-transport`, `neo-discovery`.
- Done when: traffic reads as ordinary QUIC/HTTP-3 to an entropy/DPI classifier.

### M7 — Diffused exit ⬜
Fresh-per-request routing + rotating opt-in clearnet exits + exit policy (the *statistical* form of
"no responsible exit").
- Crates: `neo-routing`, `neo-node`.

### M8 — Mobile ⬜
iOS (NEPacketTunnelProvider) + Android (VpnService) over `neo-ffi` (UniFFI); adaptive privacy dial.
- Crates: `neo-ffi`; `platforms/ios`, `platforms/android`.
- Constraints: iOS 50 MiB extension cap → minimize buffering; Android Doze throttles background;
  batch packets across the FFI boundary; no committee/PIR on-device.

### M9 — Core hardening ⬜
Threat-model doc sharpened, adversary simulations, fuzzing — a gate before wider testing.
- Done when: local, colluding-relay, and global-passive adversaries are simulated and what each
  learns is measured.

---

## Frontier (research-grade; sequenced by tractability)

### M10 — Anonymous bandwidth credits ⬜
Unlinkable, token-free credits: earn by relaying, spend to send — one mechanism for Sybil resistance
and anti-free-riding.
- Crates: `neo-credits`.
- Done when: credits are verifiably unlinkable (issuer can't correlate earn ↔ spend) and double-spend
  is caught.

### M11 — Verifiable routing ⬜
VRF-based unbiasable per-request path selection, so an adversary can't herd clients onto controlled
paths.
- Crates: `neo-verify`, `neo-routing`.
- Done when: path selection is VRF-verifiable and cannot be biased.

### M12 — Committee exit ⬜ (flagship)
A k-of-n MPC-TLS committee jointly performs each clearnet request — the *cryptographic* form of "no
responsible exit". Opt-in for sensitive, low-bandwidth requests.
- Crates: `neo-mpc`.
- Done when: no single committee member can reconstruct destination + plaintext; MPC overhead is
  measured honestly.

### M13 — Verifiable privacy (full) ⬜
PIR/oblivious peer discovery + ZK proof-of-mixing, so privacy is provable rather than trusted.
- Crates: `neo-verify`, `neo-discovery`, `neo-mix`.
- Done when: discovery lookups leak nothing (PIR) and proof-of-mixing soundness holds.

---

## Audit gate ⬜
External security + cryptography audit **before anyone relies on neo for real safety.** This is a hard
gate, not a milestone to rush past.
