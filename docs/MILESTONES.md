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
- Done (data plane): `neo run --tun` bridges a real TUN device through the tunnel
  (`neo-node::tunnel` — session seal/open + mixer); compiles under the `tun` feature, needs root to run.
- Deferred: the QUIC / obfuscated transport (M6) — the wire is plain TCP for now.
- Tests: handshake agreement, tamper + replay rejection, TCP handshake/ping-pong, tunnel round-trip.

### M2 — Onion routing ✅ (full Sphinx)
Full Sphinx over Ristretto + node-disjoint path selection.
- Done: `neo-crypto::sphinx` — fixed-size packets, per-hop blinded shared secrets, the filler trick,
  per-layer MACs, an onion-encrypted payload, and replay tags; `neo-routing` — fresh-per-request path
  selection and mutually node-disjoint multipaths for shares.
- Deferred: reaching hops behind NAT (DCUtR/relay — part of M4's libp2p work).
- Tests: 1/3/5-hop delivery, constant packet size, tamper + replay + wrong-hop rejection, payload hiding.

### M3 — Information slicing ✅ (novel core, part 1)
Encrypt-then-slice into k-of-n shares, with reassembly.
- Done: `neo-slicing` — AEAD-encrypt, Reed-Solomon k-of-n, share (de)serialization, reassemble+decrypt.
- Tests: any-k recovery, sub-threshold failure, tamper + wrong-key rejection, empty plaintext.
- End-to-end: `neo-node`'s integration test runs **M3 → M2 → M3** (slice → onion over disjoint paths
  → peel at each hop → reassemble + decrypt), proving no single relay holds a complete, readable flow.

### M4 — Decentralization ✅ (real libp2p backend + in-memory DHT)
Discovery interface, NAT-traversal strategy, an in-memory DHT, and a real libp2p stack.
- Done: `neo-discovery` — `Discovery` trait, `LocalRegistry` (in-memory DHT for tests), and
  `connection_ladder` (Direct → hole-punch → relay). `libp2p_backend` (feature `libp2p`) — a real
  Swarm with **Kademlia DHT + identify** over TCP/Noise/yamux; two nodes connect in a local test.
- Done: `Libp2pDiscovery` implements the `Discovery` trait via a background swarm task + command
  channel — announce/lookup map to Kademlia put/get; a record announced on one node is found on
  another via the DHT.
- Deferred: DCUtR hole-punching and Circuit Relay v2 for reaching peers behind NAT.
- Tests: in-memory announce/lookup/sampling/ladder; two libp2p nodes connect; cross-node DHT lookup.

### M5 — Timing defense ✅ (novel core, part 2)
Cover traffic + per-packet Poisson timing mixing, scaled by the privacy dial.
- Done: `neo-mix` — exponential per-packet delays, Poisson cover traffic, `MixParams::for_level`, and
  an async `Mixer` over channels.
- Done (wiring): the mixer is wired into the tunnel data plane (`neo-node::tunnel::run_tunnel`).
- Tests: delay-mean statistics, dial → params mapping, every real packet delivered, tunnel round-trip,
  and a **global-passive-observer simulation** (mixing decorrelates output order from input).

### M6 — Unblockable ✅ (obfuscation + QUIC; MASQUE/WebRTC/REALITY deferred)
A pluggable `Transport` with length obfuscation, plus a real QUIC transport.
- Done: `neo-transport` — `Transport`/`Obfuscation` traits with `Plain` and `Bucketed` (length
  quantization + random padding) over TCP; `quic` (feature) — a real **QUIC** transport via `quinn`
  (self-signed; neo authenticates above it).
- Deferred: MASQUE (CONNECT-UDP/HTTP-3), Snowflake-style WebRTC, and REALITY; DoH rendezvous.
- Tests: length quantization, shared-bucket sizes, TCP round-trip, QUIC round-trip.

### M7 — Diffused exit ✅
Fresh-per-request routing + rotating opt-in exits + exit policy (the *statistical* "no responsible exit").
- Done: `neo-routing::exit` — `ExitPolicy` (opt-in, off by default, port rules), `ExitSelector`
  (rotates, never an immediate repeat), `RouteRegistry` (no concurrent full-route reuse).
- Tests: exit off by default, port enforcement, exit rotation, concurrent-route disjointness.

### M8 — Mobile ✅ (FFI + UniFFI compile; native app builds deferred)
FFI surface over the core + iOS/Android project scaffolds.
- Done: `neo-ffi` — safe API (identity generate / node id), builds as `cdylib`/`staticlib`, and the
  `uniffi` feature compiles the UniFFI scaffolding. Skeletons in `platforms/ios` and
  `platforms/android`.
- Deferred: building the actual apps (needs Xcode / Gradle / NDK), `uniffi-bindgen` binding
  generation, and the on-device TUN packet loop.
- Tests: FFI generate → derive-id round-trip, invalid-input handling.

### M9 — Core hardening ✅ (adversary sims, fuzzing, threat model; audit pending)
Adversary-simulation tests, fuzzing, and an expanded threat model.
- Done: adversary tests (colluding relays, single relay, on-path observer); a global-passive-observer
  timing sim (M5); `fuzz/` cargo-fuzz targets for the wire parsers plus stable no-panic-on-garbage
  tests; the "Simulated adversaries" section in `docs/THREAT_MODEL.md`.
- Deferred: the external security + cryptography audit (the hard gate before real use).

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
