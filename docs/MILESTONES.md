# neo — milestones

The build roadmap and its live status. Core milestones (M0–M9) come first and each is independently
demoable; the four frontier capabilities (M10–M13) are sequenced last because they are research-grade
— none blocks a usable product. See `docs/ARCHITECTURE.md` for the design and the honest constraints.

**Status legend:** ✅ done · 🔨 next / in progress · ⬜ pending

**Reality check:** this is a multi-quarter (realistically ~12–18 month) program. Real onion traffic now
flows end to end — a message is discovered-routed through a live multi-hop circuit and delivered at an
exit (M4.6), and all four frontier capabilities (M10–M13) have working, tested cores. What remains for
a *safe* product is depth, not breadth: NAT traversal for home relays, the deferred transport/ZK/MPC
constructions, and — the hard gate — an external audit. **Nothing here is audited; do not rely on neo
for real-world safety until the audit gate.**

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
- [x] CI (build + test + clippy + fmt on push, incl. libp2p + tun feature builds) — `.github/workflows/ci.yml`

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

### M4.5 — Runnable discovery + Sybil resistance ✅ (seed/relay/client live; NAT + audit pending)
The point where discovery becomes a *runnable network*: `neo run` finds relays with zero manual
configuration, and the discovery layer is hardened against Sybil, eclipse, and enumeration. See
`docs/DISCOVERY.md`.
- Done (records): **self-certifying, signed `PeerRecord`** — carries the full PQ key set, id must equal
  `blake3(keys)`, Ed25519-signed, with `expires_at` + monotonic `seq`; `verify()` on receipt. Verifiers
  reject forged, tampered, foreign-id, expired, and replayed records (`neo-core`, `neo-discovery`).
- Done (client plane): **witnessed snapshots** (`neo-discovery::snapshot`) — k-of-n witness-signed relay
  sets; whole-set fetch leaks no per-relay selection (PIR-degenerate); forged records fatal, expired
  filtered. Integrity is separated from distribution, so snapshots serve from any untrusted mirror/CDN.
- Done (DHT hardening): client/server **role split** (clients are DHT-invisible), inbound `PUT`
  verification (`StoreInserts::FilterBoth`), **disjoint query paths**, seq-aware caching + TTLs.
- Done (seed): `neo-seed` — verify + **dial-back handshake attestation** (proves address ↔ key) +
  strike-based health + witness-signed snapshot; axum service (`/snapshot`, `/healthz`, `/witness`,
  rate-limited `/register`), serving **no user traffic**.
- Done (CLI + ops): `neo seed`, `neo run --relay`, zero-flag `neo run` client, `neo snapshot`; baked
  mirror/witness defaults with flag/env overrides + on-disk snapshot cache; `deploy/discovery/`
  (systemd + Caddy + installer for **discovery.junctus.org**) and `scripts/build-release.sh`
  (macOS + Ubuntu x86_64).
- Deferred: reaching NAT'd relays (AutoNAT/DCUtR/Relay v2, from M4); probe-resistant transports (M6);
  the external audit.
- Tests: record verify/tamper/expiry/foreign-id/garbage; snapshot threshold/duplicate/tamper/forged/
  expiry; DHT role split + unverifiable-record rejection; seed registry + dial-back (real handshake) +
  HTTP register/snapshot; **live seed→relay→client end-to-end** discovery with zero manual config.

### M4.6 — Onion data plane over the network ✅ (one-shot delivery; streaming deferred)
Sphinx onion routing (M2) carried over real sockets between separate processes — the point where neo
becomes an *actual multi-hop network*, not just discovery plus a 1:1 handshake.
- Done: `neo-node::forward` — a sender builds a Sphinx circuit from discovered relays (`Hop` = id +
  routing key + addr, all from the signed `PeerRecord`) and hands the onion to the first hop over an
  authenticated session; each relay `process()`es one layer, resolves the next hop's address from its
  (witness-verified) snapshot, dials it, and forwards; the terminal hop delivers. Link encryption
  (M1 session) under onion encryption (Sphinx), so no relay learns more than its next hop and none
  but the exit sees the payload.
- Done (CLI): `neo run --relay` forwards onions (per-connection tasks + a background snapshot-driven
  address book); `neo send --message --hops N` routes a message through a discovered circuit;
  `--register-cooldown` operator knob for local multi-relay demos.
- Deferred: a return path and bidirectional stream/TCP tunneling (this delivers a one-shot onion
  message — the primitive those build on); NAT traversal so home relays are dialable.
- Tests: library-level 1- and 2-hop forward+deliver over localhost sockets, relay-sees-no-payload,
  unresolvable-next-hop errors cleanly; **live seed + 3-relay + sender e2e** — a message forwarded
  through a real 3-hop circuit and delivered at the exit, plaintext seen by exactly one relay.

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

The frontier primitives are implemented and tested; each entry below states its honest
real-vs-deferred boundary. A capstone integration test (`core/crates/neo-node/tests/frontier.rs`)
exercises M10–M13 together and composes them into one request flow. None is audited.

### M10 — Anonymous bandwidth credits ✅ (unlinkable + double-spend; earn-accounting deferred)
Unlinkable, token-free credits: earn by relaying, spend to send — one mechanism for Sybil resistance
and anti-free-riding.
- Crates: `neo-credits`.
- Done: a **VOPRF** (Privacy Pass primitive) — blind a random serial, issuer blind-evaluates it
  without seeing it, finalize a token; redeem recomputes the OPRF and a spend set rejects
  double-spends. The issuer only ever saw a *blinded* serial, so issuance ↔ spending is unlinkable.
- Deferred: binding issuance to *proven* relayed bandwidth (the earn-side accounting) and wire
  transport of credits.
- Tests: unlinkable + verifiable + single-use; tampered credit rejected.

### M11 — Verifiable routing ✅ (VRF + unbiasable combined-seed selection)
VRF-based unbiasable per-request path selection, so an adversary can't herd clients onto controlled
paths.
- Crates: `neo-verify`, `neo-routing`.
- Done: `neo-verify::vrf` (schnorrkel Ristretto VRF, prove/verify/select); `neo-verify::selection` —
  a **commit-then-VRF** construction so *neither* the client (grinding request ids) nor the beacon
  (choosing the VRF input) can bias the path seed, and anyone can verify it; `neo-routing`'s
  `select_path_seeded` turns the verifiable seed into a reproducible path.
- Tests: seed agreement client↔beacon; tampered/foreign-key/rebound-commitment proofs rejected;
  neither party can grind; seeded path deterministic.

### M12 — Committee exit ✅ (flagship; threshold trust-split real, full MPC-TLS deferred)
A k-of-n committee jointly stands in for the exit — the *cryptographic* form of "no responsible exit".
Opt-in for sensitive, low-bandwidth requests.
- Crates: `neo-mpc`.
- Done: the clearnet request is **threshold secret-shared** (Shamir over GF(256)); any `k-1` members —
  even colluding — learn *nothing* (information-theoretic) about destination or payload; any `k`
  reconstruct; a bound hash makes a corrupted/swapped share detectable. `Committee` models per-member
  custody + threshold reconstruction, with an honest overhead (expansion ≈ members) report.
- Deferred: full **MPC-TLS** (computing the TLS session under MPC so plaintext is never assembled at
  one point, including the send to the real server) — a large 2PC/MPC construction. This crate is the
  trust-splitting core it slots into.
- Tests: threshold reconstructs, minority fails & leaks nothing (no single share reveals the
  destination), corruption detected, degenerate configs rejected, wire round-trip.

### M13 — Verifiable privacy (full) ✅ (PIR + oblivious discovery; ZK shuffle deferred)
PIR/oblivious peer discovery + ZK proof-of-mixing, so privacy is provable rather than trusted.
- Crates: `neo-verify`, `neo-discovery`, `neo-mix`.
- Done: `neo-verify::pir` — 2-server information-theoretic XOR PIR (neither server learns the index);
  `neo-verify::oblivious` — **keyword** oblivious lookup (public `H(salt‖key) mod B` bucketing + a
  collision-free salt search) so a client fetches a relay by `NodeId` without either server learning
  which. `neo-verify::proof_of_mixing` has a non-ZK conservation check (no packet dropped/injected).
- Deferred: a real **ZK verifiable shuffle** (Bayer–Groth-style) that hides the permutation from the
  verifier — a large construction; the conservation check is the audit-grade stepping stone.
- Tests: PIR retrieves the right record without the index; oblivious fetch by key returns the record,
  misses decode as absent, placement is collision-free and public.

---

## Hardening & expansion

### M14 — Core security hardening ✅ (all review findings fixed; external audit remains)
Driven by the adversarial internal review in `docs/SECURITY_ANALYSIS.md` (four parallel reviews across
the AKE/session, Sphinx, slicing/mix/routing, and discovery/forwarding surfaces). **Every** HIGH and
MEDIUM finding is fixed with regression tests.
- Crypto/Sphinx: **C-1** exit-verified payload integrity; **C-2** reject the identity `α`; **H-1**
  authenticate header before recording the replay tag; the full **wide-block (Lioness) payload** so any
  tamper avalanches the whole block (complete tagging resistance, SPRP avalanche test).
- Handshake: **H-3** bind the full `NodeId` (all three keys) + return it (UKS); **H-4** a
  **key-confirmation (m3) flight** — the responder establishes no session and emits no data until the
  initiator proves it derived the key — plus a **stateless retry cookie** so a replayed or
  connect-and-abandon m1 costs only a MAC, never an ML-KEM encapsulation; **M-2** reject trailing bytes.
- Slicing: **H-6** secrecy documented as computational; **M-3** per-share MACs (a corrupt shard is
  detected, attributed, and routed around as an erasure); **M-4** header bound as AEAD associated data.
- Discovery/seed/forward: **H-2** relay shares one lifetime `ReplayCache`; **H-5** trusted-proxy
  `X-Forwarded-For` allowlist; **M-6** client snapshot anti-rollback (persisted `created_at`
  high-water mark); **M-7** bounded frame allocation (64 KiB).
- Routing/mix: **H-7** full-32-byte seeded path selection (keyed XOF + rejection sampling); **M-1**
  `Router` dedup by `NodeId`; **M-5** mixer degrades instead of panicking on RNG failure; **M-8**
  fully node-disjoint concurrent routes.
- Every HIGH and MEDIUM finding is now closed with tests; the one thing left before real use is the
  **external audit gate**.

### M15 — Bidirectional streaming ✅ (request/response round-trip; persistent TCP tunnel next)
Extend the one-shot onion delivery (M4.6) with a **return path**, giving a full round-trip.
- Done: `neo-node::stream` — since Sphinx already makes the *forward* payload confidential to the exit,
  only the reverse direction is layered. Each hop derives a **return-path stream key** from the Sphinx
  shared secret it already computes (`create_packet_keyed` gives the client all of them); the exit
  encrypts its response and each relay adds its own layer, so a middle relay never sees the plaintext
  response and the client (holding all keys) peels them.
- Deferred: a persistent multi-cell byte stream / TCP tunnel (per-cell counters + connection splicing)
  and per-layer stream integrity (same wide-block hardening as the Sphinx payload, M14).
- Tests: 1- and 2-hop request/response over real sockets; middle relay cannot read the response.

### M16 — NAT traversal ✅ (reachability + ladder + libp2p behaviours; hole-punch needs real NAT)
Reachability detection + a connection ladder wired to real libp2p behaviours — the deferred half of M4.
- Done: `Reachability` (AutoNAT-driven) + `connection_ladder_for` (a public node skips hole-punching a
  directly-dialable peer; a NAT'd node tries Direct → DCUtR hole-punch → Circuit Relay v2). The libp2p
  backend now carries **AutoNAT**, **Circuit Relay v2 client**, and **DCUtR** behaviours, and exposes
  `reachability()`. Crates: `neo-discovery`.
- Deferred/honest: end-to-end hole-punching between two NAT'd hosts needs a real-NAT environment to
  exercise; here the strategy is unit-tested and the behaviours are wired + compile + co-exist with the
  DHT (the two-node connect and cross-node lookup tests still pass under the `libp2p` feature).

### M17 — Earn-side credit accounting ✅ (proof-of-relay receipts)
Bind credit issuance to proven relayed bandwidth. Done: `neo-credits::earn` — client-signed
[`RelayReceipt`]s, an `EarnLedger` that verifies + de-duplicates them and converts proven bytes into
earned credits, gating the (identified) issuance while spending stays anonymous. Honest limit: receipts
are client-attested, not a trustless bandwidth measurement (bilateral co-signed receipts are the
refinement). Tests: accumulate-to-credit, forged/replayed rejection, earn→unlinkable-spend lifecycle.

### M18 — DoH rendezvous bootstrap ✅
Censorship-resistant seed/witness bootstrap over DNS-over-HTTPS so the mirror/witness list rotates
without a client rebuild and the lookup resists blocking.
- Done: `neo-discovery::bootstrap` — a `BootstrapRecord` (current mirrors + witnesses) signed by a
  long-lived **bootstrap key** (only that key is baked into clients), with rollback protection
  (`not_before`) and a compact hex TXT encoding. CLI `doh` module fetches the TXT over DoH (JSON API),
  joins the character-strings, and verifies against the trusted bootstrap keys. Commands:
  `neo bootstrap-record` (operator signs + prints the TXT to publish) and `neo bootstrap-resolve`
  (client fetches + verifies over DoH). Crates: `neo-discovery` / CLI.
- Tests: sign/verify/TXT round-trip, untrusted-key + tamper + rollback rejection, garbage-safe parse,
  DoH-JSON TXT extraction + chunk-join, and an end-to-end record-through-the-TXT-channel test.

### M19 — ZK verifiable shuffle ✅ (sound, ZK; not succinct, not audited)
A real zero-knowledge shuffle argument replacing the `proof_of_mixing` conservation scaffold.
- Done: `neo-verify::shuffle` — a **grand-product / multiset-equality** argument over Ristretto Pedersen
  commitments with chained ZK **multiplication proofs** and a final equality proof, all Fiat–Shamir.
  The verifier learns nothing of the permutation; soundness rests on discrete-log (Pedersen binding) in
  the ROM; proof size is `O(n)`.
- Deferred/honest: not succinct (constant-size), and **not** independently audited; binding the scalar
  tags to actual mix packets is the integration step.
- Tests: real/identity/single-element permutations verify; dropped, altered, and duplicated tags and a
  tampered commitment are all rejected.

### M20 — MPC-TLS committee ✅ (verifiable custody; full 2PC-TLS still deferred)
Advance the M12 committee with **verifiable** key custody.
- Done: `neo-mpc::vss` — encrypt the request under a fresh session key, then **Feldman-verifiably**
  secret-share the *key* over Ristretto: every member can check its share against public commitments, a
  minority learns nothing (Shamir), and a corrupted share is detected **and attributed** at open time.
- Deferred/honest: full 2PC/MPC-TLS — computing the TLS session under MPC so the plaintext is never
  assembled at any single point, including the send to the real server (TLSNotary/`mpz` lineage) —
  remains research; key reconstruction here still assembles the key at decrypt time.
- Tests: threshold opens, minority cannot, every share verifies, a corrupted share is attributed.

### M21 — Persistent circuit tunnels ✅ (multi-cell byte streams + TCP tunneling)
Close M15/M4.6's one-shot limit: keep a Sphinx circuit **open** and carry a bidirectional byte stream,
with the exit splicing a real TCP connection to a target.
- Done: `neo-node::circuit` — a single Sphinx packet sets up the circuit (routing + per-hop secrets),
  then the parties exchange **cells** (`[seq][onion-layered body]`). Cells are a **counter-keyed
  symmetric onion** — each hop XORs one keystream layer `KS(dir_key_i, seq)`, `seq` unique per direction
  so no keystream reuse — with a **per-cell end-to-end MAC** keyed by the exit's secret, so a middle
  relay that mauls a cell is caught at the endpoint. The exit **splices a TCP connection** and pumps
  bytes both ways: real TCP-over-onion tunneling. Crate: `neo-node`.
- Deferred/honest: cells are variable-length (length hiding is the transport layer's job); congestion
  control and multiplexing many streams over one circuit are the next layer.
- Tests: onion+MAC layering unit test; a **real TCP byte stream** round-trips through a 2-hop circuit to
  a localhost echo server; a malicious middle relay mauling a return cell is rejected by the client.

### M22 — MPC-TLS threshold decryption ✅ (no single point of plaintext assembly for decrypt)
Advance M20 past "key assembled at decrypt": remove the single point where the committee reconstructs.
- Done: `neo-mpc::threshold` — a message encrypted to the committee's **joint public key**
  (`commitments[0]` of the Feldman sharing) is decrypted by **client-combined partials**: each member
  emits `D_i = y_i·R` with a **Chaum–Pedersen DLEQ proof** binding it to its public share, and the
  client reconstructs `s·R` by **Lagrange-in-the-exponent** (the secret `s` is never formed) to unmask
  the plaintext. **No committee node ever holds the key or the plaintext.** Crate: `neo-mpc`.
- Deferred/honest: this delivers the property for the **decrypt** direction (committee → client). Full
  MPC-TLS — computing the handshake + record encryption under 2PC so the committee talks to a *real
  upstream* without any member seeing plaintext (garbled-circuit AES-GCM; TLSNotary/DECO/`mpz`) — remains
  research.
- Tests: threshold decrypt recovers without assembling the key (two distinct quorums); a sub-threshold
  set cannot; every partial verifies; a forged partial is caught by its DLEQ proof and an honest quorum
  still wins; a lone partial leaks nothing.

### M23 — Probe-resistant transports ✅ (REALITY-style auth + MASQUE/WebRTC camouflage)
Close M6's deferred strong transports.
- Done: `neo-crypto::reality` — a **REALITY-style authenticated first flight**: a client proves
  possession of a pre-shared capability (the server's X25519 public, distributed out of band, *not*
  published) with an authenticator that is **uniform-random to anyone without it**, epoch-bound against
  capture-replay; the server **silently** decides authenticate-vs-**decoy**, so an active prober cannot
  distinguish a neo bridge from an ordinary server. `neo-transport::Camouflage` shapes each record to
  imitate a **QUIC/MASQUE** datagram or a **WebRTC/DTLS** record, and `Transport::dial_reality` /
  `Listener::accept_reality` run the auth over a real connection. Crates: `neo-crypto`, `neo-transport`.
- Deferred/honest: `Camouflage` mimics the observable *shape*, not full protocol crypto (a real QUIC
  transport lives behind the `quic` feature); wiring the decoy to a genuine upstream TLS site and
  embedding the flight in a true TLS ClientHello are the remaining integration steps.
- Tests: honest client authenticates and shares a session seed; a prober (wrong key / random / short)
  only ever sees decoy; authenticators are unlinkable; a captured hello expires after the epoch window;
  camouflage round-trips both shapes and rejects the wrong shape; auth + camouflage work end-to-end over TCP.

---

## Audit gate ⬜
External security + cryptography audit **before anyone relies on neo for real safety.** This is a hard
gate, not a milestone to rush past.

[`RelayReceipt`]: ../core/crates/neo-credits/src/earn.rs
