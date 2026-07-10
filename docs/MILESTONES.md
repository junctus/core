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
- Done (snapshot scaling): **compact records** drop the 1184-byte ML-KEM key (~85% of a record) from
  snapshots — the record signature covers `id` (which commits to the key), so one signature serves both
  forms and the client re-checks the key commitment in-band at dial time (`peer_id == id`). **Delta sync**
  (`GET /snapshot/diff`) ships only what changed since a client's cached set; the client reconstructs and
  re-verifies the witness signatures, falling back to a full fetch on any mismatch. Anti-rollback
  (`verify_fresh`) now wired on both paths.
- Done (DHT hardening): client/server **role split** (clients are DHT-invisible), inbound `PUT`
  verification (`StoreInserts::FilterBoth`), **disjoint query paths**, seq-aware caching + TTLs.
- Done (seed): `neo-seed` — verify + **dial-back handshake attestation** (proves address ↔ key) +
  strike-based health + witness-signed snapshot; axum service (`/snapshot`, `/snapshot/diff`, `/healthz`,
  `/witness`, rate-limited `/register`), serving **no user traffic**.
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

### M24 — Full two-party MPC-TLS core ✅ (real 2PC; full AEAD + key schedule under MPC)
Take M22 to the real thing: compute a TLS session under **two-party computation** so the record key and
plaintext are **never assembled at a single party** — built and verified bottom-up, then the documented
"remaining steps" done: the SHA-256 key schedule, Poly1305 MAC, OT extension, and a malicious-security step.
- Done: `neo-mpc::mpc_tls` — a genuine 2PC stack, each layer checked against a reference before the next:
  - `ot` / `ot_ext` — 1-of-2 **oblivious transfer** (Chou–Orlandi) and **IKNP OT extension** (many cheap OTs
    from `k=128` base OTs).
  - `garble` — a **garbled-circuit** engine: free-XOR, point-and-permute, **ZRE15 half-gate** AND, INV via
    the offset; BLAKE3 as the correlation-robust hash.
  - `circuit` — a boolean circuit builder + a ripple-carry **32-bit adder** and the full **ChaCha20** block
    function; `sha256` — **SHA-256** as a circuit (verified vs the NIST KAT); `poly1305` — **Poly1305** over
    `GF(2¹³⁰−5)` (verified vs the RFC 8439 KAT). Each garbled circuit is checked against its plaintext oracle.
  - `session` — a DECO-style **additively-shared ECDHE** (neither party learns the pre-master `Z`); the
    ChaCha20 keystream **and** Poly1305 tag computed **under 2PC into XOR-shares**; the SHA-256 **key schedule
    under 2PC**; and an end-to-end **ChaCha20-Poly1305 record sealed under 2PC** where neither party ever
    holds the key, keystream, or plaintext.
  - `dualex` — **dual-execution**: a cheating garbler is caught by an output-equality check.
  Crate: `neo-mpc`.
- Deferred/honest (well-scoped steps, not a redesign): **full** malicious security (authenticated garbling
  removes dual-execution's ≤1-bit leak); the **EC point→bit share conversion** (DECO's sub-protocol) that
  feeds the shared ECDHE secret into the key-schedule circuit; and **live wiring** to a real TLS socket on
  the server's actual curve with full HKDF/AEAD framing.
- Tests (21): OT delivers only the chosen message; IKNP extends correctly past `k`; every gate garbles over
  all inputs; garbled adder matches native add with OT-split inputs; ChaCha/SHA-256/Poly1305 references match
  their KATs and the circuits match the references; ECDHE is additively shared and matches the server;
  keystream / key-schedule / MAC each run under 2PC into shares (no share alone reveals the secret); a
  **ChaCha20-Poly1305 record seals under 2PC** and verifies against a stock implementation; dual-execution
  agrees honestly and catches a cheating garbler.

---

### M25 — Adversarial hardening round 2 ✅ (all round-3 review findings fixed)
A second internal adversarial review (across the PQ-AKE, Sphinx, REALITY, MPC, credits, seed, and
circuit surfaces — the code written after M14) surfaced one **critical**, several **high**, and a set
of medium/low issues. This milestone closes them with regression tests before any of the new capability
milestones ship. Nothing below is exploitable through today's binary in isolation, but each is a real
property of shipped, public, documented library code.
- Plan:
  - **CRITICAL — REALITY low-order-point authenticator forgery.** `reality.rs::classify` (line 91) does
    `diffie_hellman(&PublicKey::from(eph)).to_bytes()` with **no contributory / low-order check**, so a
    prober who sends the identity point gets an all-zero shared secret it can also compute — and forges
    `Verdict::Authenticated` **without the capability**, falsifying the module's central claim
    (`reality.rs:14-21`). Fix: after the DH, take the **silent `Decoy`** path if the result is
    non-contributory (`if ct_eq(&shared, &[0u8;32]) { return Verdict::Decoy }`, or validate `eph` against
    the small-order set); returning `Decoy` (never an error) preserves indistinguishability. Add a
    regression test that an identity/low-order `eph` yields `Decoy`.
  - **HIGH — REALITY replay + static wire fingerprint.** `classify` keeps no per-epoch replay cache, so a
    captured hello re-authenticates for the current **and** previous epoch (`reality.rs:93`, and the
    existing `a_captured_hello_expires_after_the_epoch_window` test *proves* this window). The first
    flight is also a fixed 96-byte high-entropy blob behind a cleartext `00 00 00 60` length prefix
    (`neo-transport::write_blob`), a passive DPI tell. Fix: bound per-epoch replay cache of seen
    ephemerals → `Decoy` on repeat; bind server-contributed randomness into the transcript; randomize the
    pad length. The wire-embedding fix proper is M27.
  - **HIGH — circuit cells have no end-to-end replay/reorder/drop protection.** `exit_splice` (forward,
    `circuit.rs:328-349`) and `CircuitStream::recv` (return) read `seq` but never compare it to an
    expected value, so a malicious middle relay can duplicate/re-inject a captured cell under a fresh
    **link** counter and the endpoint's e2e MAC still passes. Fix: track `next_expected_seq` per direction
    and reject out-of-order/duplicate `seq`; amend the `circuit.rs:22-25` doc (which claims parity with
    Sphinx's replay-once payload) until it holds.
  - **HIGH — seed dial-back SSRF + health-loop starvation.** `neo-seed` health (`health.rs`) dials any
    attacker-named address in a registered record via `TcpStream::connect` with no
    loopback/RFC1918/link-local/`169.254.169.254` filter, and the sweep is a serial `for record in due`
    loop over the whole (uncapped) registry. Fix: parse each addr to a `SocketAddr` and default-deny
    private/loopback/link-local/metadata ranges (prefer IP-literal-only, no DNS); cap registry size;
    run dial-backs with a bounded `FuturesUnordered` + per-sweep time budget; add a global outbound-dial
    rate limit and IPv6-prefix (`/64`) cooldown keying.
  - **HIGH — exit-splice open-proxy SSRF.** `exit_splice` calls `TcpStream::connect(target)`
    (`circuit.rs:320`) with no policy and no internal-range filter; `ExitPolicy::permits` (`exit.rs:57`)
    exists, is off by default, and is **never threaded in** (it also only checks ports, not IP class).
    Fix: thread an `Arc<ExitPolicy>` into `serve_circuit`/`exit_splice`, extend `ExitPolicy` to reject
    loopback/RFC1918/ULA/link-local/metadata destinations, and gate the connect on it. (This is the
    correctness half of M31; land it here so no exit path is ever wired without it.)
  - **HIGH — cover packets are length-distinguishable from real packets.** `tunnel.rs:81-83` emits every
    cover cell as a constant `1 + COVER_SIZE` (1025-byte) frame while real frames are `1 + packet.len()`
    and length-preserving through the sealer, so a global passive observer partitions cover from real by
    ciphertext length — defeating the size half of the cover-traffic defense (`neo-mix:8-9`). Fix: pad all
    real frames to a fixed cell size ≥ `COVER_SIZE` before sealing, carry the true length inside the
    sealed plaintext, and correct the `neo-mix`/`tunnel.rs` docs. (M30 generalizes this to the circuit.)
  - **HIGH — unbounded double-spend/claimed sets with no epoch or key rotation.** `Issuer.spent`
    (`credits/lib.rs:39`) and `EarnLedger.claimed` grow forever with no eviction, and there is no
    key-rotation API — a redeploy that regenerates the key silently re-enables replay of every historical
    serial (the `spent` set is not persisted). Fix: tag credits/receipts with an issuer-key **epoch**,
    keep per-epoch sets that retire, add an explicit rotation API with a redeem grace window, and persist
    `spent` across restarts. (Prerequisite for M32's economy.)
  - **MEDIUM — threshold ciphertext is malleable + trusts the joint key.** The threshold hashed-ElGamal
    ciphertext `(R, c)` is an unauthenticated XOR stream (`threshold.rs:61-72,186-189`) with no INT-CTXT,
    and `joint_public_key` (`threshold.rs:194`) has no `is_identity()` guard, so an attacker-supplied
    identity commitment collapses the mask to a fixed public keystream. Fix: adopt KEM-DEM — wrap the
    payload in ChaCha20-Poly1305 (as `vss.rs` already does) and verify the tag in `combine()`; reject an
    identity joint key; feed `R` into the KDF. (Prerequisite for M28's committee exit.)
  - **MEDIUM — semi-honest MPC + doc/model gaps in `session.rs`.** The shipped TLS gadgets route through
    the pure semi-honest `eval_2pc`; `dualex` is a standalone/test-only demo not on the session path, and
    `seal_record_shared` emits a **single-block, non-RFC-8439** Poly1305 tag (no length block / AAD) that
    would not verify against a stock AEAD (`session.rs:173`). Fix: state plainly in `mpc_tls.rs`/
    `session.rs` that the session is semi-honest-only and the tag is not the AEAD tag; scope the "verifies
    against stock ChaCha20-Poly1305" claim to the reference used. Full malicious security + real AEAD
    framing is M33 research, not a doc patch.
  - **MEDIUM — `sharks 0.5.0` (RUSTSEC-2024-0398) biased Shamir coefficients + overclaimed secrecy.**
    `neo-mpc` depends on the unmaintained `sharks` whose top polynomial coefficient is drawn from
    `[1,255]`, so the "information-theoretic, any k-1 learn nothing" doc (`neo-mpc/lib.rs:8-15,152`) is
    stronger than the primitive delivers. Fix: migrate to the maintained `blahaj` fork (or a vetted
    GF(256) Shamir) with a share-uniformity test, or soften the doc until then; add
    `cargo audit --deny warnings` (or `cargo-deny`) to `ci.yml` so future advisories fail the build.
  - **MEDIUM — VRF beacon abort-grinding.** `neo-verify::selection` computes the path seed before
    responding, so a malicious beacon can abort-and-retry to draw favorable i.i.d. samples
    (`selection.rs:42-45`); the "neither can bias" doc (line 7) overclaims. Fix: derive the VRF input from
    beacon-independent epoch randomness + a monotonic client counter (retries are not fresh samples),
    treat a missing response as a committed loggable abort, and/or use a threshold of beacons; correct the
    doc.
  - **LOW/hygiene bundle.** Zeroize handshake intermediate secrets (`ikm`, `dh`, `ss`, `k_confirm` in
    `handshake.rs`); add handshake read timeouts + a concurrency semaphore in `run::accept` and spawn the
    per-connection handshake so a stalled client can't head-of-line the accept loop; reject empty records
    in `neo-verify::oblivious::build` (a zero-length record aliases an empty bucket, `oblivious.rs:133-144`);
    use the seeded Fisher–Yates shuffle in `libp2p_backend::sample_relays` instead of `take(n)` over
    HashMap order (`libp2p_backend.rs:401`); soften the several doc-comments flagged as overclaims
    (snapshot anti-rollback, `dial_reality` "indistinguishable from random", multi-block Poly1305,
    slicing "attributable by index").
- Why it matters: the M20–M24 code is the newest, never-audited surface, and the project's honesty ethos
  means a shipped overclaim is itself a defect. The REALITY forgery in particular breaks the flagship
  probe-resistance claim outright and gates every REALITY milestone below.
- Boundary/risk: these are internal-review findings, not an external audit — they raise the floor but do
  **not** substitute for the audit gate. Several fixes (real AEAD under 2PC, authenticated garbling) are
  research and are deliberately left to M33, not forced into this hardening pass.

---

## Game-changer roadmap

The milestones below turn neo's tested-but-unwired primitives into differentiated product capabilities.
Each is buildable on existing crates — no capability here is a from-scratch research project unless its
boundary says so. They are sequenced so the enabling wiring (M26) lands before the features that ride it,
and every REALITY/MPC milestone depends on the M25 hardening fixes.

### M26 — One-tap local proxy over live circuits ⬜ (the "on" switch)
Why it matters: today no ordinary app can use neo without writing Rust — this is the single translation
layer between neo-the-engine and neo-the-product.
- Plan: build a `NeoSocket` that implements `tokio`'s `AsyncRead`/`AsyncWrite` over
  `CircuitSink::send` / `CircuitStream::recv` (`neo-node/circuit.rs:110-151`), buffering across the
  variable-length cell boundary (the existing round-trip test at `circuit.rs` already handles
  `cell != send` manually — that logic becomes `poll_read`). Wrap it in a localhost **SOCKS5** listener
  that parses the destination and calls `open_circuit` (`circuit.rs:156`) against a snapshot-discovered
  path (`neo-discovery` + `neo-routing::select_path`), bound by `neo run --proxy 127.0.0.1:1080`.
  **Requires first wiring `serve_circuit` into the relay loop** — the desktop relay currently runs the
  one-shot `handle_onion_shared` (`roles.rs:124`), not the persistent circuit path, so relays must run
  `serve_circuit` for `open_circuit` to have a peer. Add connection pooling / circuit reuse so per-stream
  Sphinx+PQ setup latency is amortized.
- Why a game-changer: a localhost SOCKS proxy + an `AsyncRead`/`AsyncWrite` type makes every browser, the
  OS proxy toggle, and every Rust HTTP/gRPC/WebSocket library (`hyper`, `tonic`, `rustls`,
  `tokio-tungstenite`) run **unmodified** over a 3-hop onion — with no TUN, no root, no app-store friction.
  It is the smallest change with the largest "now it's a product" delta and the correct core for the
  mobile SDK.
- Boundary/risk: needs the M25 circuit-cell seq enforcement (replay/reorder) and the exit-policy SSRF fix
  landed first, since this wires `serve_circuit` into a running node. No return-path congestion control
  yet, so large downloads may stall; Poisson-mixing latency can trip TLS handshake timeouts unless the
  `PrivacyLevel` dial is surfaced honestly.

### M27 — Genuine in-ClientHello REALITY with a live decoy reverse-proxy ⬜ (flagship)
Why it matters: this converts neo's tested REALITY auth core from "probe-resistant in theory" into the
actual REALITY threat model — a bridge that *is* a real website to any prober.
- Plan: two additive pieces on top of the M23 auth core (`neo-crypto::reality`) and the M25 forgery fix.
  (1) A minimal, correct **TLS 1.3 ClientHello builder** that hosts the 64-byte ephemeral+tag prefix
  inside fields that are already uniform-random (`key_share` / `session_ticket` / GREASE), replacing the
  bespoke `write_blob` u32-length flight (`neo-transport::dial_reality`, `lib.rs:242`) so the first packet
  is byte-for-byte a normal handshake. (2) Wire the `Verdict::Decoy` branch — today
  `RealityAccept::Decoy { conn }` hands back a bare `Conn` with no upstream (`lib.rs:298`) — to
  **reverse-proxy** the un-authenticated connection to an operator-pinned upstream `:443`, reusing the
  splice pattern already in `exit_splice` (`circuit.rs:312`), so a prober gets a real cert and a real page.
- Why a game-changer: this is the property that defeats the active-probing that killed Shadowsocks and
  plain VLESS — a censor's own scanner cannot tell a neo bridge from a benign website because it literally
  is one to anyone without the capability, and neo layers a PQ-hybrid onion behind it, which REALITY does
  not. Few VLESS deployments even ship the decoy-proxy correctly.
- Boundary/risk: matching a specific JA3/JA4 fingerprint exactly is fiddly and drifts as browsers update —
  a frozen fingerprint becomes its own tell. The authenticate-vs-decoy paths must match on timing, TLS
  version/ALPN, and TCP-reset behavior or a sophisticated censor distinguishes on side channels. Do **not**
  use "undetectable" language until this and M25's replay-cache fix both land; keep the honest-boundary
  note current.

### M28 — Verdict: the committee exit no one can subpoena 🚧 (flagship trust story; crypto foundation done, live path pending)
Why it matters: an exit whose operators are *cryptographically incapable* of complying with a wiretap is
a trust model Tor and commercial VPNs structurally cannot offer.
- Done (crypto foundation, no party holds the key): **DKG** (`neo-mpc::dkg`) — Joint-Feldman distributed
  key generation over Ristretto, so the committee's joint key has **no dealer**: `s = Σ_j s_j`, and no
  single party — not even the client — ever holds `s`. Its aggregate `KeyCommitments` + per-member
  `KeyShare` plug straight into the M22 threshold core. **Wire serialization** for `Ciphertext`, `Partial`,
  `KeyCommitments`, `KeyShare` (bounds-checked, non-canonical scalars rejected) — the encodings the live
  path sends between egress, members, and client. **Verifiable non-custody artifact** (`neo-mpc::attestation`
  `NonCustodyProof`): a member proves, via a DLEQ on a fresh challenge bound to its committed share, that it
  holds only a threshold share and is confined to partial decryption — the publishable "even the exit can't
  read your response" proof. In-process end-to-end test: DKG → egress encrypts response → members emit
  partials → only the client combines; a lone member cannot decrypt.
- Remaining (live multi-node path): (a) **M26 prerequisite** — relays must run a persistent circuit-serving
  loop (they currently one-shot `handle_onion_shared`); (b) a **committee descriptor + discovery** so a
  client learns a committee's roster + published joint `KeyCommitments`; (c) wiring the **egress** to
  `threshold::encrypt` its response and discard the plaintext, with **response chunking** across
  `MAX_CIPHERTEXT` pieces; (d) collecting each member's `Partial` back to the client over the return path
  (fan-in, with over-provisioning `n>k` + timeout for liveness); (e) the **`neo run --committee`** role loop.
- Why a game-changer: "no responsible exit" stops being a statistical hope and becomes a checkable
  cryptographic fact — a new trust story a journalist can give a source ("even the exit can't rat you
  out, and here is the DLEQ proof"), and a near-zero-liability role for altruistic operators in strict
  jurisdictions who would never run a clearnet exit.
- Boundary/risk: delivers the property for the **decrypt** (committee → client) direction only. A full
  wiretap-proof exit that *also* speaks to the real upstream with no member seeing plaintext needs the
  M33 2PC-TLS send-path, which remains research — so this ships as "the committee cannot read the
  response," **not** "plaintext never exists end-to-end" (the egress member sees plaintext at send).
  Prerequisites M22 threshold core + M25 KEM-DEM/identity-key fixes are in place. DKG is Joint-Feldman
  (a rushing adversary can bias `Y`'s distribution — GJKR99 — which reveals neither `s` nor plaintext; the
  Pedersen "New-DKG" hardening is a deferred refinement). Committee liveness/DoS and Sybil member selection
  remain operational risks.

### M29 — Bridge-in-a-QR: pre-shared REALITY capabilities as unblockable private bridges ⬜
Why it matters: every unblockable-networking product eventually loses its bridges to enumeration and
active probing — neo can ship bridges whose *existence* is cryptographically undetectable.
- Plan: an SDK layer over the M23 REALITY primitives (`RealitySecret::generate/classify`,
  `RealityKey::client_hello`, `Transport::dial_reality`/`accept_reality`): a `RealityCapability` type that
  serializes to a QR/link, a **bridge-runner** helper that loops `accept_reality`, forwards
  `Authenticated` connections into the overlay, and (via M27) reverse-proxies `Decoy` connections to a
  real upstream, plus epoch-clock management. An app embeds its own private bridge fleet with no public
  bridge list to scrape.
- Why a game-changer: a censor holding a bridge IP still cannot confirm it runs neo, and there is no
  enumerable list — the failure mode that kills Tor bridges and Shadowsocks servers is structurally
  absent. No other embeddable stack ships the capability-as-unpublished-key property.
- Boundary/risk: inherits the exact same dependency as M27 — until the decoy is a real TLS session and the
  flight is embedded in a true ClientHello, a sophisticated censor comparing against real TLS servers can
  still distinguish it. The SDK must gate any "unblockable" claim on M27; ship it as "probe-resistant
  against active scanning" until then. Also needs M35-style credit/PoW gating to resist a client-side
  enumeration of the capability distribution.

### M30 — Fixed-cell constant-rate circuits ⬜ (tunneling itself becomes hidden)
Why it matters: even with a perfect handshake, censors confirm tunnels by their steady-state size/timing
signature — a constant-shape flow removes the single most reliable passive discriminator.
- Plan: compose two shipped primitives at the circuit cell boundary. `neo-mix` already emits
  `MixOut::Cover` at Poisson intervals scaled by `PrivacyLevel` and `neo-transport` already buckets to
  fixed sizes; wire both into `CircuitSink::send` / `exit_splice` (`circuit.rs`) so every cell is padded
  to a fixed bucket (a length tag inside the MAC'd body) and clocked on a timer, injecting cover cells
  when idle. This closes the `circuit.rs:31-33` "length hiding is punted" gap and builds directly on the
  M25 real-frame-padding fix.
- Why a game-changer: it turns "the payload is hidden" into "the fact that you are tunneling is hidden" —
  a constant-rate carrier breaks end-to-end flow correlation, the attack the anonymity trilemma otherwise
  leaves open. Tor added padding machines only after years; neo composes it from primitives it already has.
- Boundary/risk: constant-rate cover is a direct bandwidth/battery tax and a non-starter on
  mobile/cellular (ARCHITECTURE constraint 5) — it must be a top-dial-only mode that degrades hard on
  battery. A naive constant rate is itself a fingerprint unless the profile imitates a plausible app (a
  video call), not a metronome; and cover that starts/stops with the session still leaks session boundaries
  unless warmed.

### M31 — Enforced exit policy + reduced-harm default ⬜ (the exit-supply unlock)
Why it matters: abuse complaints and legal exposure are *the* reason exit supply never materializes;
right now `exit=true` is maximally unsafe.
- Plan: build the operator-facing half on top of the M25 SSRF/enforcement fix. Add a curated
  **reduced-harm** default policy (443/DoH/messaging only; SMTP/25, file-sharing, known-abuse ports
  blocked), per-destination and global rate limits, and an allowlist mode to `ExitPolicy`
  (`neo-routing::exit`), exposed as `neo run --exit-policy {reduced|web|custom}` with the safe policy as
  the one-flag default. The trust-diffusion machinery (rotating exits, disjoint routes, `RouteRegistry`)
  already exists to spread residual exposure.
- Why a game-changer: it converts "nobody sane runs an exit" into "a cautious person can run a 443-only
  exit and sleep at night" — a correctness fix *and* a supply unlock for the same low effort.
- Boundary/risk: must be paired with the honest ARCHITECTURE framing — clearnet exit is diffused and
  rotated (statistical), never zero-responsibility; a reduced policy lowers complaint volume, it does not
  grant legal immunity. Blocking too much by default hurts usefulness, so the reduced-harm port set needs
  care.

### M32 — Relaykit: the unlinkable earn↔spend credit economy ⬜
Why it matters: overlays starve from the free-rider and Sybil traps; a token-free, unlinkable
"relay-to-earn, spend-to-browse" loop is a third path Tor's altruism and crypto-VPNs' coins cannot take.
- Plan: wire the tested but unwired earn side into the relay runtime. `neo-credits` has VOPRF
  blind-issue/redeem with a double-spend set (`lib.rs:63-153`) and `earn.rs` has `RelayReceipt` +
  `EarnLedger` (M17) — but issuance is currently ungated (see M25). Build: the client signs a
  `RelayReceipt` at circuit teardown (`neo-node::circuit`), the relay accumulates them in an `EarnLedger`,
  `issue()` atomically consumes a proven earning before blind-evaluating, and a **localhost-only** status
  dashboard (reusing `neo-seed`'s axum stack) shows credits earned / bytes relayed / circuits served so
  "leave it on" becomes felt.
- Why a game-changer: contribution funds your own anonymity, and earn↔spend are cryptographically
  unlinkable (the issuer only ever sees a blinded serial) — a self-bootstrapping incentive loop that
  attacks the Sybil *and* free-rider problems with one Privacy-Pass primitive, no wallet, no KYC, no coin.
- Boundary/risk: `earn.rs` receipts are **client-attested**, not a trustless bandwidth measurement — a
  colluding client+relay can fabricate capped receipts per nonce, so this bounds Sybil to the cost of
  running clients, not to zero. The dashboard must frame credits as anti-free-riding utility, not a
  payout, and must bind to localhost only (a metrics port on `0.0.0.0` is itself a fingerprint).
  Bilateral co-signed receipts + the M25 epoch/rotation fix are prerequisites before any
  "proof-of-bandwidth" language.

### M33 — Attestor: cryptographic proofs about a private TLS session ⬜ (north-star, research-grade)
Why it matters: no VPN, Tor, or mixnet can produce a verifiable fact-proof about a TLS session because
they all terminate or relay plaintext somewhere — neo's 2PC-TLS is the only stack where the record key
and plaintext are provably never assembled at one party.
- Plan: finish the two explicitly-deferred steps of the M24 2PC-TLS core (`neo-mpc::mpc_tls`, which
  already seals a ChaCha20-Poly1305 record under 2PC verified against a reference, with DECO-style
  additively-shared ECDHE): the **EC point→bit share conversion** that feeds the shared ECDHE secret into
  the SHA-256 key-schedule circuit, and **live HKDF/AEAD wiring** to a real TLS socket on the server's
  actual curve. Then a selective-opening circuit proves one fact ("balance > X", "account age > 2y")
  while the session bytes are never assembled anywhere. Also delivers the real distrusted-exit browsing
  mode and the plaintext-free forward leg M28 needs.
- Why a game-changer: TLSNotary/DECO-grade oracle attestation delivered as an anonymity-network-native
  capability — portable KYC / proof-of-income / proof-of-humanity / whistleblower evidence that is
  provably from the real site, a category normal privacy tools structurally cannot enter.
- Boundary/risk: **research-grade — the largest remaining crypto build.** The EC share-conversion
  sub-protocol, full malicious security (authenticated garbling removes dual-execution's ≤1-bit leak,
  which is not on the session path today per M25), and live socket framing are each substantial; 2PC-TLS
  is slow and only viable for small, sensitive requests, not general browsing. This **must not** ship
  before the external audit gate and must be labeled clearly as the low-bandwidth paranoid mode.

### M34 — Self-healing bootstrap control loop ⬜ ("it just reconnects")
Why it matters: "they blocked my bridges and I can't get new ones" is exactly where Tor bridges and
V2Ray subscriptions fail under an adaptive censor.
- Plan: pure orchestration of three shipped, tested pieces. On reachability failure, a client-side state
  machine rotates DoH resolvers and pulls a fresh signed `BootstrapRecord` (`neo-discovery::bootstrap`,
  M18 — anti-rollback via `not_before`), fetches a new witnessed snapshot from whichever mirror is
  reachable (integrity separated from distribution, M4.5, so the mirror can be a throwaway on any big
  CDN), and pays for the new entry point with an unlinkable credit (M10). Sequence:
  resolver-rotate → mirror-rotate → snapshot-refresh → credit-spend, no human and no new config file.
  Also wires the not-yet-consumed anti-rollback high-water mark the M18/M4.5 primitives already expose.
- Why a game-changer: it treats reachability as a control loop rather than a static config; because the
  mirror is untrusted and the credit is unlinkable, pulling a new entry point neither requires blessed
  infrastructure nor builds a profile — the "it just reconnects" experience that makes people recommend a
  tool.
- Boundary/risk: DoH resolvers themselves get blocked or poisoned (Iran has done this), so it needs a
  diverse rotating resolver set and eventually Encrypted ClientHello. The first-contact seed problem
  remains (ARCHITECTURE constraint) — if the very first bootstrap key/mirror is burned before install,
  the loop has nothing to start from.

### M35 — Enumeration-resistant bridge distribution ⬜ (credit/PoW-gated capabilities)
Why it matters: the strongest REALITY bridge is worthless if an adversary posing as a client can cheaply
enumerate and burn the whole fleet — the classic way nation-states kill bridge networks.
- Plan: a distribution service that trades a **spent unlinkable credit + a proof-of-work** for a bucketed
  `RealityKey` capability (à la Tor's bridgedb buckets), reusing the `neo-credits` double-spend machinery
  (M10) and the earn-side proof-of-relay (M17) so enumeration cost scales with bandwidth an attacker must
  actually earn. Extends `neo-credits` + the M29 capability type.
- Why a game-changer: it converts "scrape the bridge list" into "run honest bandwidth for every bridge you
  want to burn" — a structural enumeration defense using the anti-Sybil primitive Tor lacks, not a
  heuristic.
- Boundary/risk: bucketing/PoW tuning is a cat-and-mouse economics problem (too cheap and enumeration
  still works; too expensive and real users can't bootstrap). It ties bootstrap to the credit economy
  whose earn side is honestly still client-attested (M17/M32 caveat), so it is only worthwhile once M27's
  wire path and M32's hardened earning land.

---

## Audit gate ⬜
External security + cryptography audit **before anyone relies on neo for real safety.** This is a hard
gate, not a milestone to rush past.

[`RelayReceipt`]: ../core/crates/neo-credits/src/earn.rs
