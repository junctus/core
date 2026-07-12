# neo — milestones

The build roadmap and its live status. See `docs/ARCHITECTURE.md` for the design and the honest
constraints.

**Status legend:** ✅ done · 🔨 next / in progress · ⬜ pending

**Reality check:** the network is **live** — a discovery seed + two attested relay/exit nodes run in
production, and a client (`../neo-mac`) connects and browses. M0–M25, M28, and M36 are shipped and
tested (the **Shipped** table below), including the frontier research (anonymous credits, VRF paths,
committee exit, PIR + ZK shuffle), three rounds of internal security review with every finding fixed
(`SECURITY_REVIEW.md`), and the flagship — a **complete, adversarially-verified malicious-secure
two-party MPC-TLS crypto stack** (M24). The two hard gates before anyone relies on neo are the
**external cryptography audit** and **live MPC-TLS integration** (M45 — the crypto is built; wiring it
to a real session is systems work); the standing product gap is REALITY full-session indistinguishability
(M27). **Nothing here is audited; do not rely on neo for real-world safety until the audit gate.**

---

## Shipped

Every milestone below is ✅ done (built + tested; audit-gated like all of neo). One row each — the
committee-exit crypto ladder (M12 → M20 → M22) is folded into a single row because each rung is
superseded by M24/M28. The three highest-depth done milestones (M24, M28, M36) follow in **Kept at
depth**. "Deferred" items that have since shipped are reflected as done, not open.

| Milestone | Name | Crate(s) | Property (final truth) |
| --- | --- | --- | --- |
| M0 | Foundation | `neo-core`, `neo` CLI | Rust workspace, PQ-hybrid `NodeIdentity` (Ed25519 + X25519 + ML-KEM-768), `identity generate` (0600 key), CI green (build/test/clippy/fmt incl. libp2p + tun). |
| M1 | MVP tunnel | `neo-crypto`, `neo-dataplane`, `neo-node` | Signed hybrid AKE (ephemeral X25519 + ML-KEM-768, Ed25519-auth), directional ChaCha20-Poly1305 session with replay protection; `neo run --listen/--connect` over TCP; `neo run --tun` bridges a real TUN (needs root). QUIC → M6. |
| M2 | Onion routing | `neo-crypto::sphinx`, `neo-routing` | Full Sphinx over Ristretto: fixed-size packets, per-hop blinded secrets, filler trick, per-layer MACs, replay tags; fresh-per-request node-disjoint path selection + disjoint multipaths for shares. 1/3/5-hop delivery tested. |
| M3 | Information slicing | `neo-slicing`, `neo-node` | Encrypt-then-slice into Reed-Solomon k-of-n shares + reassemble/decrypt; any-k recovery, sub-threshold + tamper rejection. E2E test runs M3→M2→M3 (no single relay holds a complete readable flow). |
| M4 | Decentralization | `neo-discovery` | `Discovery` trait, in-memory `LocalRegistry`, `connection_ladder` (Direct→hole-punch→relay); real libp2p Swarm (Kademlia DHT + identify over TCP/Noise/yamux); `Libp2pDiscovery` announce/lookup via DHT, cross-node lookup tested. Hole-punch → M16. |
| M4.5 | Runnable discovery + Sybil resistance | `neo-core`, `neo-discovery`, `neo-seed`, CLI | Self-certifying signed `PeerRecord` (id = blake3(keys), expiry + seq); witness-signed snapshots (PIR-degenerate whole-set fetch); compact records + delta sync + anti-rollback; DHT client/server role split, verified PUTs, disjoint queries; `neo-seed` dial-back attestation + strike health; live seed→relay→client discovery, zero config. Deploy for discovery.junctus.org. NAT → M16. |
| M4.6 | Onion data plane over the network | `neo-node::forward`, CLI | Sender builds a Sphinx circuit from discovered relays and hands the onion to hop 1 over an authenticated session; each relay peels one layer, resolves next hop from its witness-verified snapshot, forwards; terminal hop delivers. `neo send --message --hops N`. Live seed + 3-relay + sender e2e; exactly one relay sees plaintext. Return path → M15. |
| M5 | Timing defense | `neo-mix`, `neo-node` | Exponential per-packet Poisson delays + Poisson cover traffic, `MixParams::for_level`, async `Mixer`; wired into the tunnel data plane. Global-passive-observer sim shows mixing decorrelates output from input order. |
| M6 | Unblockable | `neo-transport` | `Transport`/`Obfuscation` traits: `Plain` + `Bucketed` (length quantization + random padding) over TCP; real QUIC via `quinn` (feature `quic`, self-signed, neo authenticates above it). MASQUE/WebRTC/REALITY → M23. |
| M7 | Diffused exit | `neo-routing::exit` | `ExitPolicy` (opt-in, off by default, port rules), `ExitSelector` (rotates, never immediate repeat), `RouteRegistry` (no concurrent full-route reuse) — the statistical "no responsible exit". |
| M8 | Mobile/desktop FFI + clients | `neo-ffi`, `../neo-mac`, `../neo-linux` | Safe UniFFI API (`cdylib`/`staticlib`) over the shared core. Shipped clients on top of it: **`neo-mac`** (React Native → macOS + Android APK + iOS) and **`neo-linux`** (`.deb` terminal app + systemd). Store distribution + one-core consolidation → M46. |
| M9 | Core hardening | `neo-node`, `fuzz/` | Adversary-sim tests (colluding relays, single relay, on-path observer), GPO timing sim, cargo-fuzz wire-parser targets + no-panic-on-garbage; THREAT_MODEL "Simulated adversaries". External audit → audit gate. |
| M10 | Anonymous bandwidth credits | `neo-credits` | VOPRF (Privacy Pass): blind a serial, issuer blind-evaluates, finalize a token; redeem recomputes the OPRF, spend set rejects double-spends — issuance ↔ spending unlinkable. Earn-side accounting shipped in M17. |
| M11 | Verifiable routing | `neo-verify`, `neo-routing` | schnorrkel Ristretto VRF (prove/verify/select) + **commit-then-VRF** so neither client nor beacon biases the path seed and anyone can verify; `select_path_seeded` turns the seed into a reproducible path. |
| M12 · M20 · M22 | Committee-exit crypto (Shamir → Feldman VSS → threshold DLEQ decrypt) | `neo-mpc` | The trust-split ladder: Shamir GF(256) secret-sharing of the request (any k-1 learn nothing, corrupt share detectable); Feldman-VSS of the session key (every share checkable, corrupt share **attributed**); threshold hashed-ElGamal decrypt by **client-combined DLEQ partials** with Lagrange-in-the-exponent — **no committee node holds the key or plaintext** in the decrypt direction. Superseded/carried forward by M24 (2PC-TLS) + M28 (product wiring). |
| M13 | Verifiable privacy | `neo-verify`, `neo-discovery`, `neo-mix` | 2-server IT XOR PIR (neither server learns the index); keyword oblivious lookup (public `H(salt‖key) mod B` bucketing) so a client fetches a relay by NodeId privately; proof-of-mixing conservation check. Full ZK shuffle shipped in M19. |
| M14 | Core security hardening | (all core crates) | Closed every HIGH/MEDIUM from the internal review (`SECURITY_REVIEW.md`, R1/R2) with regression tests: Sphinx C-1/C-2/H-1 + wide-block (Lioness) payload; handshake H-3 UKS bind + H-4 key-confirm (m3) flight + stateless retry cookie + M-2; slicing per-share MACs + AEAD-bound header; discovery/seed H-2/H-5/M-6/M-7; routing/mix H-7/M-1/M-5/M-8. Audit gate remains. |
| M15 | Bidirectional streaming | `neo-node::stream` | Return path over M4.6: each hop derives a return-path stream key from its Sphinx shared secret; exit encrypts its response, each relay adds a layer, client (holding all keys) peels — middle relay never sees the plaintext response. Persistent byte stream shipped in M21. |
| M16 | NAT traversal | `neo-discovery` | `Reachability` (AutoNAT) + `connection_ladder_for` (public node skips hole-punch; NAT'd node Direct→DCUtR→Relay v2); libp2p backend carries AutoNAT + Circuit Relay v2 client + DCUtR, exposes `reachability()`; strategy unit-tested + behaviours co-exist with the DHT. (End-to-end NAT↔NAT hole-punch needs a real-NAT env to exercise.) |
| M17 | Earn-side credit accounting | `neo-credits::earn` | Client-signed `RelayReceipt`s + `EarnLedger` (verifies + de-dupes, converts proven bytes → earned credits, gating identified issuance while spend stays anonymous). Honest limit: receipts are client-attested, not trustless measurement. |
| M18 | DoH rendezvous bootstrap | `neo-discovery`, CLI | Signed `BootstrapRecord` (current mirrors + witnesses) under a long-lived bootstrap key (only that key is baked in), rollback protection (`not_before`), compact hex TXT; CLI fetches over DoH JSON + verifies. `neo bootstrap-record` / `bootstrap-resolve`. |
| M19 | ZK verifiable shuffle | `neo-verify::shuffle` | Grand-product / multiset-equality argument over Ristretto Pedersen commitments with chained ZK multiplication proofs + final equality, all Fiat–Shamir; verifier learns nothing of the permutation; soundness on DLog in ROM; `O(n)` (not succinct, not audited). Replaces the M13 conservation scaffold. |
| M21 | Persistent circuit tunnels | `neo-node::circuit`, `neo-node::mux` | One Sphinx packet sets up the circuit, then counter-keyed symmetric-onion **cells** (`[seq][onion body]`, per-cell e2e MAC keyed by the exit) — exit splices a real TCP connection: TCP-over-onion. `mux` runs many logical streams over one circuit with per-stream flow control, SSRF/port-checked per OPEN. Aggregate cross-stream congestion control remains a refinement. |
| M23 | Probe-resistant transports | `neo-crypto`, `neo-transport` | `reality` — REALITY-style authenticated first flight: client proves a pre-shared out-of-band capability with a uniform-random-to-outsiders authenticator, epoch-bound; server **silently** picks authenticate-vs-decoy (prober can't distinguish a bridge from an ordinary server). `Camouflage` shapes records to imitate QUIC/MASQUE or WebRTC/DTLS; `dial_reality`/`accept_reality` over a real connection. In-ClientHello embedding + full-session mimicry → M27. |
| M25 | Adversarial hardening round 2 | (M20–M24 + REALITY/credits/seed/circuit surfaces) | Second internal adversarial review; closed all findings with regression tests: **CRITICAL** REALITY low-order-point authenticator forgery → silent Decoy on non-contributory DH; REALITY per-epoch replay cache + randomized pad; circuit-cell replay/reorder/drop via `next_expected_seq`; seed dial-back SSRF + health-loop starvation (default-deny private ranges, capped registry, bounded sweep, rate limits); exit-splice open-proxy SSRF (thread `ExitPolicy`, reject internal ranges — the correctness half of M31/M41); length-distinguishable cover packets → fixed-cell padding; unbounded double-spend sets → per-epoch + key rotation + persisted `spent`; threshold-ciphertext malleability → KEM-DEM + identity-key guard; semi-honest MPC doc scoping; `sharks`→maintained Shamir + `cargo audit` in CI; VRF beacon abort-grinding; a LOW/hygiene bundle (zeroize handshake secrets, accept-loop timeouts/semaphore, oblivious empty-record reject, seeded shuffle in `sample_relays`, softened overclaims). Internal review — **not** a substitute for the audit gate. |

---

## Kept at depth

### M24 — Two-party MPC-TLS ✅ (malicious-secure 2PC crypto stack complete + adversarially verified; audit-gated)
Compute a TLS session under **two-party computation** so the record key and plaintext are **never
assembled at a single party** — built bottom-up, each layer checked against a reference before the next.
- **The stack (`neo-mpc::mpc_tls`), all correctness/abort-tested + adversarially verified:**
  - Base: Chou–Orlandi 1-of-2 OT + IKNP OT extension; a garbled-circuit engine (free-XOR, point-and-permute,
    ZRE15 half-gate AND, BLAKE3 correlation-robust hash); circuit builder with a 32-bit adder, ChaCha20,
    SHA-256 (vs NIST KAT), Poly1305 over GF(2¹³⁰−5) (vs RFC 8439 KAT); `dualex` dual-execution catches a
    cheating garbler.
  - Session: DECO-style additively-shared ECDHE (neither party learns pre-master `Z`); ChaCha20 keystream +
    Poly1305 tag + SHA-256 key schedule computed **under 2PC into XOR-shares**; **full RFC 8439 AEAD**
    (multi-block Poly1305, Horner) verified byte-for-byte vs the stock `chacha20poly1305` crate; **TLS 1.3
    record framing** (`seal_tls13_record_shared`, nonce = `static_iv ⊕ seq`, KAT-pinned).
  - Malicious stack: **KOS** malicious OT (GF(2¹²⁸) correlation check, aborts a cheating receiver) → malicious
    **`F_pre`** (leaky-AND triples + WRK17 bucketing) → **constant-round authenticated garbling** (WRK17/KRRW18,
    every wire doubly-authenticated, a corrupted garbled row ⇒ abort); **SPDZ** authenticated arithmetic
    (Beaver mul + triple sacrifice) for the field path.
  - Bridge: **ectf → a2b → SHA-256** chains EC point shares → `SHA-256(x-coordinate)` under 2PC (x-coord never
    assembled), validated against the `p256` crate + NIST SHA-256; A2B runs at the full 256-bit P-256 prime
    over constant-time `crypto-bigint` Montgomery residues. **HKDF-Expand-Label** under 2PC matched to the
    vetted `hmac`/`hkdf` crates.
- **"Done" here means the crypto stack is complete + tested + verified — audit-gated like all of neo, not
  production-proven.** ~62 correctness/abort tests, all green.
- Genuinely remaining (not crypto-primitive work): wire `ectf::mul_shared` onto the SPDZ Beaver online
  (**M38**); the KOS Roy22 fix an auditor applies (ships original KOS15); the **live TLS** state machine +
  record layer against a real server (**M45**). The live session path stays semi-honest with dual-execution's
  ≤1-bit leak until M45 lands — that *security* cannot be established by correctness tests.

### M28 — Verdict: the committee exit no one can subpoena ✅ (decrypt-direction, runnable end-to-end; real clearnet exit + DKG liveness deferred)
The product wiring of the M12/M20/M22 committee crypto into a **runnable** exit whose operators are
*cryptographically incapable* of reading your response.
- **Crypto foundation (no party holds the key):** Joint-Feldman **DKG** (`neo-mpc::dkg`) — `s = Σ_j s_j`,
  no dealer, no single party (not even the client) holds `s`; commitments/shares plug into the M22 threshold
  core. Wire serialization for `Ciphertext`/`Partial`/`KeyCommitments`/`KeyShare` (bounds-checked). A
  publishable **`NonCustodyProof`** (DLEQ) that a member holds only a threshold share.
- **On-circuit return path + live sockets:** `neo-node::committee` seals each hop's `Partial` under its own
  Sphinx-derived return secret (the hop nearest the client can't open them — no quorum); only the client opens
  and combines. `committee_request_response` / `handle_committee_circuit` drive fan-in over real connections;
  the exit `threshold::encrypt`s and discards plaintext; **networked Joint-Feldman DKG** (`run_dkg`) over the
  authenticated channel; `CommitteeDescriptor` discovery artifact; CLI `neo committee serve|send`.
- **Production refinements:** SSRF-guarded **real clearnet exit** with multi-chunk response; **crash-fault-tolerant
  DKG** over a qualified set; **circuit liveness** (retry k-member subsets, route around unavailable members in
  n>k); **seed discovery** (`GET|POST /committee`).
- **Deferrals (honest):** decrypt-direction only — the egress member sees plaintext at send (a full
  plaintext-free forward leg needs the **M33/M45** 2PC-TLS send path). DKG tolerates crash faults under
  synchrony, not a Byzantine member (safe — circuits fail — but a liveness regression). Descriptors served but
  not yet witness-attested; clearnet exit is send-then-read (no keep-alive awareness).

### M36 — Sybil-resistant relay admission + diverse path selection ✅ (subnet+ASN caps, diverse selection, PoW, uptime gate; continuous weighting deferred)
Caps *concentration*: dial-back binds identity↔address but nothing limited how many relays one operator runs
(N ports on one IP each attest), and clients picked hops with no subnet-diversity rule — so a cheap Sybil could
land the same operator on both ends of a circuit. M4.5 stops forging/hijacking, M11 makes selection unbiasable;
this adds cost + diversity.
- **Admission diversity (seed):** cap attested relays per `/24` (`MAX_ATTESTED_PER_SUBNET`) and per **ASN**
  (`MAX_ATTESTED_PER_ASN`, with `neo seed --asn-db`); registration stays unbounded, only snapshot listing is
  capped; internal/loopback exempt. Counts **only the dial-back-verified address** (a record can't pad `addrs`
  with a victim's `/24`/AS — fixed after adversarial review); cap survivors are earliest-registered.
- **Selection diversity:** `neo-core::net::SubnetKey` (IPv4 `/24`, IPv6 `/64`) + `prioritize_distinct_subnets`
  (best-effort reorder, falls back so a young network still builds circuits), wired into every live builder —
  `select_path`/`select_disjoint_paths`/`select_path_seeded` (stays VRF-verifiable), `ExitSelector` (rotates the
  subnet), FFI netstack picker, desktop `pick_circuit`, `sample_relays`. (Committee circuit untouched — it routes
  its whole fixed roster.)
- **NodeId PoW:** `neo-core::pow` bound to the relay NodeId, verified by the seed before admit
  (`require_registration_pow`, default on).
- **Uptime gate:** optional seed-measured maturation (`neo seed --min-maturity`) — unforgeable (measured by
  dial-back), raises the Sybil *time* cost; off by default (in-memory seed).
- **Honest scope:** raises flood cost from "sign N records" to "control N reachable hosts across ≳N/2 distinct
  `/24`s **and** spend N PoWs **and** pass N dial-backs" — **not** full Sybil resistance (a `/16`, rented `/24`s,
  or IPv6 blocks still defeat subnet diversity; CPU PoW is cheap at scale). Bandwidth-weighting was deliberately
  **declined** for the anti-Sybil path (M17 receipts are client-attested → forgeable input) — proven bandwidth
  gates the credit economy (M32), not selection; the unforgeable signal (uptime) shipped as the gate instead.
- **Open item:** *continuous* uptime weighting (witness-signed per-relay weight + client weighted selection)
  needs a `SNAPSHOT_VERSION` bump + diff-sync + client rollout → **M40**.

---

## Active

### M27 — Genuine in-ClientHello REALITY with a live decoy reverse-proxy 🔨 (in-ClientHello + decoy shipped; full-session TLS mimicry is the remaining flagship piece)
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
- **Shipped (in-ClientHello + decoy):** `neo-transport::tls` — a hand-rolled, structurally-valid TLS 1.3
  ClientHello builder/parser that hides the 64-byte authenticator in fields already uniform-random
  (`eph_pub`→`key_share`, `tag`→`legacy_session_id`, real REALITY's layout). `dial_reality` writes a real
  ClientHello (with SNI); `accept_reality` reads a real TLS record, extracts the fields, and classifies;
  `Conn::reverse_proxy_decoy` splices an un-authenticated prober to an operator-pinned upstream (SSRF-guarded,
  connect + splice timeouts). `neo-crypto` gained `RealityKey::client_hello_prefix`. An adversarial review
  confirmed the ClientHello is structurally valid (a real TLS server/Wireshark accepts it) and the parser is
  panic-free with no false-authentication path.
- **NOT yet delivered — the flagship property is not met (honest).** A three-lens review found the
  authenticated path is still distinguishable: **(1, critical)** after the ClientHello the server sends **no
  ServerHello** — the authenticated session drops straight into neo's obfuscated framing, so a censor that
  merely observes the handshake it initiated sees "no server response, then the client keeps sending," a
  trivial tell. Real REALITY completes a full TLS 1.3 handshake on the auth path too (proxying the upstream's
  ServerHello + cert) and diverges only *inside* the encrypted stream. **(2)** auth-vs-decoy **timing**
  differs (the decoy dials an upstream; the auth path doesn't). **(3)** the ClientHello is **one fixed,
  non-browser-matching fingerprint** (improved with renegotiation_info/status_request/SCT, but still not a
  byte-exact uTLS profile — itself a tell). So this shipped the two *additive* pieces the plan named, which
  are necessary but **not sufficient**: the remaining work is **full-session TLS mimicry** — the auth path
  proxying a real handshake with matched timing, plus a uTLS-grade fingerprint. That is a substantial
  separate effort. Keep "no undetectable language": today a probe cannot forge the authenticator, but a
  censor *can* still distinguish an authenticated neo session from a real TLS site.

---

## Next wave

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
- Plan: the M24 2PC-TLS core (`neo-mpc::mpc_tls`) now has both deferred sub-protocols built and tested —
  the **EC point→field conversion** (`ectf`, validated against `p256`) that turns the shared ECDHE point
  into the x-coordinate share feeding the SHA-256 key-schedule circuit, and the **complete malicious 2PC**
  (`kos` malicious OT → `authgarble` malicious `F_pre` leaky-AND + bucketing → constant-round authenticated
  garbling; `spdz` for the field path; `hkdf` key schedule matched to the vetted crates), all adversarially
  verified. The MPC-TLS crypto is **done**. What M33 still needs on top is **not crypto-primitive work**: the
  formal proofs + the **external audit**, and the **live wiring** — a real TLS 1.3 handshake state machine +
  record layer against an actual server (systems integration). Then
  a selective-opening circuit proves one fact ("balance > X", "account age > 2y") while the session bytes are
  never assembled anywhere. Also delivers the real distrusted-exit browsing mode and the plaintext-free
  forward leg M28 needs.
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

### Post-live-network wave ⬜ (from research stack → real, operable, trustworthy)

The core crypto and the frontier research are shipped; the live network runs. The highest-leverage work
now is turning that into something people can *use, operate, and trust*, and closing the last named gaps
to end-to-end malicious security and a live MPC-TLS session. These are **achievable engineering** (not
open research), sequenced roughly by leverage-per-effort. (Several finish or re-scope an existing ⬜:
noted inline.)

- **M37 — Local SOCKS5/HTTP-CONNECT proxy front-end** ⬜ ("point any app at neo") · ~1–2 wk. The built,
  tested multi-stream mux circuit (`neo-node::mux`) is only reachable via `neo send` / the Mac FFI. Add
  `neo proxy --listen 127.0.0.1:1080` (SOCKS5 + HTTP CONNECT on loopback) that opens a logical stream per
  connection over a discovered mux circuit (reuse `serve_mux`, the exit SSRF/port guard). Instantly makes
  any browser/CLI usable — no new crypto or wire protocol.
- **M38 — Wire ECtF onto the SPDZ Beaver online** ⬜ · ~1–2 wk. The one named internal wiring between
  today's stack and **end-to-end malicious** EC conversion: replace `ectf`'s four `mul_shared` calls with
  `spdz::beaver_mul` over authenticated `[x]` shares so a tampered multiplicand *aborts* via `sacrifice()`.
  Both endpoints are built + tested; lowest-effort, highest-certainty security upgrade on the list.
- **M39 — Operator observability** ⬜ · ~1–1.5 wk. Two relays, a seed and committee nodes run in
  production behind one `/healthz` string. Add a **localhost-only** (127.0.0.1) Prometheus `/metrics` +
  tiny status page: circuits served, bytes relayed, exit-reject rate by reason, dial-back pass/fail,
  attested-vs-registered, per-subnet/ASN cap headroom, committee quorum. (Never `0.0.0.0` — a metrics port
  is itself a fingerprint.)
- **M40 — Seed HA: 2nd independent seed + k-of-n witness quorum + persisted registry** ⬜ · ~2 wk. The
  live trust root is a **single** witness key on a **single** seed (a bootstrap SPOF; the wire formats
  already allow up to 16 witnesses). Persist the seed registry to disk (survive restart), stand up a 2nd
  seed on a different provider/ASN with its own witness key, and move clients to k-of-n snapshot
  verification (start 2-of-2) via a staged trust-set migration that never strands existing clients.
- **M41 — Exit-policy engine + traffic governor** ⬜ (finishes **M31**; its SSRF/enforcement half landed
  in M25 and DNS was un-blocked here) · ~1 wk. Turn the hardcoded denylist into named presets
  (`--exit-policy reduced|web|custom`), operator allow/deny TOML, and a per-destination token-bucket
  governor. The exit-supply unlock.
- **M42 — `neo doctor`: connectivity + leak self-test** ⬜ ("am I actually protected?") · ~1 wk. Build a
  real circuit, report apparent exit IP/geo through the overlay, check DNS-resolves-through-the-tunnel (no
  OS leak), verify the snapshot is fresh/witness-valid and above the anonymity-set floor. Surface it via
  FFI so the Mac client shows it.
- **M43 — One-command relay onboarding** ⬜ · ~1.5 wk. Turn "build from source on the target box" (with
  its OOM/glibc/PATH gotchas) into a CI release pipeline: signed static musl binaries (x86_64 + aarch64) +
  SHA-256SUMS + minisign/cosign + a distroless container + a hardened `neo relay-setup`. Grows exit supply.
- **M44 — Audit-readiness package** ⬜ · ~1.5 wk. Directly compresses the hard gate: a frozen
  `AUDIT_SCOPE.md` (exact crates/commits in/out, each labelled built/proven/deployed), a threat-model→code
  traceability matrix, a reproducible build, and a consolidated KAT/test-vector corpus. No new runtime
  code; high leverage.
- **M45 — Live 2PC-TLS: drive the complete stack against a real TLS 1.3 server** ⬜ (the gap between
  "crypto complete" and "MPC-TLS works"; unblocks the **M33** attestor) · ~4–6 wk. Replace
  `session.rs::shared_ecdhe`'s in-process simulation with a real TLS 1.3 handshake driver both parties
  jointly execute over a socket — real ClientHello with the split-scalar key share, real ServerHello
  parse, the server's actual transcript-hash feeding the HKDF schedule, `seal_tls13_record_shared` on the
  wire. All the crypto exists; this is the state machine + record framing + the two-party channel harness.
- **M46 — Client store distribution + one-core consolidation** ⬜ (finishes **M8**'s deferred half) ·
  ~2–3 wk. The clients already exist and run on the shared `neo-netstack` + `neo-node` core: **`../neo-mac`**
  (React Native — ships **macOS + Android APK** today, iOS from the same tree) and **`../neo-linux`** (Rust
  terminal app + systemd service, ships a **`.deb`**). Remaining is *distribution*, not first build: a
  notarized macOS release + **iOS TestFlight/App-Store**, a signed **Play-Store AAB**, reproducible signed
  release pipelines for all three, and pinning the three clients to a single audited core version (a
  shared FFI so they don't drift). Mobile is where censorship-circumvention demand is highest.

Also re-scoped by the above: **M27** (REALITY) — the remaining flagship piece is proxying the upstream's
genuine ServerHello on the authenticated path (byte-identical handshake), ~3–4 wk of systems work reusing
`reverse_proxy_decoy` + the ClientHello codec; **M30** (fixed-cell constant-rate) and **M33** (attestor)
become concretely achievable once M45 lands.

---

## Audit gate ⬜
External security + cryptography audit **before anyone relies on neo for real safety.** This is a hard
gate, not a milestone to rush past.

---

## Priority order (remaining work)

Recommended sequence for everything still 🔨/⬜, ordered by leverage-per-effort and dependencies. The
product waves (A–B) are mostly *outside* the crypto audit scope, so they run **in parallel** with the
audit path (C). Two existing items are subsumed: **M31** → M41, **M8**'s deferred half → M46.

**Wave A — make it usable & operable** *(low effort, high daily value; do first)*
1. **M37** — SOCKS5 / HTTP-CONNECT front-end · point any app at neo (the mux circuit is built, just unexposed).
2. **M39** — operator observability · stop flying blind on the live seed/relays/committee.
3. **M41** — exit-policy engine + governor · the exit-supply unlock (already started — DNS un-blocked; finishes M31).
4. **M42** — `neo doctor` connectivity + leak self-test · user trust ("am I actually protected?").
5. **M38** — wire ECtF → SPDZ Beaver · small, high-certainty; completes **end-to-end malicious** EC conversion.

**Wave B — resilience & supply** *(remove single points of failure, grow the network)*
6. **M40** — 2nd independent seed + k-of-n witness quorum · kills the single-seed/single-witness bootstrap SPOF.
7. **M43** — one-command signed relay onboarding · grow exit supply (signed static binaries + container).
8. **M46** — client store distribution · notarized macOS + iOS TestFlight + Play AAB (clients already ship).

**Wave C — the audit path & the flagship** *(the gates before real reliance; can overlap A–B)*
9. **M44** — audit-readiness package · freeze scope + threat-model→code map; compresses the hard gate.
10. **Audit gate** — engage the external cryptography audit · start once M38 + M44 land; the hard gate.
11. **M27** — REALITY full-session indistinguishability *(🔨 in progress)* · the flagship censorship property.

**Wave D — flagship capability & research horizon** *(larger / longer; sequence by appetite)*
12. **M45** — live 2PC-TLS against a real server · the gap between "crypto complete" and "MPC-TLS works".
13. **M33** — attestor (verifiable facts about a private TLS session) · category-defining; **gated on M45**.
14. **M30** — fixed-cell constant-rate circuits · close the metadata size/timing tell.
15. **M32** Relaykit credit economy · **M34** self-healing bootstrap · **M29** bridge-in-a-QR · **M35** enumeration-resistant bridge distribution.

[`RelayReceipt`]: ../core/crates/neo-credits/src/earn.rs
