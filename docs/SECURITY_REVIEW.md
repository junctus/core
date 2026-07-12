# neo — Security Review (consolidated)

This is neo's **living internal security review**: the cumulative record of every adversarial pass over the cryptographic core and networked data plane, from the original two-round core analysis through the MPC-TLS / REALITY / circuit round and the full-codebase pass. It is an internal review and **not an external audit** — **neo remains unaudited and must not be relied on for real-world safety until the external cryptography-and-security audit gate** (`MILESTONES.md`). Every finding below is remediated (each with a regression test where applicable) and the workspace is `fmt` / `clippy -D warnings` / `test` clean, but internal review only raises the floor; it is not the audit. The raw, un-deduplicated per-round logs (Round 1–2 core analysis, Round 3 MPC/REALITY/circuit, Round 4 full-codebase) live in git history.

## Cumulative findings

Every distinct finding from every round, deduplicated to its final resolution and sorted by round then severity. Round abbreviations: **R1/R2** = original core analysis (two rounds), **R3** = MPC-TLS / REALITY / circuit round, **R4** = full-codebase pass. Where the same issue was logged across rounds, the row carries its final status and cross-references the IDs.

| ID | Round | Sev | Area | Finding (one line) | Status | Fix (commit/milestone) |
|----|-------|-----|------|--------------------|--------|------------------------|
| C-1 | R1 | CRIT | sphinx | Onion payload δ unauthenticated → end-to-end tagging attack defeats unlinkability | fixed | exit-verified payload MAC; wide-block Lioness PRP closed residual (M14) |
| C-2 | R1 | CRIT | sphinx | Identity/all-zero α → public constant shared secret → key-free packet forgery | fixed | `identity.rs` rejects identity point; also at build time (R2-6) |
| H-1 | R1 | HIGH | sphinx | Replay tag recorded before MAC check → cache-poisoning / targeted-drop DoS | fixed | authenticate header MAC first, then record tag |
| H-2 | R1 | HIGH | forward | Per-call `ReplayCache` → replay defense absent across connections | fixed | `handle_onion_shared`; relay owns one lifetime cache |
| H-3 | R1 | HIGH | handshake | Only Ed25519 key authenticated, not full `NodeId` (kex/kem) → UKS | fixed | bind full NodeId in transcript |
| H-4 | R1 | HIGH | handshake | No key confirmation; m1 replay → responder DoS (ML-KEM per replay) | fixed | key-confirmation flight + stateless retry cookie |
| H-5 | R1 | HIGH | seed | `X-Forwarded-For` trusted → cooldown bypass + SSRF dial amplification | fixed | honor XFF only from trusted proxies, right-most hop |
| H-6 | R1 | HIGH | slicing | "reveal nothing" is computational (rests on AEAD key), not information-theoretic | fixed | docs/tests corrected; Krawczyk SSMS tracked (M14) |
| H-7 | R1 | HIGH | routing | Seeded path selection used only 64 of 256 seed bits → unreachable permutations (n≥21) | fixed | full-width seed consumption |
| M-1 | R1 | MED | routing | Disjointness over Vec indices not `NodeId` → duplicate relay breaks node-disjointness | fixed | `Router::new` dedups by `NodeId` |
| M-2 | R1 | MED | handshake | Transcript over raw m1 bytes; 1-byte append = deterministic DoS; no trailing-byte check | fixed | canonical transcript + trailing-byte rejection |
| M-3 | R1 | MED | slicing | Shares not individually authenticated → one relay silently forces reassembly failure | fixed | per-share MAC |
| M-4 | R1 | MED | slicing | Reassembly trusts unauthenticated header fields | fixed | bind header as AAD |
| M-5 | R1 | MED | mix | `getrandom` failure panics the mixer task; per-sample syscall | fixed | non-panicking RNG handling |
| M-6 | R1 | MED | discovery | Snapshot rollback/freeze: no lower bound on `created_at`; single-witness default | fixed | freshness bounds + witness threshold |
| M-7 | R1 | MED | discovery/forward | Unbounded 16 MiB frame + 32 MiB snapshot allocations; no connection cap | fixed | bounded allocations + caps |
| M-8 | R1 | MED | routing/exit | `RouteRegistry` de-conflicts identical routes only, not shared exit nodes | fixed | de-conflict shared exit nodes |
| R2-2 | R2 | CRIT | credits | `RelayReceipt.bytes` unbounded `u64` → one signed receipt mints ~10¹³ credits | fixed | `MAX_RECEIPT_BYTES` cap; per-receipt scope documented honestly |
| R2-1 | R2 | HIGH | streaming | Return path had per-hop XOR but no end-to-end integrity → middle relay mauls response | fixed | exit prepends e2e return MAC; client verifies (`stream.rs`) |
| R2-3 | R2 | HIGH | credits | Base (non-verifiable) OPRF → issuer key-tags earners and de-anonymizes spends | fixed | switched to verifiable VOPRF; DLEQ proof checked on finalize |
| R2-4 | R2 | MED | sphinx | `ReplayCache` unbounded `HashSet` → memory exhaustion; fresh-cache footgun | fixed | two-generation rotating bounded cache; footgun helper removed |
| R2-5 | R2 | MED | sphinx | Payload MAC covered payload but not the length prefix → truncation oracle | fixed | MAC now covers `len ‖ payload` |
| R2-6 | R2 | MED | sphinx | Packet builder didn't reject identity-point hop key → node-independent secret | fixed | `create_packet_keyed` rejects identity hop key |
| R2-7 | R2 | MED | committee | `open()` aborted on first bad share → one member vetoes a quorate reconstruction | fixed | skip-and-attribute bad shares; succeed at ≥ threshold honest |
| R2-8 | R2 | LOW | committee | `verify` accepted `member == 0`; `lagrange_at_zero` could invert a zero denominator | fixed | reject index 0; fail loudly on zero denominator |
| R3-01/R3-19 | R3 | CRIT | REALITY | Low-order/identity x25519 eph point → authenticator forgery without the capability (PoC) | fixed | reject non-contributory DH → silent `Decoy`; low-order test added |
| R3-02 | R3 | CRIT | credits | `issue()` mints to anyone; issuance fully decoupled from earning | fixed | issuance gated on proven, atomically-consumed earnings |
| R3-03 | R3 | HIGH | REALITY | Fixed 100-byte plaintext first flight — static passive DPI fingerprint | fixed | randomized pad length; doc scoped to authenticator body |
| R3-04 | R3 | HIGH | REALITY | No replay cache → captured hello re-authenticates for the epoch window | fixed | bounded per-epoch replay cache; `Decoy` on repeat |
| R3-05 | R3 | HIGH | credits | `spent`/`claimed` sets grow unbounded; no epoch/rotation/persistence | fixed | per-epoch sets, key-rotation API, persisted spent set |
| R3-06 | R3 | HIGH | circuit | Forward cells had no replay/reorder/drop protection at the exit (latent) | fixed | endpoint enforces strict in-order + e2e MAC; middle-relay reorder is by-design network-loss (R4-refuted) |
| R3-07 | R3 | HIGH | circuit | Return cells had no replay/reorder/drop protection at the client (latent) | fixed | client enforces expected-return-seq; e2e return MAC |
| R3-08 | R3 | HIGH | seed | Dial-back is unfiltered SSRF (loopback/RFC1918/metadata) | fixed | `is_safe_dial_target` SSRF guard (later hardened for IPv4-mapped, R4-1) |
| R3-09 | R3 | HIGH | seed | No registry cap + serial dial loop → health-loop starvation / attestation censorship | fixed | registry cap, concurrent bounded dial-backs, per-sweep budget |
| R3-10 | R3 | HIGH | mix/cover | Cover packets length-distinguishable from real packets on the wire | fixed | uniform cell sizing before sealing; docs corrected |
| R3-11 | R3 | HIGH | circuit/exit | Exit TCP splice is an open proxy — SSRF, no exit policy (latent) | fixed | SSRF guard + `ExitPolicy::permits_port` in both splice paths (R4-3) |
| R3-12 | R3 | MED | 2PC session | Dual-execution never wired into session; gadgets are pure semi-honest | fixed | docs state session gadgets are semi-honest-only, dualex standalone |
| R3-13 | R3 | MED | 2PC session | `seal_record_shared` emits a non-AEAD tag doc'd as stock ChaCha20-Poly1305 | fixed | doc corrected to single-block-Poly1305 (not RFC 8439 AEAD) |
| R3-14 | R3 | MED | committee VSS | `encrypt()` accepts an identity joint key → fixed public keystream | fixed | reject identity joint key / commitments / public share |
| R3-15 | R3 | MED | committee VSS | Threshold hashed-ElGamal ciphertext unauthenticated / malleable (no INT-CTXT) | fixed | KEM-DEM AEAD wrapper; tag verified in `combine()` |
| R3-16 | R3 | MED | credits | Doc claimed issuer can rate-limit earner, but it never sees the identity | fixed | resolved with R3-02 wiring; doc corrected |
| R3-17 | R3 | MED | credits | Receipts have no timestamp/expiry — colluding client pre-signs unbounded receipts | fixed | server-context binding (challenge/epoch/timestamp); honest doc retained |
| R3-18 | R3 | MED | verifiable privacy | Oblivious directory: zero-length records cause silent, undetected collisions | fixed | reject empty records / separate occupancy bitmap |
| R3-20 | R3 | MED | verifiable privacy | Beacon can bias path selection by abort-grinding; doc claimed no party can bias | fixed | doc scoped to fixed-commitment; abort-retry biasing disclosed |
| R3-21 | R3 | MED | transport camouflage | DTLS epoch is always a prefix of the sequence field (deterministic tell) | fixed | disjoint random bytes; per-connection monotonic seq / stable CID |
| R3-22 | R3 | MED | transport camouflage | Cleartext inner length field + TCP length prefix real QUIC/DTLS never carry | fixed | doc tightened to disclose framing mismatch |
| R3-23 | R3 | MED | seed | Per-IP register cooldown the only limiter; bypassable with IP diversity | fixed | global rate limit + registry cap; IPv6 keyed by /64 |
| R3-24 | R3 | MED | supply chain | `sharks 0.5.0` (RUSTSEC-2024-0398) biased Shamir coefficients (test-only path) | fixed | migrated to bias-free `blahaj` fork (R4-8) |
| R3-25 | R3 | MED | supply chain | Doc claimed Shamir information-theoretic secrecy `sharks 0.5.0` didn't deliver | fixed | `blahaj` migration makes the claim actually true (R4-8) |
| R3-48 | R3 | MED | node data plane | No handshake/read timeouts or connection caps — slowloris head-of-line on accept | fixed | timeouts on handshake reads; spawn per-conn handshake; `Semaphore` cap |
| R3-26 | R3 | LOW | AKE/record | "Stateless" cookie is neither stateless nor source-bound; over TCP only gates ML-KEM | fixed | doc corrected; connection rate-limiting added (R3-48) |
| R3-27 | R3 | LOW | AKE/record | Handshake intermediate secrets (DH, ML-KEM ss, IKM, k_confirm) not zeroized | fixed | wrap in `Zeroizing`; `PendingResponder` zeroizes `k_confirm` |
| R3-28 | R3 | LOW | sphinx | Replay-cache horizon count-driven, not time-driven; no routing-key rotation | fixed | honest doc retained; epoch rotation tracked |
| R3-29 | R3 | LOW | sphinx | Payload delta unauthenticated at non-exit hops → deliver/reject confirmation oracle | fixed | honest non-malleability-residual doc retained |
| R3-30 | R3 | LOW | 2PC OT/IKNP | IKNP extension has no receiver-consistency check (selective-failure; gated out) | fixed | header note; extension kept gated out |
| R3-31 | R3 | LOW | 2PC docs | `mpc_tls` doc omits semi-honest-only qualifier where OT/IKNP are introduced | fixed | reworded with semi-honest qualifier |
| R3-32 | R3 | LOW | 2PC dualex | `check_pass` not a secure equality test; ≤1-bit bound is the protocol's not the code's | fixed | doc softened to idealized in-process model |
| R3-33 | R3 | LOW | 2PC dualex docs | ≤1-bit bound assumes a committed/simultaneous equality channel not provided | fixed | header clause added |
| R3-34 | R3 | LOW | 2PC Poly1305 | Doc claimed multi-block Horner Poly1305 the circuit doesn't implement | fixed | doc corrected to single-16-byte-block only |
| R3-35 | R3 | LOW | 2PC Poly1305 | `tag_circuit` hard-codes high bit at position 128 (partial final block mis-padded) | fixed | documented single-block support; assert added |
| R3-36 | R3 | LOW | 2PC tests | Circuit KATs single-sample per gadget; no boundary/adversarial vectors | fixed | boundary + random-vector KATs added |
| R3-37 | R3 | LOW | committee VSS docs | Threshold decryption doc'd "verifiable" without disclosing ciphertext malleability | fixed | doc discloses partial-verifiability scope (AEAD after R3-15) |
| R3-38 | R3 | LOW | committee VSS | `combine()` takes `threshold` decoupled from committed degree → silent garbage | fixed | validate `threshold` against committed degree |
| R3-39 | R3 | LOW | discovery | `SignedSnapshot::verify` has no anti-rollback/freshness param (no consumer yet) | fixed | doc scoped; `not_before` param to be added with snapshot client |
| R3-40 | R3 | LOW | discovery docs | Doc-comments claim a snapshot anti-rollback high-water mark that isn't implemented | fixed | reworded to expiry + future-skew cap only |
| R3-41 | R3 | LOW | discovery | libp2p `sample_relays` deterministic (`HashMap take(n)`), unlike shuffled `LocalRegistry` | fixed | getrandom-seeded Fisher-Yates before truncate |
| R3-42 | R3 | LOW | verifiable privacy | `selection_index` has modulo bias + uses 64/256 bits; doc claims "verifiably fair" (unused) | fixed | full-width rejection sampling / removed; doc corrected |
| R3-43 | R3 | LOW | transport camouflage | `dial_reality` doc claimed flight "indistinguishable from random" despite structured prefix | fixed | claim scoped to authenticator body |
| R3-44 | R3 | LOW | circuit docs | Doc claimed cell integrity is "the same guarantee" as Sphinx replay-once | fixed | doc states per-cell tamper-detection only; ordering is higher-layer |
| R3-45 | R3 | LOW | mix/cover | Cover co-terminous with the session — coarse activity envelope exposed | fixed | Loopix-class per-session-cover limitation documented |
| R3-46 | R3 | LOW | mix/RNG | OS-RNG-failure fallback yields a deterministic delay (~0.693·mean), no operator signal | fixed | seed fallback CSPRNG once; log repeated RNG failures |
| R3-47 | R3 | LOW | slicing docs | Doc claimed corrupt shards "attributable by index"; API never surfaces the index | fixed | doc corrected to detect-and-drop-as-erasure |
| R3-49 | R3 | LOW | transport camouflage | `recv`/`read_blob` allocate up to 16 MiB from an unauthenticated 4-byte length | fixed | first-flight/`read_blob` cap reduced far below `MAX_RECORD` |
| R3-50 | R3 | LOW | supply chain | No cargo-audit/deny advisory gate in CI; permissive specs rely on the lockfile | fixed | advisory gate to `ci.yml` (see R4 process note) |
| R3-51 | R3 | INFO | AKE/record | m1 carries no anti-replay nonce → bounded per-connection ML-KEM+Ed25519 CPU-DoS | fixed | doc clarification; combine with R3-48 rate-limiting |
| R3-52 | R3 | INFO | sphinx | 128-bit MAC/payload tags with an unlimited online oracle (2⁻¹²⁸ per try — safe) | fixed | documented as intended sufficient target |
| R3-53 | R3 | INFO | 2PC OT | Chou-Orlandi sender never validates receiver point R (harmless under Ristretto) | fixed | forward-looking portability note |
| R3-54 | R3 | INFO | 2PC session | `shared_ecdhe` is a self-play simulation, not a live two-party handshake | fixed | doc annotates local self-play model |
| R3-55 | R3 | INFO | credits | `redeem()` uses non-verifiable `evaluate()` — correct for issuer==verifier | fixed | recorded; no action for issuer==verifier design |
| R3-56 | R3 | INFO | discovery | Bootstrap `not_before` anti-rollback correct but has no consumer yet | fixed | recorded; wire when DoH client exists |
| R3-57 | R3 | INFO | core identity | NodeId self-cert does not cover the Sphinx routing key (bound by signature instead) | fixed | doc corrected; routing key authenticated by record signature |
| R4-1 | R4 | CRIT | seed/exit | IPv4-mapped IPv6 (`[::ffff:127.0.0.1]`, `[::ffff:169.254.169.254]`) bypassed the SSRF guard | fixed | V6 branch recurses on `to_ipv4()`; mapped-loopback normalized (`1c46192`) |
| R4-2 | R4 | CRIT | circuit | Cell `seq` unchecked `+= 1` → `u64` overflow reuses XOR keystream | fixed | all six increment sites `checked_add` and error on overflow (`1c46192`) |
| R4-3 | R4 | HIGH | exit | Exit was an open proxy — no port policy (relays SMTP:25, SSH:22, plaintext DNS:53) | fixed | `ExitPolicy::permits_port` + `DENIED_EXIT_PORTS` baseline (`c5e9576`); full policy M31 |
| R4-4 | R4 | HIGH | seed | Registration rate-limit stamped before body-parse/PoW → shared-IP quota burn | fixed | parse + PoW-verify first, then spend quota (`c5e9576`) |
| R4-5 | R4 | HIGH | core identity | `NodeIdentity::to_bytes()` returned raw secret material lingering in freed heap | fixed | returns `Zeroizing<Vec<u8>>`; FFI-boundary copy documented (`c5e9576`) |
| R4-6 | R4 | MED | committee | Committee sealed-partial keystream (`xor_mask`) not zeroized | fixed | wiped before return; neo-node gains `zeroize` dep (`18f90c0`) |
| R4-7 | R4 | MED | transport camouflage | TLS ClientHello `server_name` cast to `u16` unclamped → malformed hello | fixed | clamp to 253-byte DNS-name maximum (`18f90c0`) |
| R4-8 | R4 | LOW | supply chain | `sharks 0.5.0` RUSTSEC-2024-0398 biased GF(256) coefficients backed `neo-mpc` split | fixed | migrated to bias-free `blahaj` fork; secrecy caveat now satisfied (`18f90c0`) |

**Refuted in R4 (verified as *not* bugs, no fix):**
- *"Middle relay can't enforce cell sequencing on the forward path."* By design — sequencing is an *endpoint* property (exit and client enforce strict in-order delivery with a per-cell e2e MAC). A middle relay dropping/reordering is indistinguishable from network loss and cannot forge or read cells. This is the design basis for R3-06/R3-07's resolution.
- *"FFI mutex-poisoning panic."* The spawned FFI tasks don't hold the mutexes across `.await`, so a panic can't poison them; the lock scopes are non-panicking.

## What is genuinely solid (verified, not assumed)

The reviews actively tried to break these across every round and could not. They are recorded both to note what works and to avoid re-litigating them.

**Cryptographic core.**
- **Session AEAD has no nonce reuse.** Directional key separation is correct (each direction keys `seal`/`open` oppositely); the counter nonce is strictly monotonic and hard-errors on overflow rather than wrapping — the single most important record-layer property, and it is right.
- **`verify_strict` everywhere** for Ed25519 (rejects malleable/small-order), and **Ristretto** for the group (prime-order, no cofactor/small-subgroup pitfalls beyond the identity case, now rejected).
- **Hybrid combiner is sound** (`HKDF(X25519 ‖ ML-KEM)` — secure if *either* holds; no downgrade path, both primitives always used), with transcript binding.
- **KDF domain separation** is clean and distinct across every context (handshake, records, NodeId, Sphinx subkeys, records vs snapshots).
- **Parsers are bounds-checked and panic-free** across records, snapshots, and Sphinx packets, each with a fuzz-lite garbage test.

**Sphinx onion routing.** The Lioness wide-block SPRP genuinely prevents a chosen readable-pattern mauling (avalanche-tested); the replay cache correctly rejects within its documented horizon; header MACs are checked before any expensive point operation; the packet builder and process path both reject the identity point. The residuals (R3-28/R3-29/R3-52) are honest, documented LOW/INFO correlation/margin notes — not breaks.

**Discovery / seed.** Discovery records are unforgeable (full signature coverage + self-certifying id + `verify_strict`; every ingest path verifies; `seq`/`expires_at` bound replay). DHT inbound filtering (`FilterBoth`) + disjoint query paths. Dial-back attestation genuinely proves key possession + address control. k-of-n witness counting is correct (dedup, unknown-key skip, impossible-threshold reject, forged-record-is-fatal).

**VOPRF credit unlinkability and redemption soundness.** The cryptographic core is sound: verifiable mode forces one published key so a spend cannot be key-tagged back to an earner, the DLEQ proof is checked on finalize, `redeem()` recomputation is authoritative for issuer==verifier, and double-spend rejection works. The credit *system* failures found (R3-02/R3-05/R3-16/R3-17) were all in the earning/issuance plumbing and lifecycle, not in the OPRF math, and are now fixed. The DLEQ one-key unlinkability and issuance gating re-verified clean in R4.

**Committee / MPC.** The **ZK verifiable shuffle** (grand-product multiset equality with a Fiat–Shamir multiplication proof) was probed for a forged product, a transferable proof across challenges, and a zero-factor bypass — all rejected; five `poc_*` probes are retained as regression tests, and its honest linear-size (non-succinct) limit is documented, not a defect. The **AEAD-wrapped VSS path** (`vss.rs`) correctly wraps its body in ChaCha20Poly1305, the DLEQ partial-decryption proofs authenticate each partial against the committed share, and honest-flow commitments are random non-identity points. MPC/committee re-verified clean in R4 (canonical-scalar enforcement, non-panicking deserialization, sound Chaum-Pedersen DLEQ / NonCustodyProof, sealed-partial return path a relaying member can't open).

**The 2PC-TLS core's primitives (within their semi-honest model).** Chou-Orlandi base OT is correct over Ristretto (prime-order group makes the missing R validation harmless; the pad KDF binds S and R so pads don't cross-replay). Free-XOR garbling uses a fresh independent `delta` and label randomness per garble call. The Poly1305 `reduce_circuit` is structurally sound and agrees with the RFC 8439 reference for the single 16-byte block. The `shared_ecdhe` share math is correct (`share1 + share2 = x_pub·s = z_server`, neither share alone reveals Z). With the flagged doc lines corrected, the stack's self-description is accurate: a working, in-process, semi-honest-modelled prototype that does not yet resist a malicious peer and is not wired into a live network.

**Routing / verifiable selection.** The exponential mix sampler is correct/unbiased; OS-path Fisher–Yates is unbiased; the exit-policy opt-in/port/rotation logic resisted every bypass attempt. VRF soundness, commit-then-VRF unbiasability (for a fixed commitment), node-disjoint multipaths, and the M36 subnet-diversity reorder all held. The live per-request selection uses full-width rejection sampling with no modulo bias.

**Memory-safety hygiene.** `#![forbid(unsafe_code)]` covers 13 crates; the two that can't (`neo-ffi`, `neo-netstack`) plus the three explicit `unsafe` sites (`netif.rs`, `committee.rs`, `main.rs`) were reviewed and are sound. No memory-safety or panic-on-attacker-input issue was found in the reviewed data-plane paths beyond the resource-exhaustion items already listed.

## Accepted boundaries (known, documented, not new bugs)

These are honest standing limits the code already states and remain open work items — known, not silently present:
- **DKG is crash-fault-tolerant, not Byzantine-tolerant.** A member reporting inconsistent qualified-set views can split honest members onto different keys (a liveness, not a secrecy, regression). Needs a broadcast/agreement primitive.
- **M27 REALITY is not full-session-indistinguishable.** The authenticated path doesn't complete a real TLS handshake, and the fingerprint is one fixed non-browser profile (`MILESTONES.md` M27).
- **Proof-of-relay receipts are client-attested / forgeable** (`neo-credits::earn`); credits stay anti-free-riding utility with no cash value until hardened (`MONETIZATION.md`, `MILESTONES.md` M32/M36).

## Closing note

The **external cryptography-and-security audit is the hard gate**: no amount of internal review replaces it, and neo must not be relied on for real-world safety until it passes. This document raises the floor; it is not that audit. For the adversary model these findings were evaluated against — a malicious relay/exit on the path, a malicious or coerced seed/witness, an active network adversary/censor, a malicious peer sending hostile wire input, and a colluding sub-threshold set of committee members — see [`THREAT_MODEL.md`](THREAT_MODEL.md).
