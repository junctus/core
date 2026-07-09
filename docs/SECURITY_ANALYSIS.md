# Core security analysis

An adversarial review of neo's core cryptography and networked data plane,
conducted over **two rounds**. Round 1 was four independent parallel reviews
(AKE + session, Sphinx onion routing, the novel core: slicing/mix/routing, and
the networked discovery/seed/forwarding layer). Round 2 re-reviewed the areas
that had grown since — the streaming return path, the anonymous-credits earn/spend
flow, the verifiable committee (VSS), and the Sphinx internals in more depth.
Findings are concrete, cite `file:line`, and several were **PoC-confirmed**
against the real code. This is an internal review, **not** the external audit
that gates real-world use.

**Status:** **all** findings from both rounds are now **fixed** with regression
tests. Round 1: the two CRITICAL Sphinx breaks (C-1, C-2), every HIGH (H-1
through H-7), and every MEDIUM (M-1 through M-8), plus the full **wide-block
non-malleable payload** (Lioness) closing C-1's residual tagging channel. The
handshake gained both a **key-confirmation flight** and a **stateless retry
cookie** (H-4): a replayed or connect-and-abandon m1 now costs only a MAC, never
an ML-KEM encapsulation. Round 2: the streaming return-path integrity gap (R2-1),
the unbounded credit-mint (R2-2, CRITICAL), non-verifiable OPRF deanonymization
(R2-3), and five MED/LOW hardenings across Sphinx and the committee (R2-4..R2-8).
The one thing that remains before real use is the **external security +
cryptography audit**, which no amount of internal review replaces.

## Severity summary

| # | Sev | Area | Finding | Status |
|---|-----|------|---------|--------|
| C-1 | 🔴 CRIT | sphinx | Onion payload `δ` unauthenticated → end-to-end **tagging attack** | **fixed** |
| C-2 | 🔴 CRIT | sphinx | Identity/all-zero `α` → public constant shared secret → **key-free forgery** | **fixed** |
| H-1 | 🟠 HIGH | sphinx | Replay tag recorded **before** MAC check → cache-poisoning / targeted drop | **fixed** |
| H-2 | 🟠 HIGH | forward | Per-call `ReplayCache` → replay defense absent across connections | **fixed** |
| H-3 | 🟠 HIGH | handshake | Only Ed25519 key authenticated, not full `NodeId` (kex/kem) → **UKS** | **fixed** |
| H-4 | 🟠 HIGH | handshake | No key confirmation; m1 replay → responder DoS (ML-KEM per replay) | **fixed** |
| H-5 | 🟠 HIGH | seed | `X-Forwarded-For` trusted → cooldown bypass + SSRF dial amplification | **fixed** |
| H-6 | 🟠 HIGH | slicing | "reveal nothing" is **computational, not** information-theoretic (doc conflation) | **fixed** |
| H-7 | 🟠 HIGH | routing | Seeded path selection uses only 64 of 256 seed bits → unreachable permutations (n≥21) | **fixed** |
| M-1 | 🟡 MED | routing | Disjointness over indices not `NodeId` → duplicate relay breaks node-disjointness | **fixed** |
| M-2 | 🟡 MED | handshake | Transcript over raw m1 bytes; 1-byte append = deterministic DoS; no trailing-byte check | **fixed** |
| M-3 | 🟡 MED | slicing | Shares not individually authenticated → single relay silently forces reassembly failure | **fixed** |
| M-4 | 🟡 MED | slicing | Reassembly trusts unauthenticated header fields (bind as AAD) | **fixed** |
| M-5 | 🟡 MED | mix | `getrandom` failure **panics** the mixer task; per-sample syscall | **fixed** |
| M-6 | 🟡 MED | discovery | Snapshot rollback/freeze: no lower bound on `created_at`; single-witness default | **fixed** |
| M-7 | 🟡 MED | discovery/forward | Unbounded 16 MiB frame + 32 MiB snapshot allocations; no connection cap | **fixed** |
| M-8 | 🟡 MED | routing/exit | `RouteRegistry` de-conflicts identical routes only, not shared exit nodes | **fixed** |
| L/INFO | ⚪ | various | zeroization gaps, unbounded replay cache, cover-packet distinguishability, `sample_relays` bias | M14 |

## The fixed issues (with tests)

### C-1 — payload tagging (CRITICAL, PoC-confirmed)
The Sphinx payload `δ` was a pure XOR-of-keystreams with **no integrity** at any
layer. A malicious relay could flip payload bits; the change propagated
undetected and the exit delivered attacker-chosen corruption. A first relay and a
colluding exit could imprint and read back a chosen bit-pattern — **defeating the
unlinkability** the mixnet exists to provide.

**Fix** (`sphinx.rs`): the payload now carries an **exit-verified integrity tag**
(`[len][mac][payload]`, MAC keyed from the exit's shared secret alone). Any
en-route tamper fails the tag and the exit rejects it instead of delivering
corruption. Test: `payload_tampering_is_detected_at_the_exit`.
*Residual (M14):* a tamper is still a droppable 1-bit signal; full
non-malleability needs a wide-block PRP (Lioness/AEZ) — tracked in M14.

### C-2 — identity-point forgery (CRITICAL, PoC-confirmed)
`sphinx_shared` computed `α · route_scalar` with no check that `α` is not the
Ristretto identity. For `α = identity`, the result is the identity for *every*
node — a public constant — so anyone could derive a victim's per-hop keys and
forge a packet it accepts, **with no key at all**.

**Fix** (`identity.rs`): `sphinx_shared` now rejects the identity point. Test:
`identity_alpha_is_rejected`.

### H-1 — replay-cache poisoning (HIGH, PoC-confirmed)
`process` inserted the replay tag **before** verifying the header MAC. A forged
packet (valid `α`, garbage `β`/`γ`) burned the tag, then failed the MAC — so the
*genuine* packet with the same `α` was later dropped as a "replay": a cheap
targeted-drop DoS.

**Fix** (`sphinx.rs`): authenticate the header MAC first; only record the replay
tag on an authenticated packet. Test:
`forged_packet_that_fails_mac_does_not_poison_replay_cache`.

### H-2 — replay defense absent across connections (HIGH)
`handle_onion` allocated a fresh `ReplayCache` per call, and the relay served one
call per connection — so the same onion replayed on a new connection was
re-forwarded (amplification + a correlation oracle).

**Fix** (`forward.rs` + `roles.rs`): added `handle_onion_shared`, and the relay
now owns **one** `ReplayCache` for its lifetime (shared across all connections;
the lock is held only for the synchronous `process`).

### H-6 — computational vs information-theoretic secrecy (HIGH, honesty)
`neo-slicing` is AEAD-encrypt-then-Reed-Solomon. Its "fewer than k shares reveal
nothing" claim is **computational** (rests entirely on the AEAD key), *not*
Shamir's information-theoretic secrecy — holding all n shares plus the key
recovers the plaintext. **Fix:** docs/tests corrected to say so plainly (see M14
for the optional Krawczyk SSMS upgrade if key-independent k-of-n secrecy is
wanted).

### M-1 — node-disjointness (MEDIUM)
Path disjointness was over Vec **indices**, not `NodeId`s, so a relay listed
twice (a Sybil advertising two addresses) could land on two "disjoint" paths and
collect ≥ 2 shares — breaking the invariant slicing depends on. **Fix**
(`routing`): `Router::new` deduplicates by `NodeId`. Test:
`duplicate_node_ids_are_deduplicated`.

## Review #2 — streaming, credits, committee, deeper Sphinx

A second adversarial pass over the code that landed after round 1. Severity
summary:

| # | Sev | Area | Finding | Status |
|---|-----|------|---------|--------|
| R2-1 | 🟠 HIGH | streaming | Return path had a per-hop XOR but **no end-to-end integrity** → a middle relay could maul the response the client accepts | **fixed** |
| R2-2 | 🔴 CRIT | credits | `RelayReceipt.bytes` an unbounded `u64` → one validly-signed receipt mints ~`u64::MAX / BYTES_PER_CREDIT` (~10¹³) credits | **fixed** |
| R2-3 | 🟠 HIGH | credits | **Base** (non-verifiable) OPRF → a malicious issuer can blind-evaluate earners under **different keys** and de-anonymize spends by key-tagging | **fixed** |
| R2-4 | 🟡 MED | sphinx | `ReplayCache` an unbounded `HashSet` → sustained traffic exhausts relay memory; `handle_onion` fresh-cache footgun | **fixed** |
| R2-5 | 🟡 MED | sphinx | Payload MAC covered `payload` but **not the length prefix** → parse/truncation oracle if the payload transform ever weakened | **fixed** |
| R2-6 | 🟡 MED | sphinx | Packet builder didn't reject an **identity-point hop key** → node-independent (public) shared secret | **fixed** |
| R2-7 | 🟡 MED | committee | `open()` aborted on the **first** bad share → one malicious member vetoes an otherwise-quorate reconstruction | **fixed** |
| R2-8 | ⚪ LOW | committee | `verify` accepted `member == 0` (the secret's own point); `lagrange_at_zero` could silently invert a zero denominator | **fixed** |

### R2-1 — streaming return-path malleability (HIGH)
The bidirectional stream layer layered the response with a per-hop XOR keystream
(so no relay reads it) but carried **no end-to-end integrity tag**. A middle relay
could flip bytes of the encrypted return payload; the flip survived the remaining
XOR layers and the client accepted mangled data — the return-path analogue of the
round-1 C-1 tagging break.

**Fix** (`stream.rs`): the exit prepends an **end-to-end return MAC** (keyed by
`"neo-stream-return-mac-v1"` over the exit's shared secret, 16 bytes) to the
response body; the client verifies it after peeling all XOR layers and rejects on
mismatch. A MAC (not Lioness) is used because responses are arbitrary-length and
a droppable-but-not-forgeable tag reaches integrity parity with the forward path.
Tests: `two_hop_round_trip_returns_the_response`, `a_mauled_response_is_rejected_by_the_client`.

### R2-2 — unbounded credit mint (CRITICAL)
`EarnLedger::record` accepted a receipt's `bytes` field verbatim, and `bytes` is a
`u64`. A single receipt — validly signed by a free client identity — could claim
`u64::MAX` bytes and mint ~10¹³ credits in one call, defeating the entire
proof-of-relay economics.

**Fix** (`earn.rs`): a receipt is capped at `MAX_RECEIPT_BYTES` (100 credits'
worth); a larger claim is refused. The module docs were corrected to state the
cap's true scope honestly — it bounds *per receipt*, not *per identity*, so a
colluding client+relay can still fabricate many capped receipts; earning is
*identified* so the issuer can rate-limit, and bilateral co-signed receipts are
the future refinement. Test: `a_receipt_over_the_cap_is_rejected`.

### R2-3 — non-verifiable OPRF de-anonymization (HIGH)
Credits used `voprf`'s **base** `OprfServer`/`OprfClient`. Base OPRF gives the
client no way to check the issuer used a consistent key, so a malicious issuer
could blind-evaluate different earners under different keys and later, at redeem
time, tell which key a spend verifies under — **partitioning the anonymity set**
and linking earn↔spend, the exact property the credits exist to prevent.

**Fix** (`lib.rs`): switched to the **verifiable** `VoprfServer`/`VoprfClient`. The
issuer publishes a committed public key and returns a **DLEQ proof** with every
blind evaluation; `finalize` verifies the proof against the pinned key and rejects
if the issuer strayed from it — forcing one key for everyone. Test:
`evaluation_under_the_wrong_key_is_caught_by_the_proof`.

### R2-4 — unbounded replay cache (MED)
`ReplayCache` was an ever-growing `HashSet<[u8;32]>`; a relay processing traffic
indefinitely exhausts memory. Separately, `handle_onion` allocated a fresh cache
per call — a footgun that silently disables replay defense.

**Fix** (`sphinx.rs` + `forward.rs`): the cache is now a **two-generation rotating**
structure bounded at `~2 × capacity` tags — it rejects every replay within its
horizon and rotates (dropping the oldest generation) instead of growing without
bound. The `handle_onion` fresh-cache helper was removed; callers use
`handle_onion_with_cache` (owned) or `handle_onion_shared` (`Mutex`). Tests:
`bounded_replay_cache_still_rejects_recent_replays`, `bounded_replay_cache_caps_memory_by_rotating`.

### R2-5 / R2-6 — Sphinx length authentication & identity hop key (MED)
The exit-verified payload MAC covered only the payload, not the 2-byte length
prefix; and `create_packet_keyed` didn't reject a hop advertising the Ristretto
identity as its routing key (which yields a public, node-independent shared
secret). **Fix** (`sphinx.rs`): the MAC now covers `len ‖ payload`, and the
builder rejects an identity hop key — mirroring the process-side identity-`α`
guard (round-1 C-2). Test: `identity_hop_key_is_rejected_at_build_time`.

### R2-7 / R2-8 — committee reconstruction robustness (MED/LOW)
`CommitteeSession::open` returned an error on the first share that failed Feldman
verification, so one malicious member could veto reconstruction even with a full
honest quorum present. And `KeyShare::verify` accepted `member == 0` (the secret's
own evaluation point), while `lagrange_at_zero` could silently invert a zero
denominator on a duplicate index. **Fix** (`vss.rs`): `open` now **skips and
attributes** bad shares and succeeds whenever ≥ threshold honest shares remain;
`verify` rejects index 0; `lagrange_at_zero` fails loudly on a zero denominator.
Tests: `one_bad_share_cannot_veto_a_reconstruction_with_a_quorum`,
`a_share_claiming_member_zero_never_verifies`.

### Confirmed sound (round 2, no fix needed)
- **ZK verifiable shuffle** (`neo-verify::shuffle`): the grand-product multiset
  equality with a Fiat–Shamir multiplication proof was probed for a forged product,
  a transferable proof across challenges, and a zero-factor bypass — all rejected.
  Five `poc_*` probes are retained as regression tests. The construction is sound;
  its honest limit (linear-size, not succinct) is documented, not a defect.

## What is genuinely solid (verified, not assumed)

The reviews actively tried to break these and could not:

- **Session AEAD has no nonce reuse.** Directional key separation is correct
  (each direction keys `seal`/`open` oppositely); the counter nonce is strictly
  monotonic and hard-errors on overflow rather than wrapping. This is the single
  most important record-layer property and it is right.
- **`verify_strict` everywhere** for Ed25519 (rejects malleable/small-order),
  and **Ristretto** for the group (no cofactor/small-subgroup pitfalls beyond the
  identity case now fixed).
- **Hybrid combiner is sound** (`HKDF(X25519 ‖ ML-KEM)` — secure if *either*
  holds; no downgrade path, both primitives always used).
- **KDF domain separation** is clean and distinct across every context
  (handshake, records, NodeId, Sphinx subkeys, records vs snapshots).
- **Discovery records are unforgeable**: full signature coverage + self-certifying
  id + `verify_strict`; every ingest path verifies; `seq`/`expires_at` bound
  replay. DHT inbound filtering (`FilterBoth`) + disjoint query paths.
- **Dial-back attestation genuinely proves key possession + address control.**
- **k-of-n witness counting is correct** (dedup, unknown-key skip,
  impossible-threshold reject, forged-record-is-fatal).
- **Parsers are bounds-checked and panic-free** across records, snapshots, and
  Sphinx packets, each with a fuzz-lite garbage test.
- **The exponential mix sampler is correct/unbiased**; OS-path Fisher–Yates is
  unbiased; `rand_below` modulo bias is ~1e-15 (negligible, honestly disclosed);
  the exit policy opt-in/port/rotation logic resisted every bypass attempt.

## How this was run

Independent reviewers read the target files in full and analyzed adversarially
against protocol-specific threat models (nonce reuse, transcript binding, KCI/UKS,
tagging, replay, point validation, resource exhaustion, signature coverage,
info-theoretic-vs-computational honesty, OPRF verifiability, VSS robustness). PoC
probes were written and run for the CRITICAL/HIGH crypto findings, then removed;
the ZK-shuffle probes were kept as regression tests. Round 1 covered the original
core; round 2 re-reviewed the streaming, credits, committee, and Sphinx code that
had grown since. Every finding from both rounds is fixed with a regression test
and the workspace is `fmt`/`clippy -D warnings`/`test` clean.
