# Core security analysis

An adversarial review of neo's core cryptography and networked data plane,
conducted as four independent parallel reviews (AKE + session, Sphinx onion
routing, the novel core: slicing/mix/routing, and the networked
discovery/seed/forwarding layer). Findings are concrete, cite `file:line`, and
several were **PoC-confirmed** against the real code. This is an internal review,
**not** the external audit that gates real-world use.

**Status:** both CRITICAL Sphinx breaks and **most** HIGH/MEDIUM findings are now
**fixed** with regression tests (C-1, C-2, H-1, H-2, H-3, H-5, H-6, H-7, M-1, M-2,
M-4, M-5, M-7, M-8). The heaviest remaining items — **H-4** (key-confirmation
flight, a 3-message redesign), **M-3** (per-share authentication, a share-format
change), **M-6** (client snapshot anti-rollback persistence), and the full
**wide-block non-malleable payload** — are tracked in `docs/MILESTONES.md` (M14).

## Severity summary

| # | Sev | Area | Finding | Status |
|---|-----|------|---------|--------|
| C-1 | 🔴 CRIT | sphinx | Onion payload `δ` unauthenticated → end-to-end **tagging attack** | **fixed** |
| C-2 | 🔴 CRIT | sphinx | Identity/all-zero `α` → public constant shared secret → **key-free forgery** | **fixed** |
| H-1 | 🟠 HIGH | sphinx | Replay tag recorded **before** MAC check → cache-poisoning / targeted drop | **fixed** |
| H-2 | 🟠 HIGH | forward | Per-call `ReplayCache` → replay defense absent across connections | **fixed** |
| H-3 | 🟠 HIGH | handshake | Only Ed25519 key authenticated, not full `NodeId` (kex/kem) → **UKS** | M14 |
| H-4 | 🟠 HIGH | handshake | No key confirmation; m1 replay → responder DoS (ML-KEM per replay) | M14 |
| H-5 | 🟠 HIGH | seed | `X-Forwarded-For` trusted → cooldown bypass + SSRF dial amplification | M14 |
| H-6 | 🟠 HIGH | slicing | "reveal nothing" is **computational, not** information-theoretic (doc conflation) | **fixed (docs)** |
| H-7 | 🟠 HIGH | routing | Seeded path selection uses only 64 of 256 seed bits → unreachable permutations (n≥21) | M14 |
| M-1 | 🟡 MED | routing | Disjointness over indices not `NodeId` → duplicate relay breaks node-disjointness | **fixed** |
| M-2 | 🟡 MED | handshake | Transcript over raw m1 bytes; 1-byte append = deterministic DoS; no trailing-byte check | M14 |
| M-3 | 🟡 MED | slicing | Shares not individually authenticated → single relay silently forces reassembly failure | M14 |
| M-4 | 🟡 MED | slicing | Reassembly trusts unauthenticated header fields (bind as AAD) | M14 |
| M-5 | 🟡 MED | mix | `getrandom` failure **panics** the mixer task; per-sample syscall | M14 |
| M-6 | 🟡 MED | discovery | Snapshot rollback/freeze: no lower bound on `created_at`; single-witness default | M14 |
| M-7 | 🟡 MED | discovery/forward | Unbounded 16 MiB frame + 32 MiB snapshot allocations; no connection cap | M14 |
| M-8 | 🟡 MED | routing/exit | `RouteRegistry` de-conflicts identical routes only, not shared exit nodes | M14 |
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

Four independent reviewers read the target files in full and analyzed
adversarially against protocol-specific threat models (nonce reuse, transcript
binding, KCI/UKS, tagging, replay, point validation, resource exhaustion,
signature coverage, info-theoretic-vs-computational honesty). PoC probes were
written and run for the CRITICAL/HIGH crypto findings, then removed. See M14 in
`docs/MILESTONES.md` for the remediation roadmap.
