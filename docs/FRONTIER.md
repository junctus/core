# Frontier capabilities (M10–M13)

The four research-grade capabilities that move neo from *trusted* to *verifiable*
privacy. Each is implemented with a **real, tested cryptographic core** and an
**honestly-labeled deferral** for the parts that are genuinely large research
constructions. Nothing here is audited.

A capstone integration test — `core/crates/neo-node/tests/frontier.rs` — exercises
all four through their public APIs and composes them into one request flow.

## The composed flow

```
   client
     │  M10  earn a bandwidth credit by relaying, spend it (unlinkably) to pay
     ▼
   M13  discover a relay by NodeId via 2-server PIR — neither server learns which
     │
     ▼
   M11  client-commit + beacon-VRF ⇒ a path seed neither side can bias, verifiable
     │
     ▼
   M12  hand the clearnet request to a k-of-n committee; no minority can read it
     ▼
   exit
```

Each arrow is a real primitive; the composition is what the capstone test proves.

## M10 — anonymous bandwidth credits (`neo-credits`)

**Real:** a VOPRF (the Privacy Pass primitive, `voprf` over Ristretto255). A node
blinds a random serial; the issuer blind-evaluates it *without seeing it*; the
node finalizes an unlinkable token. Spending presents `(serial, token)`; the
issuer recomputes the OPRF and a spend set rejects double-spends. Because the
issuer only ever saw a **blinded** serial at issuance, it cannot correlate
issuance with spending — the credits are unlinkable. Earning a credit costs real
relayed bandwidth, so N Sybil identities cost N identities' worth of work.

**Deferred:** binding issuance to *cryptographically proven* relayed bytes
(right now "earned by relaying" is the intended policy, not enforced in-crate),
and the on-wire credit format.

## M11 — verifiable, unbiasable routing (`neo-verify`, `neo-routing`)

**Real:** a schnorrkel Ristretto **VRF** (`vrf`) gives a per-node output that's
unbiasable for a fixed input and publicly verifiable. `selection` closes the
two-party biasing gap with a **commit-then-VRF** construction:

1. the client publishes only `commitment = H(nonce)` — bound before it sees any
   VRF output, so it can't grind request ids;
2. the beacon computes a VRF over that commitment — a *function* of its input, so
   it has exactly one possible output and can't grind either;
3. the path seed is `H(domain ‖ commitment ‖ vrf_output)`, which
   `neo-routing::select_path_seeded` turns into a reproducible, verifiable path.

Anyone with the beacon's VRF public key verifies the whole thing.

**Deferred:** nothing structural for the two-party case; production would add a
multi-beacon/threshold beacon so no single beacon is even a liveness dependency.

## M12 — committee exit (`neo-mpc`, flagship)

**Real:** the clearnet request (`destination + payload`) is **threshold
secret-shared** with Shamir over GF(256) (`sharks`), one share per committee
member. Any `k-1` members — even fully colluding — learn *nothing* about the
destination or payload; this is Shamir's information-theoretic guarantee, not a
computational assumption. Any `k` reconstruct. A hash bound into the shared
secret makes a corrupted or swapped share detectable. `Committee` models
per-member custody, threshold reconstruction, and reports the honest overhead
(share expansion ≈ committee size).

**Deferred (the honest boundary):** full **MPC-TLS**, where the committee
computes the TLS session *itself* under multi-party computation so the plaintext
is never assembled at any single point — including the moment it's sent to the
real server (TLSNotary / `mpz` lineage). This crate is the trust-splitting core
that a future MPC reconstruct-and-send step slots into; today, reconstruction
does assemble the request in one place.

## M13 — verifiable privacy (`neo-verify`)

**Real:** two-server information-theoretic **PIR** (`pir`, the classic XOR
scheme) — a client fetches record `i` while neither server learns `i` (each
sees a uniformly-random query). `oblivious` lifts this from index to keyword:
records are placed by a public `bucket = H(salt ‖ key) mod B` with a
collision-free salt searched at build time, so a client fetches a relay **by
NodeId** without either server learning which relay. Requires the two servers
not to collude — the standard 2-server PIR assumption.

**Deferred:** a real **zero-knowledge verifiable shuffle** (Bayer–Groth-style
over Bulletproofs/arkworks) that proves a mix permuted its inputs *without
revealing the permutation*. `proof_of_mixing` currently implements the weaker
non-ZK **conservation check** (outputs are a permutation of inputs — nothing
dropped or injected), which is for audit/simulation, not live privacy.

## What "done" means here

These milestones are marked ✅ in `docs/MILESTONES.md` in the sense the rest of
the roadmap uses: the **core primitive is real, tested, and demonstrable**, with
deferrals named explicitly. They are **not** production-hardened or audited, and
the deferred pieces (MPC-TLS, ZK shuffle, enforced earn-accounting) are the
genuine multi-quarter research remaining. The audit gate still stands before any
of this protects real users.
