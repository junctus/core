# Discovery & Sybil resistance

How a neo node finds the network with **zero manual configuration** — no peer
addresses typed by hand, no central server that traffic depends on — and how the
discovery layer resists Sybil, eclipse, and enumeration attacks.

> Status: implemented and demoed between live processes (seed + relay + client).
> Not audited. NAT traversal for relays behind home routers (AutoNAT / DCUtR /
> Circuit Relay v2) is still deferred — see [Limitations](#limitations).

## The problem

A fresh node has no reason to prefer any of 4 billion IP addresses. Every
decentralized network solves this the same way: a small, well-known set of entry
points ships in the binary. The honest questions are *what those entry points
can do to you* and *what they can learn about you*. neo's answers:

- **A seed can't forge the network.** Everything it hands out is signed; a
  malicious or hacked seed can omit relays, never invent or impersonate them.
- **Relays are enumerable; clients are not.** This is structural for any overlay
  (a relay a stranger can reach is a relay an adversary can reach), so we protect
  the party that actually needs it — the client — and make relay enumeration
  costly and unconfirmable over time.

## Two planes

### Relay plane — the DHT, hardened

Relays discover each other over a libp2p **Kademlia** DHT
(`core/crates/neo-discovery/src/libp2p_backend.rs`). Hardening applied:

- **Self-certifying, signed records.** A `PeerRecord` carries the node's full
  public-key set; its id *must* equal `blake3(keys)`, and the whole record is
  Ed25519-signed by the node. Verifiers recompute the id and check the signature
  before caching (`PeerRecord::verify`). Forgery and record-poisoning are
  impossible; an adversary can at most replay a node's *own* signed statements,
  bounded by `expires_at` and a monotonic `seq`.
- **Inbound store filtering.** Server nodes run Kademlia with
  `StoreInserts::FilterBoth`: every inbound `PUT` is parsed, checked against the
  key it claims, and verified before storage — no unverified value ever lands.
- **Disjoint query paths** (`disjoint_query_paths(true)`), so a single
  adversarial routing neighborhood can't eclipse a lookup (S/Kademlia).
- **Client mode for clients.** Consumers run `kad::Mode::Client`: they never
  announce, never listen, never answer queries. A client's participation is
  *not enumerable* via the DHT. (See `NodeRole`.)

### Client plane — a witnessed snapshot

Clients never do per-relay DHT lookups — a lookup for relay *R* reveals to
strangers that *you* are about to use *R*. Instead, **seeds act as witnesses**:
they observe and health-check the relay set and periodically emit one signed
**snapshot** of all relays. Clients fetch the whole snapshot, so *what they fetch
reveals nothing about the path they'll build* — the degenerate-but-perfect form
of PIR, and the same reason Tor clients download a full consensus.

`core/crates/neo-discovery/src/snapshot.rs`:

- A `Snapshot { created_at, expires_at, relays }` is signed by one or more
  witnesses into a `SignedSnapshot`.
- `verify(trusted, threshold, now)` requires **k-of-n distinct trusted
  witnesses**; unknown/duplicate/invalid signatures are ignored (tolerating a
  bad or rotated witness). A **forged relay record inside a snapshot is fatal** —
  honest witnesses never sign one — while merely *expired* records are filtered
  out, not rejected.

Because integrity rides the signatures, **distribution is untrusted**: a
snapshot can be served from a seed, a CDN, a mirror, or an on-disk cache without
that host being able to alter it. A recent snapshot can even be embedded in the
release binary, so a fresh install's first act is dialing relays directly rather
than phoning home.

### Snapshot bandwidth: compact records + delta sync

A witnessed snapshot has to scale to thousands of relays without becoming a
multi-megabyte download that every client repeats. Two mechanisms keep it small
(`snapshot.rs`, `neo-seed/src/service.rs`, `platforms/desktop/src/discovery.rs`):

- **Compact records.** A `PeerRecord`'s ML-KEM-768 key is 1184 bytes — ~85% of
  the record. Snapshots omit it and carry the *compact* encoding
  (`to_compact_bytes`). This is safe because the record `id` is `blake3(signing,
  kex, kem)` — it already commits to the key — and the record signature is defined
  over `id`, not the raw key, so **one signature covers both the full and compact
  forms** and a seed derives the compact snapshot from full registrations without
  the node re-signing. The dropped key isn't lost: the relay sends it in-band in
  handshake m2, and the client checks the re-derived `NodeId` against the `id` the
  witnesses vouched for (`result.peer_id == relay.id`). So a compact record's key
  commitment is verified **at dial time against live key material**, not at parse
  time — with no extra round trip. Compact records are snapshot-only; the DHT keeps
  the full self-certifying form (`verify_full`).

- **Delta sync.** A client holding a snapshot fetches only what changed:
  `GET /snapshot/diff?base=<fingerprint>` returns a `SnapshotDelta` (upserts +
  removals + the new signatures) instead of the whole set. The delta carries **no
  signature of its own** — the client applies it, reconstructs the exact new signed
  body in canonical id order, and verifies the *witness* signatures over the
  result. A mirror that smuggles in, drops, or reorders a relay produces a body no
  signature matches, so the client discards it and falls back to a full fetch.
  Every path ends at the same `verify_fresh` (signatures + anti-rollback high-water
  mark), so forcing the fallback can't downgrade integrity. The seed remembers a
  bounded window of recent relay sets; an unrecognized (too-old) base just gets a
  full snapshot.

Honest scope: compact records cut *snapshot / mirror / cache* bandwidth, not
handshake bytes (the key still crosses in m2). Deltas reduce steady-state transfer
for clients that refresh within the snapshot's validity window; a client offline
longer falls back to a full fetch. Neither changes the integrity model — a
snapshot, full or reconstructed, is trusted only when k-of-n witness signatures
verify over it.

## Reachability: dial-back attestation

Admission proves a record is internally valid; it does not prove the operator
controls the advertised address. Before a seed *attests* a relay, it **dials the
relay back and completes the neo handshake** (`neo-seed/src/health.rs`): the
connection only succeeds if the far side holds the record's signing key, which
simultaneously proves reachability and binds address ↔ identity. Relays that fail
repeatedly are struck and evicted. This stops a seed from amplifying bogus or
hijacked entries.

## Concentration defense: subnet caps, diverse selection, and registration PoW (M36)

Dial-back binds an identity to an address, but it does not cap how many relays one
operator runs — N processes on distinct ports of one box each pass their own
dial-back. M36 adds a *concentration* layer (a coarse anti-Sybil measure, **not**
full Sybil resistance):

- **Admission diversity.** The seed attests at most `MAX_ATTESTED_PER_SUBNET`
  relays per public subnet (IPv4 `/24`, IPv6 `/64`), and — when an `ip2asn` dataset
  is loaded (`neo seed --asn-db`) — at most `MAX_ATTESTED_PER_ASN` per autonomous
  system. Registration stays unbounded (memory-bounded by `MAX_ENTRIES`); only the
  *listed* set clients pick from is capped. The cap counts a relay against **only
  the address its dial-back verified**, never an unverified advertised one — so a
  record can't pad its `addrs` with a victim's `/24`/AS to consume that network's
  cap slots and evict honest relays there. Loopback / internal addresses are exempt.
- **Maturation (uptime).** Optionally (`neo seed --min-maturity`, off by default) a
  relay is not attested until it has stayed continuously healthy for a window. The
  seed measures this by dial-back, so it is *unforgeable* by the relay and raises the
  Sybil **time** cost. Off by default because the seed is in-memory (a restart blanks
  the snapshot for the window) — enable once several independent seeds exist.
- **Selection diversity.** Every client circuit builder front-loads
  subnet-distinct hops (`neo-core::net::prioritize_distinct_subnets`) so one
  operator can't own two hops of a path — including the k-of-n *share* router, where
  two "disjoint" paths through one `/24` would still leak two shares to one operator.
  It is **best-effort**: a young network with few subnets still builds full circuits.
- **Registration proof-of-work.** A relay attaches an `X-Neo-Pow` proof bound to
  its `NodeId` (`neo-core::pow`); the seed verifies it before admit. This taxes
  identity minting per-Sybil. CPU PoW is cheap at scale, so it's a speed bump on top
  of the real costs (a reachable host + a distinct subnet per identity), not a
  standalone defense.

The honest boundary: this raises the flood cost from "sign N records" to "control N
reachable hosts across ≳N/2 distinct `/24`s (and ≳N/8 distinct ASes) **and** pass N
dial-backs **and** spend N proofs **and**, under the maturation gate, keep them all
alive for the window". An adversary spanning a `/16`, many rented `/24`s/ASes, or an
IPv6 block still defeats the diversity caps. **Bandwidth**-weighted selection is
deliberately *not* used: the M17 proof-of-relay receipts are client-attested and
thus forgeable by a colluding client+relay, so weighting selection by them would be
security theater — proven bandwidth gates the unlinkable credit economy (M32), not
path selection. See `MILESTONES.md` M36.

## The seed (`discovery.junctus.org`)

`neo seed` runs a witness signer + health checker + a static HTTP service
(`GET /snapshot|/snapshot/diff|/healthz|/witness`, `POST /register`). It serves
**no user traffic**. Deploy bundle in `deploy/discovery/` (systemd unit + Caddy TLS +
installer). See that directory's README.

Trust is explicit and k-of-n: `discovery.junctus.org` is witness #1 and mirror
#1, not a trust root. Stand up more independent seeds and raise the client
threshold to dilute any single operator.

## Using it

```bash
# Zero-config client — discovers a relay and connects:
neo run

# Run a public relay that registers with the seeds:
neo run --relay --announce-addr <public-host:port>

# Inspect what the seeds are attesting:
neo snapshot
```

Mirrors and trusted witnesses come from (in order) CLI flags
(`--mirror`/`--witness`/`--threshold`), env (`NEO_MIRRORS`/`NEO_WITNESSES`), then
the baked-in constants in `platforms/desktop/src/defaults.rs`. A client refuses
to trust a snapshot from a witness it hasn't been told about — trust is never
implicit.

## DoH rendezvous bootstrap (M18)

Baking the mirror/witness list into the binary works but can't rotate without a
rebuild, and a fixed list is easy to block. A **bootstrap record**
(`neo-discovery::bootstrap`) decouples them: a long-lived **bootstrap key**
(the only thing baked in) signs a small record listing the *current* mirrors and
witnesses, published in DNS and fetched over **DNS-over-HTTPS** — so the lookup
is encrypted, hard to censor, and the list rotates by re-signing. The record is
rollback-protected (`created_at`) and verified against the trusted bootstrap
keys. Operators publish one with `neo bootstrap-record`; clients resolve it with
`neo bootstrap-resolve` (or automatically). Integrity still rides the witness
signatures on the snapshot, so the DoH transport and the DNS are untrusted.

## Threat model summary

| Attack | Defense |
|--------|---------|
| Forge/impersonate a relay | Self-certifying id + node signature; verify-on-receipt |
| Poison the DHT | Inbound `PUT` filtering; verify before store |
| Eclipse a lookup | Disjoint query paths; (future) routing-table diversity |
| Enumerate clients | Clients are DHT-invisible (client mode, no announce/listen) |
| Learn a client's chosen relay | Whole-snapshot fetch leaks no per-relay selection |
| Advertise a hijacked address | Dial-back handshake proves address ↔ key |
| Malicious/hacked seed | Witness signatures + k-of-n; can omit, never forge |
| Tamper with a snapshot diff | Client reconstructs + re-verifies witness signatures; any mismatch → discard + full refetch |
| Swap a compact record's key | `id` commits to the key; dial-time `peer_id == id` check rejects a mismatch |
| Replay an old record | `expires_at` + monotonic `seq` |
| Registration flooding | Per-IP + per-key cooldown; body-size limit; registration proof-of-work (M36) |
| Flood the attested set from one network | Per-subnet attestation cap (`/24`, `/64`); coarse — a multi-`/24` adversary still Sybils (M36) |
| Own both hops of a victim's circuit | Subnet-diverse selection at every picker; best-effort on small networks (M36) |

## Limitations

- **Relay enumeration is inherent.** Mitigations are cost/uncertainty
  (probe-resistant transports — deferred M6 REALITY; a future unlisted bridge
  tier via M10 credentials), not prevention.
- **NAT'd relays aren't reachable yet.** Only publicly-addressable relays work
  until AutoNAT / DCUtR / Circuit Relay v2 land (deferred from M4). This is the
  Tor relay shape and a fine early-network posture.
- **Witnesses are a small trusted set** (like Tor directory authorities).
  Dissolving that trust is exactly what frontier milestones M11 (VRF-verifiable
  path selection) and M13 (PIR discovery + proof-of-mixing) are for.
- **Sybil resistance is partial (M36).** Subnet caps + diverse selection + a
  registration PoW raise concentration cost but don't eliminate it — an adversary
  with many distinct `/24`s (or a `/16`, or an IPv6 block) still Sybils. Per-ASN
  caps and bandwidth-weighted selection are deferred.
