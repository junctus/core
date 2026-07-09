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

## Reachability: dial-back attestation

Admission proves a record is internally valid; it does not prove the operator
controls the advertised address. Before a seed *attests* a relay, it **dials the
relay back and completes the neo handshake** (`neo-seed/src/health.rs`): the
connection only succeeds if the far side holds the record's signing key, which
simultaneously proves reachability and binds address ↔ identity. Relays that fail
repeatedly are struck and evicted. This stops a seed from amplifying bogus or
hijacked entries.

## The seed (`discovery.junctus.org`)

`neo seed` runs a witness signer + health checker + a static HTTP service
(`GET /snapshot|/healthz|/witness`, `POST /register`). It serves **no user
traffic**. Deploy bundle in `deploy/discovery/` (systemd unit + Caddy TLS +
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
| Replay an old record | `expires_at` + monotonic `seq` |
| Registration flooding | Per-IP cooldown; body-size limit |

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
