# neo — Internal Security Review, Round 3

**Status:** Internal review. **This is NOT the external audit.** neo remains
explicitly unaudited. This round targets the newest, never-before-reviewed code:
the two-party MPC-TLS stack (`neo-mpc/src/mpc_tls/*`), the REALITY
probe-resistant transport (`neo-crypto/src/reality.rs`), persistent circuit
tunnels (`neo-node/src/circuit.rs`), the verifiable-VOPRF credits
(`neo-credits`), and the surrounding data plane, discovery, seed, mix, and
transport-camouflage layers. Rounds 1–2 (see `SECURITY_ANALYSIS.md`) are already
remediated; findings here are new.

Every point below was traced to source and cites `file:line`. Findings that were
originally proposed at a higher severity but did **not** survive adversarial
re-verification have been calibrated down and the reasoning recorded, in keeping
with the project's honesty mandate: a plausible-but-wrong finding is treated as a
defect of the review, not a win.

Two findings are **CRITICAL and demand action before any further deployment of
the affected code paths**: the REALITY low-order-point authenticator forgery
(R3-01) and the credit-issuance/earning decoupling (R3-02). Note that several
HIGH circuit findings (R3-06, R3-07, R3-19, R3-20) are *latent*: the vulnerable
`serve_circuit`/`exit_splice` API is real, public, documented M21 code but is not
yet wired into any running binary (the desktop relay uses the one-shot
`handle_onion_shared` path). They must be fixed **before** that API is wired into
a node role.

---

## 0. Resolution status

**All findings in this review are now remediated** on branch `security-review-3-fixes` (each with a regression test where applicable). CRITICAL/HIGH/MEDIUM findings were fixed in code; LOW/INFO findings were fixed in code or resolved by honest doc corrections (the "overclaims" table wording was applied). The workspace is `fmt`/`clippy -D warnings`/`test` clean (229 tests, 0 failures) and both end-to-end scripts pass. This remains an internal review, not the external audit.

## 1. Severity Summary

| ID | Sev | Area | Finding | Status |
|----|-----|------|---------|--------|
| R3-01 | CRITICAL | REALITY transport | Low-order/identity x25519 eph point → authenticator forgery without the capability | FIXED |
| R3-02 | CRITICAL | Credits / earn | `issue()` mints to anyone; issuance fully decoupled from earning | FIXED |
| R3-03 | HIGH | REALITY transport | Fixed 100-byte plaintext first flight — static passive fingerprint | FIXED |
| R3-04 | HIGH | REALITY transport | No replay cache — captured hello re-authenticates for the epoch window | FIXED |
| R3-05 | HIGH | Credits / earn | `spent`/`claimed` sets grow unbounded; no epoch/rotation/persistence | FIXED |
| R3-06 | HIGH | Circuit data plane | Forward cells have no replay/reorder/drop protection at the exit (latent) | FIXED |
| R3-07 | HIGH | Circuit data plane | Return cells have no replay/reorder/drop protection at the client (latent) | FIXED |
| R3-08 | HIGH | Seed server | Dial-back is unfiltered SSRF (loopback/RFC1918/metadata) | FIXED |
| R3-09 | HIGH | Seed server | No registry cap + serial dial loop → health-loop starvation / attestation censorship | FIXED |
| R3-10 | HIGH | Mix / cover | Cover packets are length-distinguishable from real packets on the wire | FIXED |
| R3-11 | HIGH | Circuit data plane | Exit TCP splice is an open proxy — SSRF, no exit policy (latent) | FIXED |
| R3-12 | MEDIUM | 2PC session | Dual-execution never wired into the session; gadgets are pure semi-honest | FIXED |
| R3-13 | MEDIUM | 2PC session | `seal_record_shared` emits a non-AEAD tag but is doc'd as stock ChaCha20-Poly1305 | FIXED |
| R3-14 | MEDIUM | Committee VSS | `encrypt()` accepts an identity joint key → fixed public keystream | FIXED |
| R3-15 | MEDIUM | Committee VSS | Threshold hashed-ElGamal ciphertext is unauthenticated / malleable (no INT-CTXT) | FIXED |
| R3-16 | MEDIUM | Credits / earn | Doc claims issuer can rate-limit the earning relay, but it never sees the identity | FIXED |
| R3-17 | MEDIUM | Credits / earn | Receipts have no timestamp/expiry — colluding client can pre-sign unbounded receipts | FIXED |
| R3-18 | MEDIUM | Verifiable privacy | Oblivious directory: zero-length records cause silent, undetected collisions | FIXED |
| R3-19 | HIGH | REALITY transport | classify() accepts low-order x25519 points (duplicate lens on R3-01, confirmed by PoC) | FIXED |
| R3-20 | MEDIUM | Verifiable privacy | Beacon can bias path selection by abort-grinding; doc claims neither party can bias | FIXED |
| R3-21 | MEDIUM | Transport camouflage | DTLS epoch is always a prefix of the sequence field (deterministic tell) | FIXED |
| R3-22 | MEDIUM | Transport camouflage | Cleartext inner length field + TCP length prefix that real QUIC/DTLS never carry | FIXED |
| R3-23 | MEDIUM | Seed server | Per-IP register cooldown is the only limiter; bypassable with IP diversity | FIXED |
| R3-24 | MEDIUM | Supply chain | `sharks 0.5.0` (RUSTSEC-2024-0398) biased Shamir coefficients (test-only path) | FIXED |
| R3-25 | MEDIUM | Supply chain | Doc claims Shamir information-theoretic secrecy that `sharks 0.5.0` does not deliver | FIXED |
| R3-26 | LOW | AKE / record layer | "Stateless" cookie is neither stateless nor source-bound; over TCP only gates ML-KEM | FIXED |
| R3-27 | LOW | AKE / record layer | Handshake intermediate secrets (DH out, ML-KEM ss, IKM, k_confirm) not zeroized | FIXED |
| R3-28 | LOW | Sphinx | Replay-cache horizon is count-driven, not time-driven; no routing-key rotation | FIXED |
| R3-29 | LOW | Sphinx | Payload delta unauthenticated at non-exit hops → deliver/reject confirmation oracle | FIXED |
| R3-30 | LOW | 2PC OT/IKNP | IKNP extension has no receiver-consistency check (selective-failure leak; gated out) | FIXED |
| R3-31 | LOW | 2PC docs | `mpc_tls` crate doc omits the semi-honest-only qualifier where OT/IKNP are introduced | FIXED |
| R3-32 | LOW | 2PC dualex | `check_pass` is not a secure equality test; ≤1-bit bound is the protocol's, not the code's | FIXED |
| R3-33 | LOW | 2PC dualex docs | `dualex` ≤1-bit bound assumes a committed/simultaneous equality channel not provided | FIXED |
| R3-34 | LOW | 2PC Poly1305 | Doc claims multi-block Horner Poly1305 that the circuit does not implement | FIXED |
| R3-35 | LOW | 2PC Poly1305 | `tag_circuit` hard-codes the high bit at position 128 (partial final block mis-padded) | FIXED |
| R3-36 | LOW | 2PC test coverage | Circuit KATs are single-sample per gadget; no boundary/adversarial vectors | FIXED |
| R3-37 | LOW | Committee VSS docs | Docs present threshold decryption as "verifiable" without disclosing ciphertext malleability | FIXED |
| R3-38 | LOW | Committee VSS | `combine()` takes `threshold` decoupled from the committed degree → silent garbage | FIXED |
| R3-39 | LOW | Discovery | `SignedSnapshot::verify` has no anti-rollback/freshness param (no consumer yet) | FIXED |
| R3-40 | LOW | Discovery docs | Doc-comments claim a snapshot anti-rollback high-water mark that isn't implemented | FIXED |
| R3-41 | LOW | Discovery | libp2p `sample_relays` is deterministic (`HashMap take(n)`), unlike shuffled `LocalRegistry` | FIXED |
| R3-42 | LOW | Verifiable privacy | `selection_index` has modulo bias + uses 64/256 bits; doc claims "verifiably fair" (unused) | FIXED |
| R3-43 | LOW | Transport camouflage | `dial_reality` doc claims flight "indistinguishable from random" despite structured prefix | FIXED |
| R3-44 | LOW | Circuit docs | Doc claims cell integrity is "the same guarantee" as Sphinx replay-once (it isn't) | FIXED |
| R3-45 | LOW | Mix / cover | Cover co-terminous with the session — coarse activity envelope exposed | FIXED |
| R3-46 | LOW | Mix / RNG | OS-RNG-failure fallback yields a deterministic delay (~0.693·mean), no operator signal | FIXED |
| R3-47 | LOW | Slicing docs | Doc claims corrupt shards "attributable by index"; API never surfaces the index | FIXED |
| R3-48 | MEDIUM | Node data plane | No handshake/read timeouts or connection caps — slowloris head-of-line on accept loop | FIXED |
| R3-49 | LOW | Transport camouflage | `recv`/`read_blob` allocate up to 16 MiB from an unauthenticated 4-byte length | FIXED |
| R3-50 | LOW | Supply chain | No cargo-audit/deny advisory gate in CI; permissive specs rely on the lockfile | FIXED |
| R3-51 | INFO | AKE / record layer | m1 carries no anti-replay nonce → bounded per-connection ML-KEM+Ed25519 CPU-DoS | FIXED |
| R3-52 | INFO | Sphinx | 128-bit MAC/payload tags with an unlimited online oracle (2⁻¹²⁸ per try — safe) | FIXED |
| R3-53 | INFO | 2PC OT | Chou-Orlandi sender never validates receiver point R (harmless under Ristretto) | FIXED |
| R3-54 | INFO | 2PC session | `shared_ecdhe` is a self-play simulation, not a live two-party handshake | FIXED |
| R3-55 | INFO | Credits | `redeem()` uses non-verifiable `evaluate()` — correct for issuer==verifier | FIXED |
| R3-56 | INFO | Discovery | Bootstrap `not_before` anti-rollback is correct but has no consumer yet | FIXED |
| R3-57 | INFO | Core identity | NodeId self-cert does not cover the Sphinx routing key (bound by signature instead) | FIXED |

**Counts:** 2 CRITICAL · 9 HIGH · 12 MEDIUM · 27 LOW · 7 INFO.

---

## 2. CRITICAL

### R3-01 / R3-19 — REALITY: low-order/identity ephemeral point forges an authenticator without the capability
**`core/crates/neo-crypto/src/reality.rs:89-101` (DH at :91).**

`classify()` computes
`shared = self.0.diffie_hellman(&PublicKey::from(eph)).to_bytes()` on the
attacker-controlled `eph` with **no** `was_contributory()` / low-order check.
Feeding `eph = [0u8;32]` (the identity point) makes the server's `shared`
all-zeros **independent of the server secret**; `eph[0]=1` and the other
small-order points do the same. Because `auth_tag` (`:143`) and `session_seed`
(`:152`) are public `blake3::derive_key` functions over `(shared, epoch, eph)`
and `(shared, eph)`, an attacker with **no capability** precomputes
`got = auth_tag([0;32], epoch, [0;32])`, sends `eph‖got‖pad`, and `ct_eq` at
`:94` matches — `classify` returns `Verdict::Authenticated` with a fully
attacker-derivable `session_seed`.

This was reproduced by a PoC compiled against the exact code (x25519-dalek 2.0.1
/ curve25519-dalek 4.1.3 per `Cargo.lock`): the server printed an all-zero
shared for the identity point and the forged flight reached the Authenticated
branch. It falsifies the module's central claim (`reality.rs:6-8,13-17,21`) that
"a prober cannot reach the authenticated branch" and "cannot forge an
authenticator". The existing test `a_prober_without_the_capability_only_ever_sees_decoy`
(`:183`) gives false assurance because no test drives a low-order point.

**Impact.** Any censor/probe defeats the entire REALITY authentication with a
16-byte-of-effort forgery, deriving the session seed with zero secret knowledge.

**Fix.** After DH, reject non-contributory results and take the **silent Decoy**
path (never an error, to preserve indistinguishability):
```rust
let ss = self.0.diffie_hellman(&PublicKey::from(eph));
if !ss.was_contributory() { return Verdict::Decoy; }
let shared = ss.to_bytes();
```
Also validate the capability key isn't low-order on the client. Add a regression
test that sends the identity/low-order `eph` and asserts `Decoy`. Do **not**
re-claim indistinguishability in the docstring until this lands.

### R3-02 — Credit issuance is fully decoupled from earning: `issue()` mints to anyone
**`core/crates/neo-credits/src/lib.rs:63-71`.**

`struct Issuer` holds only `server` and `spent` (`:37-40`) — no `EarnLedger` and
no `earn::` reference in `lib.rs`. `issue(&self, blinded: &BlindCredit)` (`:63`)
deserializes the blinded element and unconditionally returns a blind evaluation +
DLEQ proof; it takes no `NodeId`, no `RelayReceipt`, no earned count, and
consults no ledger. The only callers are `neo-node/tests/frontier.rs:40,113`,
which call `issue()` with zero earn gating. The one test that appears to gate
issuance (`earn.rs:177`) merely `assert!(earned >= 1)` in test code before
calling the ungated `issue()` — a test assertion, not an API invariant.

**Impact.** Any party reaching the issuer loops `request() → issue() →
finalize()` and mints unlimited spendable credits at **zero bandwidth**. The
entire `earn.rs` machinery (receipts, byte accounting, thresholds) is enforced
nowhere in the real issuance path. This voids the anti-Sybil / anti-free-rider
premise the crate doc (`lib.rs:19-21`) advertises.

**Fix.** Wire `issue()` to require and atomically consume proven earnings — pass
the earning relay's `NodeId` plus a fresh earn-proof, look it up in an
issuer-held `EarnLedger`, and decrement one credit under a lock before
blind-evaluating. Issuance is *identified* while the blinded serial stays
*blinded*, so unlinkability is preserved. Until wired, correct the crate doc to
stop claiming earning gates issuance (see R3-16).

---

## 3. HIGH

### R3-03 — REALITY first flight is a fixed 100-byte plaintext pattern
**`core/crates/neo-crypto/src/reality.rs:130`; framing `neo-transport/src/lib.rs:242,325-328`.**

`MIN_PAD` is a constant 32 (`:43`); `client_hello` always allocates
`vec![0u8; MIN_PAD]` (`:130`) — the *content* is random but the *length* is
fixed. `HELLO_PREFIX = EPH_LEN + TAG_LEN = 64`, plus 32 pad = a **96-byte hello,
invariant on every connection**. `dial_reality` writes it via `write_blob` with a
cleartext 4-byte big-endian length prefix; for len 96 that prefix is exactly
`00 00 00 60`. So every neo first flight is invariably **100 wire bytes beginning
`00 00 00 60`** followed by 96 high-entropy bytes — a passive DPI keys on this
with ~zero false positives, contradicting `reality.rs:42` ("realistic
ClientHello size class") and the indistinguishability goal.

**Fix.** Randomize the pad length (sample `MIN_PAD..MIN_PAD+N`) so flight length
varies; more importantly, embed the flight inside a real TLS ClientHello (first
bytes `16 03 01 …`) rather than a bespoke u32 length prefix. Until then, do not
claim wire indistinguishability (see R3-43).

### R3-04 — REALITY has no anti-replay state: captured hello re-authenticates for the epoch window
**`core/crates/neo-crypto/src/reality.rs:85-101` (loop at :93).**

`classify()` derives its verdict purely from `hello` bytes + `epoch`, keeps no
cache of seen ephemerals/tags, and loops over `[epoch, epoch.wrapping_sub(1)]`
(`:93`). The authenticator binds only `(shared, epoch, eph)` and `session_seed`
only `(shared, eph)` — nothing single-use. The first flight is sent as plaintext
(`neo-transport/src/lib.rs:288-289,325-329`), so an on-path observer captures the
96-byte flight and byte-for-byte replays it within the current/previous epoch,
gets `Authenticated` again, and reproduces the identical deterministic
`session_seed`. The crate's own test `a_captured_hello_expires_after_the_epoch_window`
(`:213`) proves the two-epoch replay window. Epoch duration is caller-supplied
with no wall-clock derivation wired anywhere yet, so the real-world window is
currently undefined.

**Impact.** A positive distinguisher for a suspected bridge plus session
duplication. **This finding is largely subsumed once R3-01 is fixed only if** the
fix also adds replay defense — it does not by itself, so treat as independent.

**Fix.** Add a bounded per-epoch replay cache of accepted ephemerals/tags and
`Decoy` on repeats; bind server-chosen randomness/timestamp into the transcript
and derive `session_seed` from server-side randomness too. Document a concrete
epoch granularity.

### R3-05 — Double-spend `spent` set and replay `claimed` set grow unbounded; no rotation/persistence
**`core/crates/neo-credits/src/lib.rs:39,83`; `earn.rs:94,115`.**

`Issuer.spent: HashSet<Vec<u8>>` (`:39`) inserts every 32-byte serial on redeem
(`:83`) and is never pruned — no eviction/epoch/expiry, and `Credit` carries no
timestamp to allow one. `EarnLedger.claimed` (`earn.rs:94`) grows one triple per
receipt forever (`earn.rs:115`). The only `Issuer` constructor is `new()` with a
fresh random key (`:44`): there is **no rotation API and no epoch tag**, so
rotating the key strands all outstanding credits (they verify under the old key),
while a naive redeploy that regenerates the key **wipes the in-memory `spent`
set, re-enabling double-spend of every historical serial** (`spent` is not
persisted).

**Impact.** Unbounded memory growth (a real DoS, trivial to drive because R3-02
makes minting free) plus a correctness/operational defect: no safe key-rotation
story and a redeploy resets the double-spend log.

**Fix.** Tag each credit/receipt with an issuer-key epoch id; keep per-epoch
spent/claimed sets that drop when the epoch retires; add an explicit
key-rotation API with a grace window for outstanding credits; **persist the
`spent` set across restarts**.

### R3-06 — Circuit forward cells have no replay/reorder/drop protection at the exit (latent)
**`core/crates/neo-node/src/circuit.rs:328-349` (send path `:110-128`).**

The exit's `to_target` loop (`:337-346`) reads `seq` from the cell, uses it only
to key `xor_cell`/`cell_mac`, and **never compares it to an expected/last-seen
value** — there is no `next_seq` state in `exit_splice`. The per-link `Opener`
counter (`session.rs:65-83`, rejecting `counter <= last`) does not help: a
malicious middle relay owns its Sealer toward the exit and re-seals a captured
inner cell verbatim under a fresh, strictly-increasing **link** counter. The exit
accepts it (new link counter), decrypts a bit-identical `[seq][mac][payload]`,
the e2e MAC over `(seq‖payload)` still passes, and `write_all` pushes the same
payload to the target a second time. Reorder/drop are equally undetected because
each cell is authenticated in isolation.

**Latency of exploit.** `serve_circuit`/`exit_splice` is invoked only from its own
unit test (`circuit.rs:411`); the production desktop relay
(`platforms/desktop/src/roles.rs:124-152`) runs `handle_onion_shared`, not
`serve_circuit`. So this is a real property of shipped, public, documented M21
library code but not reachable through the current binary — a **latent HIGH**.
Must be fixed before `serve_circuit` is wired into any node role.

**Fix.** Track `next_expected_seq` per direction in `exit_splice` and reject any
cell whose `seq != expected` (or `<= last` if gaps are allowed); do not rely on
the per-link `Session` counter. Optionally bind direction+seq into the transcript.
Until fixed, the module doc must state cells are not replay/reorder/drop
protected end to end (see R3-44).

### R3-07 — Circuit return cells have no replay/reorder/drop protection at the client (latent)
**`core/crates/neo-node/src/circuit.rs:134-151` (`CircuitStream::recv`); exit emits at `:352-375`.**

Symmetric to R3-06. `CircuitStream::recv` (`:140-149`) reads `seq`, peels return
layers keyed by `seq`, verifies the e2e return MAC over `(seq‖payload)`, and
returns payload — with **no monotonicity or dedup** (the struct at `:104-108`
holds only `r`/`opener`/`secrets`, no seq state). A malicious middle relay
re-seals a captured return cell under a new link counter toward the client; the
client's `Opener` accepts the fresh link counter, the inner return MAC still
verifies, and the duplicate/reordered payload is delivered to the SOCKS/VPN
inbound path. Same latency caveat as R3-06 (test-only path today).

**Fix.** Add an expected-return-seq field to `CircuitStream` and reject
out-of-order/duplicate seq, mirroring the exit-side fix.

### R3-08 — Seed dial-back is unfiltered SSRF (loopback / RFC1918 / cloud metadata)
**`core/crates/neo-seed/src/health.rs:26-38` → `core/crates/neo-node/src/run.rs:46-48`.**

`post_register` (`service.rs:184`) parses an attacker-controlled `PeerRecord`;
`admit` (`registry.rs:60-93`) calls only `record.verify()`, which checks
structural limits, self-certification, expiry, and the Ed25519 signature — and
the attacker signs with **their own** key, so the record is trivially valid.
There is **no address validation anywhere**: `check_limits` only bounds
`addrs.len() <= 8` and `addr.len() <= 256`; addrs are free-form UTF-8. On the
health timer (`service.rs:239-247`) the seed calls `dial_back` → `handshake_matches`
→ `neo_node::run::connect` → `TcpStream::connect(addr)` (`run.rs:46`), then
**writes the first handshake frame (`init1`) before any key check** (`run.rs:47-48`).
The peer-key equality check (`health.rs:36`) only gates *attestation*, not the
connect+write.

**Impact (calibrated).** The seed is a confused deputy originating TCP
connections and sending the neo handshake init frame to `127.0.0.1:<port>`,
`10/172.16/192.168` ranges, `169.254.169.254`, or arbitrary third-party
`host:port` (hostnames resolved via DNS). Two nuances bound impact but do **not**
downgrade it: the written bytes are a fixed neo frame (cannot smuggle a crafted
HTTP GET into the metadata endpoint, so *reading* metadata is overstated), and
the success oracle is weak (attestation needs a neo key match internal services
never produce). The confirmed impact — **connection origination from the seed's
network position**: internal/RFC1918/loopback reachability, dial amplification,
and connection-flooding an arbitrary victim — justifies HIGH.

**Fix.** Before dialing, parse each addr to a `SocketAddr` and reject
`is_loopback`/`is_private`/`is_link_local`/`is_unspecified`/`is_multicast`/
documentation ranges and `169.254.169.254`; prefer requiring IP:port literals
(reject hostnames) to kill DNS-rebinding and pin the resolved IP. Apply the same
filter in `admit()` so bogus-target records are never stored; consider
restricting the destination port to the expected relay range.

### R3-09 — No registry cap + serial dial loop → health-loop starvation / attestation censorship
**`core/crates/neo-seed/src/registry.rs:60-93,98-105`; `service.rs:239-247`.**

`admit` (`registry.rs:60-93`) inserts into a `HashMap` with **no capacity check**
(no `MAX_RELAYS` anywhere). `due_for_check` (`:98-105`) returns **every**
non-expired record each sweep, so serial cost accumulates across the whole
registry. The health loop (`service.rs:239-247`) is strictly serial —
`for record in due { dial_back(...).await }` — and `dial_back` tries up to 8
addresses sequentially, each at `DIAL_TIMEOUT = 5s` (`health.rs:18,35`), i.e.
~40s wall time per record whose addresses accept-then-hang. No
`FuturesUnordered`/semaphore, no `MissedTickBehavior` (defaults to Burst).
Registration is gated only by a per-IP 30s cooldown (R3-23), trivially
parallelised across an IPv6 pool, each record naming up to 8 blackhole targets.

**Impact.** A few dozen blackhole records make every sweep overrun the 60s
`health_interval`, so legitimate relays' health checks are delayed or never run;
only healthy, unexpired relays are attestable (`registry.rs:132-139`) and thus
present in the witness-signed `/snapshot` — a **cheap censorship primitive
against the whole overlay**, plus sustained outbound dial amplification.
`MAX_STRIKES = 3` eviction only forces re-registration ~every 90s, which the
cooldown permits.

**Fix.** Cap total registry entries (reject or LRU-evict beyond it). Run
dial-backs concurrently with a bounded `FuturesUnordered`/semaphore instead of a
serial `await` loop; bound per-sweep work with a time budget or max-records-
per-sweep. Set `MissedTickBehavior::Skip`. Add a global outbound-dial rate limit
independent of the per-IP cooldown.

### R3-10 — Cover packets are length-distinguishable from real packets on the wire
**`core/crates/neo-node/src/tunnel.rs:77-84` with `neo-mix/src/lib.rs:23,113` and `neo-crypto/src/session.rs:28-44`.**

Outbound at `tunnel.rs:77-79` tags a real packet `TAG_REAL` then appends the raw
packet: tagged length = `1 + packet.len()`, varying with IP packet size. Cover at
`tunnel.rs:81-83` does `tagged.resize(1 + size, 0)` with `size = COVER_SIZE = 1024`
(`neo-mix:23,113`) — a **constant 1025 bytes**. Real packets are never padded to a
uniform cell. `sealer.seal` (`session.rs:28-44`) builds `8-byte counter ‖
ChaCha20-Poly1305 ciphertext (len + 16)` — strictly length-preserving. So every
cover frame is a constant 1049 bytes while real frames are `25 + packet.len()`.

**Impact.** A global passive observer (neo-mix's explicit threat model,
`neo-mix:3`) trivially partitions cover from real by ciphertext length and
recovers the real flow's packet-size distribution. The timing-mixing does nothing
against this size channel. This collapses the size-analysis component of the
headline cover-traffic defense, contradicting `neo-mix:8-9` ("hides the real
traffic rate and pattern") and `tunnel.rs:5`.

**Fix.** Pad all real frames to a fixed cell size (≥ `COVER_SIZE`) before
sealing so real and cover frames are byte-identical on the wire; carry the true
payload length inside the sealed plaintext and trim on open; segment or reject
oversized packets. Correct `neo-mix:8-9`/`tunnel.rs:5` to state that size
indistinguishability requires uniform cell sizing (currently unimplemented).

### R3-11 — Exit TCP splice is an open proxy (SSRF, no exit policy) (latent)
**`core/crates/neo-node/src/circuit.rs:320` (`TcpStream::connect(target)`); target from `:237-240`.**

`exit_splice` calls `TcpStream::connect(target)` at `:320` with `target =
String::from_utf8` of the Sphinx exit payload (`:237-239`), with **no allowlist,
no loopback/RFC1918/link-local/metadata check, and no port policy**. A
`neo-routing` `ExitPolicy` exists (`neo-routing/src/exit.rs:36-68`) but (a)
`circuit.rs` never imports or calls it, and (b) it only filters *ports*, not IP
classes — so it would not stop metadata/internal SSRF anyway. `target =
127.0.0.1:port`, cloud metadata, or internal hosts are all dialed and spliced.

**Latency.** As with R3-06/07, `serve_circuit` is referenced only from its own
test (`circuit.rs:411`); the desktop relay runs `handle_onion_shared`. Genuine,
exploitable open-proxy property of shipped M21 code, not reachable via the
current binary — **latent HIGH**. The finding's impact applies the moment this
API is wired into a relay.

**Fix.** Before connect, resolve `target` and **default-deny**: reject loopback,
link-local (`169.254.0.0/16`, `fe80::/10`), RFC1918/ULA/metadata, and
non-allowlisted ports; require operator opt-in; add a connect timeout. Extend
`neo-routing::ExitPolicy` to cover destination IP classes and call it from
`exit_splice`. Track that this must land before `serve_circuit` is wired into any
node role.

---

## 4. MEDIUM

### R3-12 — Dual-execution is never wired into the session; gadgets use the pure semi-honest executor
**`core/crates/neo-mpc/src/mpc_tls/session.rs:121`; `poly1305.rs:207`; `sha256.rs:313`; only non-def `dual_execute` call is `dualex.rs:153` inside `#[cfg(test)]`.**

The only non-definition call to `dual_execute` is `dualex.rs:153`, inside `mod
tests` (`#[cfg(test)]` opens at `:131`). Every production gadget routes through
`garble::eval_2pc`: `session.rs:121` (`share_keystream`, transitively
`seal_record_shared`), `poly1305.rs:207` (`tag_shared`), `sha256.rs:313`
(`digest_shared`). `eval_2pc` (`garble.rs:213-237`) is the raw semi-honest
executor — garble once, evaluate once, decode; no second execution, no equality
check. A semi-honest-model garbler in the session path can drive any output label
and the evaluator accepts with zero detection.

**Impact / calibration.** Held at MEDIUM, not higher: the stack is explicitly
in-process, semi-honest-modelled, with no live network — the "inject/leak"
property is the generic property of unauthenticated GC the crate already declares
out of scope. The real defect is a **docs-honesty gap**: `mpc_tls.rs:27-28` lists
dualex as shipped component #5 and `:36-38` says "dual-execution here catches a
cheating garbler", which a reader takes to mean the session is protected, when
dualex is standalone/test-only.

**Fix.** State plainly in `mpc_tls.rs` and `session.rs` that the shipped session
gadgets are semi-honest only and dual-execution is a standalone demonstration not
invoked by the session path. To make the guarantee real, route session circuits
through `dual_execute` **and** replace `check_pass` with a genuine secure-equality
protocol (R3-32).

### R3-13 — `seal_record_shared` emits a non-AEAD tag but is doc'd as stock ChaCha20-Poly1305
**`core/crates/neo-mpc/src/mpc_tls/session.rs:148-149,173,19`.**

`session.rs:173` computes the tag as `poly1305::tag_shared(poly_a, poly_b,
ciphertext, [0u8;16])` — the 4th arg is `block_b` (an XOR-share of the message),
**not AAD**, and it is zero, so the MAC input is exactly **one** 16-byte Poly1305
block over the raw ciphertext. RFC 8439 §2.8 requires `pad16(AAD) ‖ pad16(ct) ‖
le64(len AAD) ‖ le64(len ct)`. Here AAD is absent and, critically, the trailing
`le64‖le64` length block (a full second Poly1305 block for a 16-byte ct with
empty AAD) is **missing**. A stock RFC 8439 verifier MACs 2 blocks and **rejects**
this 1-block tag; the record length is unauthenticated/malleable. The
`chacha20poly1305` crate is already a `neo-mpc` dependency (`Cargo.toml:14`, used
in `vss.rs`), yet the seal test (`session.rs:295-301`) verifies against the
crate's own internal non-AEAD `poly1305()` reference — the wrong reference. Docs
at `session.rs:148-149` ("verifies against a stock ChaCha20-Poly1305
implementation") and `:19` ("ChaCha20-Poly1305 AEAD under 2PC") overclaim. Not
exploitable in-tree (nothing wires this to a live TLS peer) → MEDIUM, not HIGH.

**Fix.** Soften `session.rs:19/148-149` to: "produces a single-block Poly1305 tag
over the ciphertext; this is NOT the RFC 8439 AEAD tag (AAD and the le64 length
block are unimplemented) and will not verify against a stock AEAD
implementation." To actually claim AEAD conformance, add the `pad16 + le64 +
le64` length block (needs the multi-block accumulator, R3-34) and change the test
to verify against `chacha20poly1305::ChaCha20Poly1305::encrypt`.

### R3-14 — `encrypt()` accepts an identity (degenerate) joint public key → fixed public keystream
**`core/crates/neo-mpc/src/threshold.rs:61-72` (`joint_public_key` `:194-201`).**

`joint_public_key()` returns `commitments[0].decompress()` with only a
decompress-failure check, **no `is_identity()` guard**. `KeyCommitments`
(`vss.rs:50`) is `pub struct KeyCommitments(pub Vec<CompressedRistretto>)` and
`encrypt()` is `pub`, so an attacker can construct
`KeyCommitments(vec![RistrettoPoint::identity().compress()])`. The Ristretto
identity compresses to a fixed public byte string; then `shared = y * r =
identity` for **every** `r` (`:65`), so `xor_mask` keys
`blake3_derive_key("neo-mpc-threshold-mask-v1", <identity_bytes>)` — one fixed
public keystream independent of `r`, and `c = m XOR fixed_keystream` is
recoverable by anyone with zero committee cooperation.

**Calibration.** In the honest flow `commitments[0] = key_scalar·G` with random
`key_scalar` (`vss.rs:97,108,112-117`), so the honest path is **not** vulnerable;
the exploit requires an attacker-influenced joint key, which the `pub` API permits
but no in-tree caller does. A `pub`-surface foot-gun → MEDIUM.

**Fix.** In `joint_public_key()`/`encrypt()` reject an identity joint key
(`if y.is_identity() { return Err(...) }`). For defence in depth reject an
identity `commitments[0]` at deal time and a non-identity `public_share` before
trusting a partial. Document that `encrypt()` must only be called on
committee-generated, non-identity commitments.

### R3-15 — Threshold hashed-ElGamal ciphertext is unauthenticated and malleable (no INT-CTXT)
**`core/crates/neo-mpc/src/threshold.rs:34-42,61-72,186-189,221-230`.**

The ciphertext is `(r_point, c)` with `c = m XOR blake3-XOF(shared)` (`encrypt
:66-67` → `xor_mask :221-230`). `combine()` (`:186-188`) recomputes `shared = s·R`
via Lagrange-in-exponent, does `xor_mask(&mut m, &shared)`, and returns `m` with
**no MAC/tag verification anywhere**. Flipping any bit of `ct.c` flips the
corresponding plaintext bit and `combine()` returns it without error — textbook
stream-cipher malleability. The DLEQ proofs (`:89-94,116-119`) authenticate only
that each partial is a correct `s_i·R`; they say nothing about `c`. Contrast:
`vss.rs` wraps its body in ChaCha20Poly1305 AEAD (`:99-102,185-189`), so the
sibling path *is* authenticated — the threshold path is the outlier.

On the R-binding sub-claim: `shared = r·Y` already depends on `r`, so distinct
honest ciphertexts already get distinct keystreams; the missing `hasher.update(R)`
is a valid hardening but not itself a keystream-reuse bug. The load-bearing issue
is the **absent MAC**: a MITM on committee→client could undetectably rewrite
recovered plaintext (e.g. destination bytes).

**Fix.** Adopt KEM-DEM: derive an AEAD key from a KDF over the shared point and
wrap the payload in ChaCha20Poly1305 (as `vss.rs` already does), verifying the tag
in `combine()` before returning plaintext. Additionally feed `R` into the
mask/KDF for per-ciphertext binding.

### R3-16 — Doc claims the issuer can rate-limit/blocklist the earning relay, but it never receives the identity
**`core/crates/neo-credits/src/earn.rs:22-25`.**

`earn.rs:22-25` states "Because earning is *identified*, the issuer sees the
earning relay and can rate-limit or blocklist it." But `issue()` (`lib.rs:63`)
receives only an opaque `BlindCredit` — no `NodeId`, no receipt — and the
`EarnLedger` that holds relay identity is never consulted at issuance (R3-02).
There is no per-identity mint-rate cap anywhere; `MAX_RECEIPT_BYTES`
(`earn.rs:38`) bounds only a single receipt. The claimed backstop is not
something the current issuance path can perform at all.

**Fix.** Either wire the earning relay's identity into `issue()` and add a real
per-identity mint-rate cap, or soften `earn.rs:22-25` to state plainly that no
per-identity rate limiting is implemented and the issuer currently cannot see or
throttle the earning relay at issuance time.

### R3-17 — Receipts have no timestamp/expiry: a colluding client can pre-sign unbounded capped receipts
**`core/crates/neo-credits/src/earn.rs:44-56` (`signable` `:77-85`, `record` `:107-123`).**

`RelayReceipt` (`:45-56`) carries only `relay, bytes, nonce, client, sig`;
`signable()` covers exactly `{domain, relay, bytes, nonce, client}` — **no
timestamp, no expiry, no server-issued challenge**, the only circuit binding a
client-chosen 32-byte nonce. `record()` enforces only signature validity, the
per-receipt cap, and nonce-uniqueness. So one entity holding one client key and
one relay key can locally sign arbitrarily many distinct-nonce receipts at
`MAX_RECEIPT_BYTES` with no real traffic, each accepted; marginal cost per
fabricated credit is one Ed25519 signature. Combined with the unbounded `claimed`
set (R3-05) it is also a ledger-growth vector.

**Calibration / honesty note.** The module doc is **honest** about this
(`earn.rs:14-25`): it explicitly says receipts are client-attested not measured
and that colluding client+relay can fabricate many capped receipts. So this is a
disclosed design limitation, not a hidden claim. MEDIUM because near-zero-cost
fabrication substantially weakens the stated Sybil/free-rider goal even under the
honest framing.

**Fix.** Bind receipts to a signed server-side context (issuer-provided
challenge/epoch + timestamp in `signable()`, reject stale receipts) and pursue
the bilateral co-signed receipts already noted as future work at `earn.rs:24-25`;
self-signed one-sided receipts give essentially no work guarantee.

### R3-18 — Oblivious directory: zero-length records cause silent, undetected collisions
**`core/crates/neo-verify/src/oblivious.rs:133-144,108`.**

`try_place` uses the 2-byte length prefix as the occupancy sentinel: a bucket is
"free" iff `records[bucket][0]==0 && [1]==0` (`:138`). A legitimately placed record
whose value length is 0 writes `(0u16).to_be_bytes() = [0,0]` (`:142`) —
byte-identical to an untouched bucket. A later key hashing to the same bucket
passes the occupancy check, overwrites the prior record (`:142-143`), and
`try_place` still returns `Some`; the collision is never detected and `build()`
reports success. This was reproduced by driving the real crate: two 32-byte keys
that both hash to bucket 0 at salt 0 with `n_buckets=4` yielded "BUILD SUCCEEDED"
with `bucket_of(ka)==bucket_of(kb)==0`, violating the "so no two keys collide"
invariant (`oblivious.rs:11-14`). `decode()` also treats `len==0` as a miss
(`:108`), so the record is additionally unreadable.

**Calibration.** Exploitation requires at least one entry to legitimately have a
zero-length record; no in-tree code path is known to produce empty relay records,
so this is a latent integrity bug rather than a demonstrated live break. MEDIUM
because `build()` silently returns corrupt placement (a discovery-integrity
break) with no error and no test coverage for empty records.

**Fix.** Reject empty records explicitly in `build()` (`Error::Config` if any
`r.len()==0`) **or** track occupancy with a separate occupied bitmap instead of
overloading the length prefix. Additionally assert distinct-bucket placement in
`try_place` before returning `Some`.

### R3-20 — Beacon can bias path selection by abort-grinding; module doc claims neither party can bias
**`core/crates/neo-verify/src/selection.rs:42-45,5-8`.**

`beacon_respond` (`:43-44`) computes both the VRF proof **and** the final path
seed via `derive_seed(commitment, output)` before returning anything, so the
beacon learns the exact seed (hence the exact path, since the seed feeds
`select_path_seeded`) while it is still free to not answer. The construction
correctly stops client id-grinding (commitment binds before output) and
beacon-chosen VRF input (input is the client's commitment). But it does **not**
bind the beacon to a single attempt: on retry the client uses a fresh nonce, so
`commitment()` changes (`:33-38`) and the VRF output is a fresh independent
sample. No abort/retry/penalty/deposit/timeout mechanism exists, and no
threshold-of-beacons. Over `k` aborts a malicious beacon draws `k` i.i.d. path
samples and returns only the favorable one. `selection.rs:5-8,7` makes the
absolute claim "neither can bias the result" — an overclaim.

**Calibration.** For any *fixed* commitment the beacon genuinely has exactly one
output (verified by `the_beacon_cannot_grind_for_a_fixed_commitment` and VRF
determinism), so each extra sample costs a full aborted round trip and is
observable as a failure. The abort-budget deanonymization is real but
round-trip-rate-limited, not silent. MEDIUM.

**Fix.** Correct the module doc (`:5-19`) to state abort-and-retry biasing is NOT
prevented and is out of scope of "neither can bias". To close it: derive the VRF
input from beacon-independent public epoch randomness plus a monotonic client
counter (so retries aren't free fresh samples), treat a missing/invalid response
as a committed loggable abort, and/or use a threshold of independent beacons.

### R3-21 — Camouflage DTLS: epoch is always a prefix of the sequence field
**`core/crates/neo-transport/src/lib.rs:132-136` (draw at `:124`).**

`write_header` draws one 8-byte `rnd`, then for `WebRtcDtls` writes `&rnd[..2]` as
the 2-byte epoch (`:134`) and `&rnd[..6]` as the 6-byte sequence (`:135`) — both
sliced from index 0, so `record[3..5] == record[5..7]` on **every** neo
DTLS-camouflaged record. Real DTLS keeps epoch small/stable and increments the
48-bit sequence monotonically; here both are fully random and correlated. For
`QuicMasque`, `write_header` draws a fresh random 8-byte "connection id" per
`frame()` (`:130`), while real QUIC keeps a stable CID per flow. MEDIUM: these are
shape defects, exactly the layer Camouflage claims (`lib.rs:20-21,153`), so a
DTLS/QUIC-shape fingerprinter separates neo reliably.

**Fix.** Fill epoch and sequence from **disjoint** random bytes; maintain
per-connection state so the DTLS sequence increments monotonically, the epoch
stays small/stable, and the QUIC connection id is stable per flow.

### R3-22 — Camouflage exposes a cleartext inner length field + a TCP length prefix real QUIC/DTLS never carry
**`core/crates/neo-transport/src/lib.rs:181-190,353-360`.**

`frame()` writes a 2-byte big-endian plaintext payload-length immediately after
the shape header (`:183`) then plaintext-or-padded payload — real QUIC is
AEAD-encrypted after the header with no such delimiter, and real DTLS's length is
the record length, not the neo payload length. Independently, `Conn::send`
prepends a 4-byte big-endian **TCP** length prefix to the whole record
(`:356-358`); QUIC/DTLS are UDP datagram protocols with no stream framing. The
crate doc (`lib.rs:9-11,149-151`, "sees a familiar protocol, not neo") overstates
what shape delivers, though the Honest boundary (`lib.rs:20-25`) partly discloses
this → MEDIUM (doc-precision + design limitation, not a crypto break).

**Fix.** Tighten the doc: state Camouflage imitates only coarse header bytes and
datagram sizing and is NOT expected to fool a protocol-aware classifier; have the
Honest boundary explicitly name the cleartext length field and the TCP-vs-UDP
framing mismatch. For real resistance, carry records over UDP and encrypt/pad so
no cleartext length delimiter remains.

### R3-23 — Per-IP register cooldown is the only limiter; bypassable with IP diversity
**`core/crates/neo-seed/src/service.rs:201-215,179-197`.**

`check_and_stamp_cooldown` (`:201-214`) keys the cooldown solely on the resolved
client IP; there is no per-record-key limit, no global registration rate, and no
registry-size cap (R3-09). Each distinct source IP registers a fresh record with a
brand-new `NodeId`/key every `register_cooldown` (default 30s, `:60`). An IPv6
`/64` yields effectively unlimited distinct exact-IP cooldown keys (keyed on exact
`IpAddr`, not prefix). The cooldown map itself is bounded (`retain` at 4× cooldown,
`:212`), so the DoS lands on the uncapped registry and serial dial loop —
amplifying R3-08/R3-09. Note the X-Forwarded-For handling is **correct** (honors
XFF only from `trusted_proxies`, takes the right-most hop, `:220-232`, test
`:288-301`), so XFF spoofing is not viable; the bypass is genuine IP diversity.

**Fix.** Add a global registration rate limit and a hard registry-size cap. Key
IPv6 sources by prefix (e.g. `/64`). Consider a lightweight PoW or requiring a
valid VOPRF credit as an admission token so minting a fresh signing key is not
free.

### R3-24 — `sharks 0.5.0` (RUSTSEC-2024-0398) biased Shamir coefficients (test-only path)
**`core/crates/neo-mpc/src/lib.rs:46,167-168,192-201`; `Cargo.toml:46`; `Cargo.lock` sharks 0.5.0; `sharks-0.5.0/src/math.rs:36`.**

`sharks-0.5.0/src/math.rs:36` uses `Uniform::new_inclusive(1, 255)` for **all**
non-constant polynomial coefficients including the highest-degree one, excluding
0 — matching RUSTSEC-2024-0398. `Cargo.lock` pins sharks 0.5.0 (curve25519-dalek
4.1.3 is patched, so sharks is the only live crypto advisory). With the top
coefficient from `[1,255]`, a `k-1` coalition can statistically exclude candidate
secrets (textbook Shamir makes every secret equiprobable).

**Calibration (downgraded HIGH→MEDIUM).** The advisory itself states secrets
shared once are not impacted; recovery in ~500–1500 distributions requires
re-dealing the **same** secret many times, ideally 2-of-N. `neo_mpc::deal` /
`Committee::deal` are invoked **only in tests** (`neo-node/tests/frontier.rs` and
the crate's own `#[cfg(test)]`); `neo-node/src/` has zero references. There is no
production loop re-dealing the same request to overlapping committees, so the
amplification scenario does not exist in shipped code. The advisory is genuine and
the crate is API-exposed, so it should be removed.

**Fix.** Drop sharks 0.5.0: migrate to the maintained `blahaj` fork (same API,
`[0,255]` range) or a vetted GF(256) Shamir, and add a share-uniformity test. Add
the CI advisory gate (R3-50).

### R3-25 — Doc claims Shamir information-theoretic secrecy that `sharks 0.5.0` does not deliver
**`core/crates/neo-mpc/src/lib.rs:8-15,152`.**

`lib.rs:12-13` asserts "Any k-1 members — even colluding — learn nothing … this is
Shamir's information-theoretic guarantee, not a computational assumption", and
`deal`'s doc (`:152`) repeats "Any threshold-1 of them reveal nothing." True only
for textbook Shamir; the shipped sharks 0.5.0 (R3-24) does **not** deliver perfect
secrecy — below-threshold coalitions get a statistical advantage. The doc asserts
strictly more secrecy than the code delivers, contradicting the no-overclaim
commitment. Distinct from the already-fixed H-6. MEDIUM: the claim is in an
internal crate doc-comment and the primitive is test-only, but it is unambiguously
false as written.

**Fix.** Migrate off sharks (after which the claim is accurate) **or** amend
`lib.rs:8-15` and `:152` to note the implementation caveat / stop making the
information-theoretic claim. A uniformity test would let CI back the claim.

### R3-48 — No handshake/read timeouts or connection caps — slowloris head-of-line on the accept loop
**`core/crates/neo-node/src/run.rs:31-41,64-79`; prod loop `platforms/desktop/src/roles.rs:123-157`.**

`read_frame` (`run.rs:33,39`) uses `read_exact` with **no timeout**; `accept()`
(`:68-78`) does four untimed `read_frame`s; there is no `Semaphore`/connection cap
anywhere. This **is** reachable in production — the relay loop
(`roles.rs:123`) awaits `run::accept` inline. Worse than a per-task stall: because
`accept()` is awaited **before** the `tokio::spawn` (`roles.rs:124` vs `:129`), a
single client that sends the 4-byte length prefix then stalls blocks the **entire
accept loop** (head-of-line) until its socket errors — one slow client denies all
new connections.

**Calibration (HIGH→MEDIUM; overclaim sub-claim REFUTED).** The `accept()` doc
(`run.rs:59-63`) claims only that the cookie makes a replayed/abandoned m1 cost a
MAC before ML-KEM work — it makes **no** general DoS-resistance claim, so there is
no doc overclaim to soften. The idle-hold-on-established-circuit portion targets
`exit_splice`/`serve_circuit`, not wired into a running node yet (R3-11), so only
the handshake-stall bites production today.

**Fix.** Wrap `accept()`'s handshake reads and every `read_frame` in
`tokio::time::timeout`; **spawn the per-connection handshake** so a stalled client
cannot block the accept loop; add a `Semaphore` bounding concurrent
handshakes/connections and an idle timeout on established circuits. No doc change
needed for the cookie claim.

---

## 5. LOW

### R3-26 — "Stateless" anti-DoS cookie is neither stateless in the driver nor source-bound
**`core/crates/neo-crypto/src/handshake.rs:45-51 (doc),61-66`; usage `neo-node/src/run.rs:68-79`.**
`cookie()` (`:61-66`) keys BLAKE3 with the per-connection secret and hashes only
`COOKIE_DOMAIN + eph_x_pub_i` (the initiator's own ephemeral key) — **no source
address**, so no return-routability/anti-spoofing guarantee. `accept()` calls
`listener.accept()` first, then generates a fresh `CookieKey` per connection
(`run.rs:69`) and holds it plus an open socket across three I/O calls — real
per-connection state for a full RTT, with no rate limit. Over TCP the cookie's
only marginal benefit is gating ML-KEM work behind an already-established,
non-spoofable connection. "Stateless" is defensible only in the narrow sense that
no cross-connection lookup *table* is kept. **Fix:** soften the doc to say the
cookie only gates ML-KEM work behind an established TCP connection and gives NO
source-address/anti-spoofing/amplification guarantee; note that any future UDP
transport must bind the cookie to the source address with a rotating global
secret. Add connection rate-limiting / a concurrency cap regardless (see R3-48).

### R3-27 — Handshake intermediate secrets are not zeroized
**`core/crates/neo-crypto/src/handshake.rs:230,265,342-345,376-388`; k_confirm `:136,299`.**
In `derive_keys` (`:376-388`) `ikm: [u8;64]` holds `dh‖ss` (the exact inputs that
reconstruct **both** session keys) and is dropped with no `Zeroizing`. The `dh`
copies from `.to_bytes()` (`:230,342-345`) and `ss` (`:515-519`) are plain
`[u8;32]`. `k_confirm` in `PendingResponder` (`:136`) has no `Drop` and is dropped
in `responder_confirm` (`:291-308`) unzeroized. Session keys **are** zeroized
(`session.rs:47-51,86-90`, advertised at `session.rs:9`) — so leaving the pre-key
material resident is a genuine inconsistency with that hygiene claim. Standard
defense-in-depth (core dump/swap/cold-boot). **Fix:** wrap `ikm` and the returned
keys in `zeroize::Zeroizing`; zeroize `dh`/`ss` after they feed `derive_keys`;
give `PendingResponder` a `Drop` that zeroizes `k_confirm`.

### R3-28 — Sphinx replay-cache horizon is count-driven, not time-driven; no routing-key rotation
**`core/crates/neo-crypto/src/sphinx.rs:159-171,116-131`.**
`check_and_insert()` rejects a tag only if in `current` or `previous`; on rotation
it discards the old `previous` wholesale, so a tag aged past both generations by
`>capacity..2*capacity` distinct packets is accepted again. `identity.rs:227-244`
derives `route_scalar()` deterministically from the static seed ("re-derived, not
stored") — there is **no** time-epoch routing-key rotation, so the horizon is
purely traffic-volume-driven, untied to wall-clock. The doc-comment
(`:116-131`) honestly acknowledges the horizon → documented residual, not
overclaim. Requires pushing `>2M` distinct onions through one relay. **Fix:**
implement epoch-based routing-key rotation (drop the cache atomically) or add
per-tag timestamps/TTL for a wall-clock-bounded window. Keep the honest doc.

### R3-29 — Payload delta is unauthenticated at non-exit hops → deliver/reject confirmation oracle
**`core/crates/neo-crypto/src/sphinx.rs:338-340,265-273,353-361`.**
Per hop `process()` peels one Lioness layer of delta (`:338-340`) with no per-hop
payload MAC; only header beta is MAC-protected per hop (`:316`). The payload MAC
key derives from the exit's shared secret alone (`:276-277` build / `:353-354`
check), so only the exit verifies delta and rejects on tamper. Lioness SPRP
prevents a *chosen readable pattern* (avalanche test `:622-644`), narrowing the
residual to a binary deliver-vs-reject signal a colluding entry can induce (mark)
and the exit can observe (reject) — a flow-confirmation oracle. No confidentiality
or delivered-data integrity loss. The doc (`:270-273`) honestly calls full
non-malleability "the remaining hardening". **Fix:** adopt a wide-block PRP
spanning header+payload, or fold delta into the per-hop MAC. Retain the honest
wording until then.

### R3-30 — IKNP extension has no receiver-consistency check (selective-failure; gated out)
**`core/crates/neo-mpc/src/mpc_tls/ot_ext.rs:49-67`.**
Protocol-level claim is correct: semi-honest IKNP03 has no r-consistency check, and
a malicious extension receiver submitting inconsistent `u_j` mounts the classic
selective-failure attack recovering the sender's selector `s`; wired to free-XOR
(`garble.rs:85-86,121-123`) that could leak Δ. **But** `extend` (`ot_ext.rs:22`)
runs both roles in one process — it generates `s` itself and computes `u_j`
honestly (`:50-57`); there is no network boundary, no attacker-supplied `u_j`, and
**no caller anywhere except unit tests** (`ot_ext.rs:162,178`). The live session
uses base OT only (`session.rs:121`), never the extension. So this is a valid
missing-check / model-limitation note, **not** a live break — the original HIGH
"totally breaks garbling" impact is not reachable in shipped code. **Fix:** add one
sentence to the `ot_ext.rs` header (`:7`) stating a malicious receiver recovers `s`
(and thus Δ if wired to free-XOR), so a KOS15/ALSZ15 consistency check is required
before any non-in-process deployment. Keep it gated out (it currently is).

### R3-31 — `mpc_tls` crate doc omits the semi-honest-only qualifier where OT/IKNP are introduced
**`core/crates/neo-mpc/src/mpc_tls.rs:6-14`.**
Lines 8-9 state "neither alone holds the traffic key or can read/forge a record"
as the construction goal, while ot.rs/ot_ext.rs are semi-honest. The overclaim is
**minor**: the same file has a prominent "## Honest boundary" (`:30-46`) that
defers "Full malicious security", notes dual-execution's ≤1-bit leak, and flags
the external-audit gate — so a reader isn't left believing the primitives resist a
malicious peer; the qualification is just later in the file. Honesty-tone nit.
**Fix:** reword line 8 to "such that against a semi-honest peer neither alone holds
the traffic key or can read/forge a record", and cross-reference the ot/ot_ext
bullet (`:12-14`) to the malicious-model gaps. No code change.

### R3-32 — `check_pass` is not a secure equality test; the ≤1-bit bound is the protocol's, not the code's
**`core/crates/neo-mpc/src/mpc_tls/dualex.rs:95-112,27-34,122-129,14-15`.**
`Execution.garbler_pairs` (`:33`) is populated by `Garbler::output_labels`
(`garble.rs:127-133`), which returns **both** `(zero, one)` labels per output wire —
and since `one = zero XOR delta`, holding a pair reveals delta on that wire.
`check_pass` (`:95-112`) is a single in-process fn receiving `ex1` and `ex2` in
full and just blake3-hashing concatenations (`hash_pairs :122-129`) — no
commitment step, no restriction to a single self-derived check value. So the code
does not itself deliver the ≤1-bit bound; that bound belongs to the
Mohassel-Franklin/HKE protocol the doc (`:8-15`) cites. Line 14-15 overstates what
this fn achieves. Downgraded MEDIUM→LOW because dualex is never in the session path
(R3-12), so it leaks nothing in any actual neo execution — a dormant demo. **Fix:**
implement the equality test as commit-then-open (operating solely on each party's
own hashed check value) and stop handing `check_pass` full `garbler_pairs`; **or**
soften `:14-15` to say it is an idealized in-process model that does NOT by itself
achieve the ≤1-bit bound.

### R3-33 — `dualex` ≤1-bit bound assumes a committed/simultaneous equality channel not provided
**`core/crates/neo-mpc/src/mpc_tls/dualex.rs:1-15,95-112`.**
The cryptographic caveat is correct: the ≤1-bit MF/HKE bound requires a secure
two-party equality test; `check_pass` compares two hashes computed by one process,
so a naive port revealing hashes sequentially over a wire would leak more than one
bit. But the doc already scopes this ("Modelled in-process; the equality test here
compares hashes … revealing only the equal/not-equal bit", `:14-15`), and
independent per-execution randomness is satisfied (`execute()` garbles fresh with
independent `rand_label`/`delta`, `:43`, `garble.rs:84-91`). A legitimate doc
refinement, not an overclaim surviving the disclaimer. **Fix:** add one clause to
the header — the ≤1-bit bound holds only when `check_pass` is wrapped in a
committed/simultaneous secure-equality subprotocol; the in-process comparison
models the value check, not that wrapper. No code change.

### R3-34 — Doc claims multi-block Poly1305 (Horner) the circuit does not implement
**`core/crates/neo-mpc/src/mpc_tls/poly1305.rs:15,186`.**
`tag_shared` (`:187-192`) takes a single `[u8;16]` block; no accumulator, no loop.
`tag_circuit` (`:214-245`) reconstructs one block, appends the high bit, multiplies
once by `r`, reduces once, and adds `s` **once inside** the per-block circuit
(`:240`). A true Horner MAC adds `s` exactly once at the very end and chains the
accumulator — neither wire exists. The reference `poly1305()` (`:48-56`) correctly
loops and adds `s` once after — the reference is fine, but doc lines 15 and 186
assert the circuit/`tag_shared` supports multi-block. A latent trap: calling
`tag_shared` per chunk would re-add `s` and never chain `acc`. Zero attacker gain
(single caller uses one block). **Fix:** change `:15` and `:186` to state "Single
16-byte block only; multi-block Horner iteration is NOT implemented," or implement
the accumulator wires + move `+ s` to a final step and add a >16-byte KAT.

### R3-35 — `tag_circuit` hard-codes the message high bit at position 128 (partial block mis-padded)
**`core/crates/neo-mpc/src/mpc_tls/poly1305.rs:232`.**
`:231-232` does `block_hi.push(one)`, unconditionally placing the Poly1305 message
bit at position 128 — correct only for a full 16-byte block. The reference
(`:52`) places it at `block[chunk.len()]` for partial blocks per RFC 8439 §2.5.1.
Strictly latent: `tag_shared`'s one caller (`session.rs:173`) always passes 16
bytes. **Fix:** when adding multi-block support, parameterize the high-bit position
by the actual tail length, or add an explicit assert that only exact 16-byte blocks
are supported.

### R3-36 — Circuit KAT coverage is single-sample per gadget; no boundary/adversarial vectors
**`core/crates/neo-mpc/src/mpc_tls/poly1305.rs:398-412`; `sha256.rs:391-417`; `circuit.rs:435-456`.**
The 2PC tag circuit is tested by exactly one pseudo-random input pair; SHA-256
compression by one block; ChaCha by two cases. None drive the arithmetic
boundaries where `reduce_circuit`/`add_mod` bugs hide: `r` clamped to max, block
all-ones, an accumulator in `[P, 2^130)` to exercise the final conditional subtract
(`poly1305.rs:283-291`). Review-hygiene / false-confidence gap, not a live vuln —
`reduce_circuit` (`:265-291`) is structurally sound. A regression in the fold count
or subtract branch would still pass CI. **Fix:** add KATs that (a) drive `r` to its
clamped max and block to all-ones, (b) hit the conditional-subtract branch, and (c)
compare `tag_shared` against the reference over ~1000 random `(key, block)` pairs.

### R3-37 — Docs present threshold decryption as "verifiable" without disclosing ciphertext malleability
**`core/crates/neo-mpc/src/threshold.rs:1-24`; `lib.rs:19-27`.**
`threshold.rs:1-24` stresses verifiability/robustness ("DLEQ-proved partials", "a
forged partial is caught and attributed", "a real, verifiable building block") and
`lib.rs:23-27` repeats it; neither states the ciphertext `(R,c)` is unauthenticated
and malleable (R3-15) nor that `encrypt()` trusts the joint key (R3-14). Not
technically false — the verifiability described is partial-consistency-with-
committed-shares — but omitting the malleability caveat lets an integrator assume
end-to-end plaintext integrity the code does not provide. **Fix:** add one sentence
to both docs — the threshold layer provides confidentiality and partial-
verifiability only; `(R,c)` is NOT authenticated (malleable) and `encrypt()`
assumes a committee-generated non-identity joint key; an AEAD/MAC wrapper is
required. If R3-15 is fixed, describe the AEAD instead.

### R3-38 — `combine()` takes `threshold` decoupled from the committed degree → silent garbage
**`core/crates/neo-mpc/src/threshold.rs:128-164`.**
`combine` (`:128-133`) takes `threshold: usize` with no cross-check against
`commitments.0.len()` (the degree+1 that fixes the true `k`), and uses
`&valid[..threshold]` (`:164`). A caller passing `threshold` smaller than the real
`k` while supplying ≥`threshold` valid partials interpolates over too few points,
reconstructs a point `≠ s·R`, and `xor_mask` yields **garbage returned with no
error** (there is no post-decrypt integrity check — that is R3-15). **Calibration:**
the secondary "weakens the threshold guarantee / helps an attacker" claim is
**refuted** — sub-`k` interpolation produces garbage, not `m`, so there is no
confidentiality/threshold bypass, only a mis-integration foot-gun. In-tree callers
(tests) pass the correct threshold. **Fix:** validate `threshold` against the
committed degree in `combine()` (require `threshold == commitments.0.len()`, or at
least `2 <= threshold <= commitments.0.len()`), erroring otherwise. Adding the R3-15
AEAD would also convert this into a clean decrypt-error.

### R3-39 — `SignedSnapshot::verify` has no anti-rollback/freshness param (no consumer yet)
**`core/crates/neo-discovery/src/snapshot.rs:104-149`.**
`verify()` takes `(trusted, threshold, now)` and enforces only `expires_at > now`
(`:111`), `created_at < expires_at` (`:114`), and `created_at <= now +
MAX_FUTURE_SKEW` (`:122`); it never consumes a `not_before`/high-water mark, unlike
`BootstrapRecord::verify` (`bootstrap.rs:63,70`). `SignedSnapshot` is only produced
(`neo-seed/registry.rs:142-150`) and served as pre-serialized bytes; `verify()` is
called only from this module's unit tests — there is **no client** that fetches,
parses, or verifies a snapshot (no CLI crate exists). So the "freeze a client"
primitive requires a consumer that does not exist. A real latent format gap, not a
currently exploitable path → LOW. **Fix:** when a snapshot client is written, give
`verify()` a `not_before: u64` param mirroring `BootstrapRecord::verify`, reject
`created_at < not_before`, and persist the highest accepted `created_at`.

### R3-40 — Doc-comments claim a snapshot anti-rollback high-water mark that isn't implemented
**`core/crates/neo-discovery/src/snapshot.rs:31-34,117-126`.**
The `MAX_FUTURE_SKEW` doc (`:31-34`) says the skew cap exists to bound "the
anti-rollback high-water mark", and the inline comment in `verify` (`:117-126`)
reasons about "a client persisting an anti-rollback high-water mark" — but
`verify()` never reads or enforces any high-water mark, and no workspace caller
persists/compares `created_at`. The comments describe a protection the shipped code
cannot deliver. Genuine overclaim in comments. **Fix:** reword `:31-34` and
`:117-126` to state `verify()` enforces expiry + a future-skew cap **only**, that
anti-rollback requires a (not-yet-existing) client to persist and pass a high-water
mark, and that `MAX_FUTURE_SKEW` is a forward-looking guard for that future caller.

### R3-41 — libp2p `sample_relays` is deterministic (`HashMap take(n)`), unlike shuffled `LocalRegistry`
**`core/crates/neo-discovery/src/libp2p_backend.rs:396-405`.**
The libp2p `SampleRelays` handler does `cache.values().filter(...).take(n)`
(`:398-403`) with no shuffle, whereas `LocalRegistry::sample_relays` performs a
getrandom-seeded Fisher-Yates shuffle before truncate (`lib.rs:422-425,438`). std
`HashMap` uses SipHash with a per-map random seed, so iteration order is randomized
once per process but **stable across calls within it** — a given client repeatedly
draws the same early-slot relays, and a Sybil who floods records raises the odds
its nodes land early (attacker cannot choose the per-process seed). Defense-in-depth
/ traffic-analysis concern, LOW. **Fix:** use the same getrandom-seeded Fisher-Yates
shuffle as `LocalRegistry::sample_relays` before truncating.

### R3-42 — `selection_index` has modulo bias + uses 64/256 bits; doc claims "verifiably fair" (unused)
**`core/crates/neo-verify/src/vrf.rs:64-71`.**
`selection_index` copies `output[..8]` into a u64 (`:68-69`) and returns
`u64_le % n` (`:70`) — classic modulo bias for non-power-of-two `n`, consuming only
8 of 32 output bytes. The module doc (`:1-7`) advertises "verifiably fair"
selection. Contrast `neo_routing::select_path_seeded` (`lib.rs:110-137`) which uses
a full 32-byte keyed BLAKE3 XOF with rejection sampling. `selection_index` has **no
callers outside its own test** (`vrf.rs:109-114`); the live per-request selection
uses the correct `select_path_seeded`. Fairness defect in an unused public helper,
LOW (arguably dead code). **Fix:** delete `selection_index`, or fix it to
reject-sample over the full 32-byte output and stop advertising "verifiably fair".

### R3-43 — `dial_reality` doc claims flight "indistinguishable from random" despite a structured prefix
**`core/crates/neo-transport/src/lib.rs:233`.**
The docstring states "To a censor the flight is indistinguishable from random." But
the flight is written by `write_blob` with a cleartext 4-byte big-endian length
prefix (`:326`) which for the fixed 96-byte hello is the structured bytes
`00 00 00 60`, and the length is fixed (R3-03). The module-level docs are
commendably honest (`lib.rs:20-25`, `reality.rs:23-28`), but this per-method line
asserts a property the code doesn't deliver. **Fix:** reword to scope the claim to
the authenticator body — e.g. "the authenticator bytes are uniform to anyone
without the capability; the wire framing is NOT yet TLS-embedded and is
fingerprintable — see the module honesty note."

### R3-44 — Doc claims cell integrity is "the same guarantee" as Sphinx replay-once (it isn't)
**`core/crates/neo-node/src/circuit.rs:18-25`.**
Doc lines 22-25 assert the per-cell e2e MAC gives "the same integrity guarantee the
forward Sphinx payload and the one-shot return path already have." Sphinx forward
payloads are replay-once via the `ReplayCache` and the `stream.rs` return path is a
single message — both inherently non-replayable. Cells carry an attacker-mutable
`seq` with zero dedup (R3-06/07), so the parity claim holds only for bit-mauling,
not replay/reorder/drop. Line 19 even says "Unlike Sphinx (one packet per hop,
replay-once)" and then claims equal integrity. Exactly the overclaim the honesty
bar forbids. **Fix:** implement seq enforcement (R3-06/07) and keep the claim, or
amend `:22-25` to state cells provide per-cell tamper-detection **only**, and that
stream ordering/uniqueness must be enforced by a higher layer.

### R3-45 — Cover traffic is co-terminous with the session — coarse activity envelope exposed
**`core/crates/neo-mix/src/lib.rs:89,100-101`; `neo-node/src/tunnel.rs:64,112`.**
`spawn_cover` launches the instant `Mixer::run` starts (`:89`) and its Poisson loop
emits immediately, independent of app packets; `cover.abort()` fires (`:101`) only
after input closes and inflight drains, and `tunnel.rs:112` aborts `mix_task` on
session end. So cover is bounded by the **tunnel-session** lifetime (it *does* run
during idle periods within a live session), **not** by "when the user starts/stops
sending" as originally framed — that causal claim is corrected. The residual: a
session that only comes up when the user has traffic still brackets activity at
session granularity; there is no link-lifetime steady-state cover across idle
sessions. A well-known Loopix-class per-session-cover limitation, not a doc
overclaim (`neo-mix:8-9` speaks to rate/pattern within the mixed stream).
Downgraded MEDIUM→LOW. **Fix:** if hiding the session envelope is in scope, run
cover for the full link lifetime independent of tunnel-session state; otherwise
document that per-session cover masks per-packet timing but not session presence.

### R3-46 — OS-RNG-failure fallback yields a deterministic mixing delay (~0.693·mean), no operator signal
**`core/crates/neo-mix/src/lib.rs:121-128,137-145`.**
`uniform_open_unit()` returns exactly 0.5 on getrandom failure (`:139-141`), and
`sample_exponential` computes `-mean·ln(0.5) = 0.693·mean` (`:126`) — a constant —
for both real-packet delays and cover intervals. Under sustained induced RNG
failure every delay/interval becomes deterministic and input→output timing linkable
while the mixer appears healthy (no log/metric on the failure path). The tradeoff is
honestly documented (`:131-136`, "the unbiasable timing property only holds while
the RNG works") → not an overclaim. Narrow precondition (attacker inducing durable
getrandom failure). **Fix:** on RNG failure, seed a fallback CSPRNG once from an
earlier successful draw (or otherwise vary the fraction) instead of a fixed 0.5, and
log/surface repeated RNG failures.

### R3-47 — Doc claims corrupt shards "attributable by index"; the API never surfaces the index
**`core/crates/neo-slicing/src/lib.rs:216-222,68-71`.**
`reassemble_and_decrypt`'s doc (`:214-219`) and `Share::mac`'s doc (`:68-71`) claim
a bad share is "attributable by index". The implementation (`:222`) does
`shares.iter().filter(|s| s.is_authentic(key))` — failing shares are silently
dropped; no failing index is collected, and the signature returns
`Result<Vec<u8>>`, so outputs are plaintext or an aggregate `Error`. No per-index
attribution reaches the caller. No confidentiality/integrity break — the MAC
correctly demotes corrupt shards to erasures and RS routes around them (`:328-335`).
Pure documentation-honesty overclaim. **Fix:** either return the set of
authentic-but-failing indices (richer result type) so attribution is real, or
soften `:216-219` and `:68-71` to say corrupt shards are detected and dropped as
erasures without claiming per-index attribution is exposed.

### R3-49 — `recv`/`read_blob` allocate up to 16 MiB from an unauthenticated 4-byte length
**`core/crates/neo-transport/src/lib.rs:364-374,333-343`.**
Both `read_blob` (`:334-341`) and `Conn::recv` (`:365-372`) read a 4-byte length
`n`, check only `n > MAX_RECORD` (16 MiB, `:37`), then eagerly `vec![0u8; n]` before
any bytes/auth. On the pre-auth `accept_reality` path (`:288-289`) the blob is read
before `classify` runs, so a decoy/prober forces a 16 MiB zeroed allocation with a
4-byte header even though a real REALITY hello is only 96 bytes. `read_exact` then
blocks (not unbounded), one allocation per connection → LOW. **Fix:** cap the
first-flight/`read_blob` size far below `MAX_RECORD` (a few KiB is ample for a
REALITY hello). For `recv`, use a smaller cap or reserve incrementally into a reused
buffer.

### R3-50 — No supply-chain advisory gate (cargo-audit/deny) in CI
**`.github/workflows/ci.yml` + `Cargo.toml:33-60`.**
`grep -iE 'audit|deny|rustsec'` over `ci.yml` returns nothing — no advisory gate,
which is exactly why RUSTSEC-2024-0398 (R3-24) survived two prior rounds.
`Cargo.lock` is committed and pins exact versions (mitigates drift for the binary),
but workspace specs are permissive caret ranges (`tokio="1"`, `voprf="0.5"`,
`getrandom="0.2"`, `rand="0.8"`, `sharks="0.5"`). LOW today because of the lockfile,
but the missing gate is the process root-cause. **Fix:** add a `cargo audit --deny
warnings` (or cargo-deny with a checked-in `deny.toml`) job to `ci.yml`. Optionally
pin the security-sensitive specs (sharks, voprf, the dalek crates) to tilde/exact.

---

## 6. INFO

### R3-51 — m1 carries no anti-replay nonce → bounded per-connection ML-KEM + Ed25519 CPU-DoS
**`core/crates/neo-crypto/src/handshake.rs:23-26,209,222,190-286`.**
`nonce_i` is parsed (`:209`) and fed into signature verification (`:222`) but never
recorded/cross-checked, so it plays no freshness role. An attacker records a
victim's valid `m1+sig` (no private key needed — replayed verbatim), performs the
cheap cookie round-trip itself, and sends the cookied init2; `responder_process`
passes the cookie check, verifies the (replayed) signature, does the X25519 DH, the
**ML-KEM encapsulation** (`:234`), and the **Ed25519 sign** (`:263`), failing only
at `responder_confirm` (`:300`) because the attacker lacks `k_confirm`. So the
expensive asymmetric work is incurred per replay — a real, bounded CPU-amplification
primitive. **The doc (`:23-26`) is literally true** ("a replayed or forged m1 can
never establish a confirmed session" — scoped to establishment, not to CPU cost), so
this is a doc-clarity nit, INFO. **Fix:** add a one-line doc clarification that a
replayed m1 still drives one ML-KEM encapsulation + Ed25519 signature before
rejection; combine with the connection rate-limiting of R3-48.

### R3-52 — 128-bit MAC/payload tags with an unlimited online oracle (safe)
**`core/crates/neo-crypto/src/sphinx.rs:31,460-465,276-282,316-324`.**
`MAC_LEN = 16` (`:31`); `mac()` truncates BLAKE3 to 16 bytes (`:460-465`). The
header MAC gamma and exit payload MAC both use this 16-byte tag. `process()` checks
the header MAC (`:316`) **before** burning the replay tag (`:321-324`) and before
any point ops (`:364`), so a forger retries cheaply with no state cost — an
unlimited online oracle. Each attempt succeeds only at 2⁻¹²⁸, the standard
authenticator target, so **not exploitable** — a margin/uniformity note (128-bit tag
vs 256-bit keys), INFO. **Fix (optional):** widen gamma and the payload MAC to 32
bytes for uniformity, OR document that 128-bit tag strength is the intended,
sufficient target. No security action required.

### R3-53 — Chou-Orlandi sender never validates receiver point R (harmless under Ristretto)
**`core/crates/neo-mpc/src/mpc_tls/ot.rs:53-64`.**
`sender_send` computes `yr = r*setup.y` with no validation of `R`. Not exploitable:
`R` is a `RistrettoPoint` (prime-order, no cofactor/torsion), so there is no
small-subgroup attack, and a receiver choosing `R = identity` gains nothing it
couldn't compute itself. The protocol is documented semi-honest (`ot.rs:6`); the
pad binds `S` and `R` into the KDF (`:78-86`). Forward-looking portability note.
**Fix:** none now. If OT ever moves off Ristretto to a non-prime-order or x-only
curve (anticipated at `mpc_tls.rs:43-44`), add point/identity validation and bind
`R` into a transcript to prevent cross-instance pad replay.

### R3-54 — `shared_ecdhe` is a self-play simulation, not a live two-party handshake
**`core/crates/neo-mpc/src/mpc_tls/session.rs:57-70,51-56`; `mpc_tls.rs:39-45`.**
`shared_ecdhe` takes `server_secret` as a local `&Scalar` arg, samples `x1`/`x2`
locally (`:61-62`), and computes both client shares and `z_server` in the same
process — a single-process self-play model, with no point-share-to-bit-share
conversion (so the additive point shares aren't yet consumable by the key-schedule
circuit). The arithmetic is sound (`share1+share2 = x_pub·s = z_server`, test
`:214`; neither share alone equals `z_server`, `:216-217`), so "neither party learns
Z" holds within the model. The docs already hedge both gaps (`mpc_tls.rs:39-42`
names EC share conversion as unimplemented, `:43-45` flags live wiring, `session.rs:
20-23` says parties are modelled in-process). Only the fn-level doc (`:51-56`)
reading "against a server" could imply a live external handshake. **Fix:** annotate
`shared_ecdhe`'s own doc as a local self-play model of DECO ECDHE and note no
point-share→bit-share conversion is performed. The share/mask math is correct.

### R3-55 — `redeem()` uses the non-verifiable `evaluate()` path — correct for issuer==verifier
**`core/crates/neo-credits/src/lib.rs:75-87`.**
`redeem()` recomputes the OPRF via `server.evaluate(&credit.serial)` (`:78`) and
compares to the presented token (`:80`), then rejects double-spends (`:83`). Since
only the issuer holds the key, recomputation is authoritative — the correct private
verification for an issuer==verifier design (tampered-token test `:178`). It yields
no publicly verifiable spend proof, which matches the design. Recorded only so any
future doc claiming third-party-verifiable spends would be flagged. **Fix:** none.
If redemption is ever delegated to non-issuer verifiers, switch to a construction
producing a verifiable spend proof.

### R3-56 — Bootstrap `not_before` anti-rollback is correct but has no consumer yet
**`core/crates/neo-discovery/src/bootstrap.rs:60-76`.**
`BootstrapRecord::verify` (`:63`) takes `not_before` and rejects
`created_at < not_before` (`:70-74`); the signature/limits/trusted-key checks are
correct. `from_txt`/`verify` are exercised only in unit tests (`:210-237`); there is
no CLI crate / no workspace consumer, so the anti-rollback guard is inert until a
DoH client persists and passes `not_before`. The module doc (`:12-13`) **honestly**
states "The DoH transport lives in the CLI" — not an overclaim. Correct-but-unwired
primitive, INFO. **Fix:** when the DoH client is implemented, persist the highest
accepted `created_at` and pass it as `not_before`. Optionally note in the crate doc
that rollback protection is not yet in effect.

### R3-57 — NodeId self-cert does not cover the Sphinx routing key (bound by signature instead)
**`core/crates/neo-core/src/identity.rs:43,68-81,203-207,228-238`.**
`from_keys` (`:75-79`) hashes only `b"neo-node-id-v1" ‖ signing ‖ kex ‖ kem` — the
Ristretto sphinx key is not an input. But `sphinx` **is** inside the signed record
body (`encode_body :183`, verified by `verify_static` over `signable_bytes`,
`neo-discovery/lib.rs:147`), so only the holder of the node's signing secret can set
it — no cross-identity forgery. `verify_static`/`check_limits` never decode `sphinx`
to a canonical point, so a node can self-publish a malformed sphinx key, harming
only its own reachability (and `sphinx_shared` at `identity.rs:216-225` rejects the
identity point, closing the one node-independent-shared-secret hole). A pure
documentation-honesty nit: `identity.rs:43` ("BLAKE3 over the public keys") and the
module doc read as if the routing key were part of the id, when it is only bound via
the signature. INFO. **Fix:** tighten `identity.rs:43` and the module doc to state
NodeId binds only signing/kex/kem and the routing key is authenticated by the record
signature. Optionally (defense-in-depth) add a `verify_static` check that
`self.sphinx` equals the value re-derived from the signing seed, and validate it
decodes to a canonical Ristretto point.

---

## 7. What is genuinely solid

The review attempted to break the following and **failed** — these held up under
adversarial scrutiny and are called out both to record what works and to avoid
re-litigating them next round.

**The 2PC-TLS core's cryptographic primitives (within their semi-honest model).**
This is the newest code and it holds up on the axes it claims:
- **Chou-Orlandi base OT** (`ot.rs`) is correct over Ristretto: the prime-order
  group makes the missing `R` validation (R3-53) harmless, and the pad KDF binds
  `S` and `R` so pads don't cross-replay within an instance.
- **Free-XOR garbling** (`garble.rs:84-91`) uses a fresh independent `delta` and
  label randomness per garble call, so the dual-execution executions are
  independent as required (this refutes one sub-claim originally raised against
  dualex).
- **The Poly1305 `reduce_circuit`** (`poly1305.rs:265-291`) is structurally sound —
  fold `high*5 + low` up to four times then a single conditional subtract of `P`;
  the reference `poly1305()` (`:48-56`) is a faithful RFC 8439 implementation. The
  reference-vs-circuit agreement for the single 16-byte block is real (the defects
  found are the *unimplemented* multi-block/AEAD paths and their *doc claims*,
  R3-13/R3-34/R3-35 — not an arithmetic bug in what is implemented).
- **The `shared_ecdhe` share math** (`session.rs:57-70`) is correct:
  `share1 + share2 = x_pub·s = z_server` and neither share alone reveals `Z`, so the
  masking claim holds within the in-process model.

**The honesty of the 2PC boundary claims — mostly holds, with named exceptions.**
`mpc_tls.rs` carries a prominent **"## Honest boundary"** section (`:30-46`) that
correctly defers full malicious security to WRK17, flags the ≤1-bit dual-execution
leak, names EC share conversion and live wiring as unimplemented DECO steps, and
gates everything behind the external audit. `dualex.rs:14-15` says "Modelled
in-process". `session.rs:20-23` says the parties are "modelled as in-process
functions". `earn.rs:14-25` is candid that receipts are client-attested and
collusion can fabricate them. Sphinx (`sphinx.rs:116-131,270-273`) honestly labels
its replay horizon and non-malleability residuals. **The exceptions where the
honesty bar is breached are exactly the overclaims in §8** — chiefly the "stock
ChaCha20-Poly1305 AEAD" claim (R3-13), the dual-execution "catches a cheating
garbler" framing applied to a test-only module (R3-12), the Shamir
information-theoretic claim (R3-25), the REALITY indistinguishability/no-forgery
claims (falsified by R3-01/R3-03/R3-43), and the circuit cell "same guarantee"
claim (R3-44). With those specific lines corrected, the 2PC stack's self-description
becomes accurate: **a working, in-process, semi-honest-modelled prototype that does
not yet resist a malicious peer and is not wired into a live network** — which is a
defensible and honest position for unaudited code.

**Sphinx onion routing (crypto core).** The Lioness wide-block SPRP genuinely
prevents a chosen readable-pattern mauling (avalanche test `sphinx.rs:622-644`); the
replay cache correctly rejects within its (documented) horizon; header MACs are
checked before any expensive point ops. The residuals (R3-28/R3-29/R3-52) are
honest, documented, LOW/INFO correlation/margin notes — not breaks.

**VOPRF credit unlinkability and redemption soundness.** The *cryptographic* core is
sound: verifiable mode forces one published key so a spend cannot be key-tagged back
to an earner (`lib.rs:13-17`), the DLEQ proof is checked on finalize, `redeem()`
recomputation is authoritative for issuer==verifier (R3-55), and double-spend
rejection works. The credit *system* failures (R3-02/R3-05/R3-16/R3-17) are all in
the **earning/issuance plumbing and lifecycle**, not in the OPRF math.

**Committee VSS (the AEAD-wrapped path).** `vss.rs` correctly wraps its body in
ChaCha20Poly1305 (`:99-102,185-189`), the DLEQ partial-decryption proofs authenticate
each partial against the committed share, and honest-flow commitments are random
non-identity points. The threshold-decryption defects (R3-14/R3-15) are confined to
the *hashed-ElGamal outer layer* and its `pub`-API foot-guns, not the VSS core.

**Core identity binding.** No record can be published under another node's id
(`from_keys` binds signing/kex/kem, the signature gates the body), `sphinx_shared`
rejects the identity point, and the VRF path selection actually used by the system
(`select_path_seeded`) uses full-width rejection sampling with no modulo bias. The
routing-key binding gap (R3-57) and the unused `selection_index` bias (R3-42) are
documentation/dead-code nits with no exploit.

**One RNG/panic sweep note.** `neo-credits` and several crates carry
`#![forbid(unsafe_code)]`; the reviewed hot paths use `getrandom`/`OsRng`
consistently and the one RNG-failure fallback that degrades silently (R3-46) is
honestly documented as such. No memory-safety or panic-on-attacker-input issue was
found in the reviewed data-plane paths beyond the resource-exhaustion items already
listed (R3-48/R3-49).

---

## 8. Overclaims in docs/comments — exact honest wording to use

The project prizes honesty; these are the specific lines that currently claim more
than the code delivers, with the precise replacement wording.

| Where | Current claim | Honest replacement |
|-------|---------------|--------------------|
| `reality.rs:6-8,21` | "indistinguishable from random"; "a prober cannot reach the authenticated branch" | After R3-01/R3-03 land, restore. Until then: "The authenticator is uniform to anyone without the capability, **but** the current wire framing is a fixed-length, u32-prefixed blob (not TLS-embedded) and **classify() does not yet reject low-order ephemeral points** — see the honesty note; a prober can currently forge Authenticated via a low-order point." |
| `neo-transport/src/lib.rs:233` (`dial_reality`) | "To a censor the flight is indistinguishable from random." | "The authenticator bytes are uniform to anyone without the capability; the wire framing is NOT yet TLS-embedded and is fingerprintable (fixed length, cleartext u32 prefix) — see the module honesty note." |
| `neo-transport/src/lib.rs:9-11,149-151` | Camouflage "sees a familiar protocol, not neo" | "Camouflage imitates only coarse header bytes and datagram sizing and is NOT expected to fool a protocol-aware classifier. A cleartext inner length field and a TCP length prefix (absent from real UDP QUIC/DTLS) remain observable." |
| `mpc_tls/session.rs:19,148-149` | "ChaCha20-Poly1305 AEAD under 2PC"; "verifies against a stock ChaCha20-Poly1305 implementation" | "Produces a single-block Poly1305 tag over the ciphertext; this is NOT the RFC 8439 AEAD tag (AAD and the `le64` length block are unimplemented) and will not verify against a stock AEAD implementation." |
| `mpc_tls.rs:36-38` + component list `:27-28` | "dual-execution here catches a cheating garbler" | "Dual-execution is a standalone/demonstration component; the shipped session gadgets are semi-honest only and are NOT routed through dual-execution. A cheating garbler in the session path is not currently detected." |
| `mpc_tls.rs:8-9` | "neither alone holds the traffic key or can read/forge a record" | "such that, **against a semi-honest peer**, neither alone holds the traffic key or can read/forge a record (see the Honest boundary for malicious-model gaps)." |
| `mpc_tls/dualex.rs:14-15` | in-process check "reveal[s] only the equal/not-equal bit" | "This in-process comparison models the value check; the ≤1-bit bound holds only when `check_pass` is wrapped in a committed/simultaneous secure-equality subprotocol, which is not implemented here." |
| `mpc_tls/poly1305.rs:15,186` | multi-block Poly1305 (Horner) | "Single 16-byte block only; multi-block Horner iteration is NOT implemented (`tag_shared` takes one `[u8;16]` block and adds `s` inside the per-block circuit)." |
| `neo-mpc/src/lib.rs:8-15,152` | "Shamir's information-theoretic guarantee, not a computational assumption"; "Any threshold-1 of them reveal nothing." | Until sharks is replaced: "The **shipped** `sharks 0.5.0` biases the top polynomial coefficient (RUSTSEC-2024-0398), so below-threshold coalitions get a small statistical advantage; the information-theoretic guarantee holds only for a bias-free Shamir implementation." |
| `threshold.rs:1-24` + `neo-mpc/src/lib.rs:19-27` | threshold decryption is "verifiable" / "a real, verifiable building block" | Add: "Verifiability here means each partial is DLEQ-proved consistent with its committed share. The ciphertext `(R,c)` is **NOT authenticated** (stream-cipher malleable), and `encrypt()` assumes a committee-generated, non-identity joint key. An AEAD/MAC wrapper is required for end-to-end integrity." |
| `neo-credits/src/lib.rs:19-21` | "Earning a credit costs real relayed bandwidth … against both Sybil attacks and free-riding" | Until R3-02 is wired: "**Note:** `issue()` does not currently verify earnings — issuance is decoupled from `earn.rs`, so this Sybil/free-rider guarantee is NOT yet enforced by the API." |
| `neo-credits/src/earn.rs:22-25` | "the issuer sees the earning relay and can rate-limit or blocklist it" | "Earning is identified in principle, but `issue()` does not currently receive the relay identity, so the issuer cannot yet see or rate-limit the earning relay at issuance time." |
| `neo-node/src/circuit.rs:22-25` | cell integrity is "the same guarantee the forward Sphinx payload … already ha[s]" | "The per-cell MAC gives per-cell tamper-detection only. Unlike Sphinx forward payloads (replay-once) and the one-shot return path, cells are **NOT** replay/reorder/drop protected end to end; stream ordering and uniqueness must be enforced by a higher layer." |
| `neo-discovery/src/snapshot.rs:31-34,117-126` | skew cap bounds "the anti-rollback high-water mark"; verify reasons about a persisted high-water mark | "`verify()` enforces expiry and a future-skew cap **only**. Anti-rollback requires a client (not yet implemented) to persist and pass a high-water mark; `MAX_FUTURE_SKEW` is a forward-looking guard for that future caller." |
| `neo-slicing/src/lib.rs:68-71,216-219` | corrupt shards are "attributable by index" | "Corrupt shards are detected by MAC and dropped as erasures (Reed-Solomon routes around them). The failing index is **not** currently surfaced to the caller — no per-index attribution is exposed." |
| `neo-verify/src/selection.rs:5-8` | "neither can bias the result" | "Neither party can bias the result **for a fixed commitment**. Abort-and-retry biasing by the beacon (drawing fresh i.i.d. samples across aborted round trips) is **NOT** prevented by this construction and is out of scope of this guarantee." |
| `neo-verify/src/vrf.rs:1-7` | `selection_index` is "verifiably fair" | Either delete `selection_index` (unused), or: "`selection_index` uses a truncated modulo reduction with residual bias and is retained only for reference; live selection uses `select_path_seeded` (full-width rejection sampling)." |
| `neo-core/src/identity.rs:43` | NodeId is "BLAKE3 over the public keys" (implying all of them) | "NodeId is BLAKE3 over the signing, KEX, and KEM public keys. The Ristretto routing (Sphinx) key is **not** in the id hash; it is authenticated by the record signature." |
| `handshake.rs:45-51` | "stateless" cookie | "The cookie keeps no cross-connection lookup table (verification is recomputed), but the production driver holds per-connection state for a full RTT and the cookie is **not** source-address-bound: over TCP it only gates ML-KEM work behind an already-established connection and gives no anti-spoofing/amplification guarantee." |

Honest claims deliberately **not** flagged (they held up on reading): the Sphinx
replay-horizon and non-malleability residual notes (`sphinx.rs:116-131,270-273`), the
`mpc_tls.rs` "## Honest boundary" section as a whole, `dualex.rs`/`session.rs`
"modelled in-process" disclaimers, `earn.rs:14-25` receipt-attestation candor,
`neo-mix:131-136` RNG-degradation note, and `bootstrap.rs:12-13` "DoH transport lives
in the CLI". These are examples of the honesty standard the flagged lines should meet.
