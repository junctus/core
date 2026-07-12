# Security review 4 — full-codebase pass

A whole-codebase security review (~25k LOC, 16 crates) run as a multi-agent workflow:
ten domains each deep-reviewed against the neo threat model, then **every** critical/high
finding independently **adversarially verified** (a second reviewer tried to refute it from
the source) before it counted. This filters false positives — two high-severity claims were
correctly refuted and are *not* bugs.

**Result: 8 real findings — 2 critical, 3 high, 3 medium/low — all fixed.** The cryptographic
core, MPC/committee, credit economy, and routing/verifiable-selection domains came back clean.

Threat actors assumed: a malicious relay/exit on the path; a malicious or coerced seed/witness;
an active network adversary/censor; a malicious peer sending hostile wire input; a colluding
sub-threshold set of committee members.

## Fixed

| # | Sev | Finding | Fix | Commit |
|---|-----|---------|-----|--------|
| 1 | 🔴 Critical | **IPv4-mapped IPv6 bypassed the SSRF guard.** `is_internal_ip`'s V6 branch didn't classify mapped/compatible addresses, so a dial-back or exit target like `[::ffff:127.0.0.1]` or `[::ffff:169.254.169.254]` (cloud metadata) was treated as *public*. | V6 branch recurses on `to_ipv4()`; `is_safe_dial_target` normalizes mapped-loopback for the `allow_loopback` opt-in. Tests cover mapped loopback/RFC1918/metadata. | `1c46192` |
| 2 | 🔴 Critical | **Circuit sequence-number overflow → keystream reuse.** Cell `seq` used unchecked `+= 1`. The `(key, seq)` pair drives a one-time XOR keystream; on a `u64` wrap the keystream repeats and an observer can XOR two cells to recover plaintext. (Unreachable at `u64` in practice, but the guarantee was conditional.) | All six increment sites (`CircuitSink::send`, `CircuitStream::recv`, `exit_splice` ×2, `exit_splice_udp` ×2) now `checked_add` and error on overflow. | `1c46192` |
| 3 | 🟠 High | **Exit was an open proxy.** `exit_splice`/`exit_splice_udp` enforced only the SSRF guard, not any port policy — an exit would relay to SMTP:25 (spam), SSH:22, plaintext DNS:53, etc. — the abuse that deters exit operators. | `ExitPolicy::permits_port` + a reduced-harm `DENIED_EXIT_PORTS` baseline (mail / remote-login / file-share / plaintext DNS), enforced in both splice paths. (Full configurable/allowlist policy is M31.) | `c5e9576` |
| 4 | 🟠 High | **Registration rate-limit stamped before validation.** The per-IP cooldown was recorded before the body was parsed or the PoW verified, so a malformed / no-PoW request from a shared source IP (NAT / the fronting proxy) could burn an honest relay's quota. | Reordered: parse + PoW-verify first; spend rate-limit quota only on a well-formed, PoW-valid request. | `c5e9576` |
| 5 | 🟠 High | **Identity secret bytes not zeroized.** `NodeIdentity::to_bytes()` returned a plain `Vec` of raw secret key material that lingered in freed heap (e.g. after being written to disk). | Returns `zeroize::Zeroizing<Vec<u8>>`, wiped on drop; the unavoidable FFI-boundary copy is documented. | `c5e9576` |
| 6 | 🟡 Medium | **Committee sealed-partial keystream not zeroized** (`xor_mask`). It is as sensitive as the partial it masks. | Wiped before return (neo-node gains the `zeroize` dep). | `18f90c0` |
| 7 | 🟡 Medium | **TLS ClientHello `server_name` cast to `u16` unclamped** — a pathologically long SNI could truncate a length field and emit a malformed hello. | Clamp to the 253-byte DNS-name maximum. | `18f90c0` |
| 8 | 🟡 Low/dep | **`sharks 0.5.0` — RUSTSEC-2024-0398** (unmaintained; biased GF(256) coefficients weaken Shamir's information-theoretic secrecy) backed `neo-mpc`'s request split. | Migrated to the maintained, bias-free `blahaj` fork — a drop-in (56 tests pass). The secrecy caveat is now actually satisfied. | `18f90c0` |

## Refuted (verified as *not* bugs)

- **"Middle relay can't enforce cell sequencing on the forward path."** By design — sequencing is
  an *endpoint* property (the exit and client enforce strict in-order delivery with a per-cell
  end-to-end MAC). A middle relay dropping/reordering is indistinguishable from network loss and
  cannot forge or read cells; enforcing seq at the middle would buy nothing.
- **"FFI mutex-poisoning panic."** The spawned FFI tasks don't hold the mutexes across `.await`,
  so a panic can't poison them; the lock scopes are non-panicking.

## Clean domains

The reviewers found no exploitable issues in: the **cryptographic core** (PQ-hybrid AKE with
transcript binding; `verify_strict` Ed25519; HKDF domain separation; monotonic-counter AEAD with
overflow check; Sphinx per-hop MACs + replay tags + identity-point rejection; the REALITY replay
cache); **MPC/committee** (canonical-scalar enforcement, non-panicking deserialization, sound
Chaum-Pedersen DLEQ / NonCustodyProof, sealed-partial return path a relaying member can't open);
the **credit economy** (VOPRF double-spend set, DLEQ one-key unlinkability, issuance gating); and
**routing / verifiable selection** (VRF soundness, commit-then-VRF unbiasability, node-disjoint
multipaths, the M36 subnet-diversity reorder).

## Accepted boundaries (already documented, not new bugs)

The review re-confirmed the honest limits the code already states, and they remain the standing
work items — they are *known*, not silently present:

- **DKG is crash-fault-tolerant, not Byzantine-tolerant.** A member reporting inconsistent
  qualified-set views to different peers can split honest members onto different keys (circuits
  fail — a liveness, not a secrecy, regression). Needs a broadcast/agreement primitive.
- **M27 REALITY is not full-session-indistinguishable.** The authenticated path doesn't complete
  a real TLS handshake, and the fingerprint is one fixed non-browser profile (see `MILESTONES.md`
  M27).
- **Proof-of-relay receipts are client-attested / forgeable** (`neo-credits::earn`); credits stay
  anti-free-riding utility, and no cash value attaches until this is hardened (see
  `MONETIZATION.md`, `MILESTONES.md` M32/M36).

## Process notes

- **`cargo-audit` is not installed** in the dev/CI environment. Add `cargo audit` (and
  `cargo deny`) to CI so dependency advisories like RUSTSEC-2024-0398 are caught automatically —
  this pass found it by manual dependency inspection.
- `#![forbid(unsafe_code)]` covers 13 crates; the two that can't (`neo-ffi`, `neo-netstack`) plus
  the three explicit `unsafe` sites (`netif.rs`, `committee.rs`, `main.rs`) were reviewed and are
  sound.
- **Nothing here changes the standing rule: neo is unaudited and must not be relied on for
  real-world safety until the external audit gate** (`MILESTONES.md`). This internal review raises
  the floor; it is not that audit.

_Reviewed at `18f90c0`. Full workspace green (`cargo test --workspace`, `clippy -D warnings`, `fmt`)._
