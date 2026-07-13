# neo — threat model (draft)

> Draft. Sharpen alongside each milestone; this is a living document, not a guarantee.

## Adversaries considered

| Adversary | Capability | neo's answer | Honest limit |
|-----------|-----------|--------------|--------------|
| Local network / ISP | sees your link, does DPI | everything encrypted; transport mimics mainstream TLS/QUIC | traffic *volume* still observable |
| On-path censor | blocks by IP/SNI/protocol, active probing | decentralized DoH rendezvous; obfuscation ladder; REALITY-style authenticate/decoy split (M23) | full-session TLS indistinguishability still open — the auth path sends no ServerHello (M27) |
| Colluding relays | run several nodes on your path | k-of-n slicing: fewer than k shares reveal nothing; onion layering | collusion ≥ k on one request's paths degrades it |
| Global passive observer | watches all links at once | cover traffic + Poisson timing mixing (M5) | costs latency/bandwidth; imperfect at tiny scale |
| Malicious exit | inspects/tampers with clearnet traffic | fresh per-request exits (M7); committee exit + threshold-decrypt (M12/M28); malicious-secure 2PC-TLS crypto stack (M24), live against a real TLS 1.3 server (M45) | plaintext to a clearnet site is inherently visible to *some* egress; all audit-gated |
| Sybil attacker | floods fake nodes to map/deanonymize | bandwidth credits make identities costly (M10); VRF paths (M11) | open problem; residual risk during bootstrap |
| Quantum "harvest now" | records today, decrypts later | PQ-hybrid handshake + onion packets from day one | depends on PQ primitive assumptions |

## Explicit non-goals (v1)

- Defeating a censor willing to accept large collateral damage (allowlist-only, whole-protocol bans).
- Hiding *that* a clearnet connection happened from the destination server.
- Endpoint security (a compromised device is out of scope).
- Formal, proven anonymity bounds.

## Simulated adversaries (tested)

Properties asserted by tests today across `neo-crypto`, `neo-slicing`, `neo-node`, `neo-discovery`,
`neo-verify`, and `neo-mpc`:

- **Colluding relays below threshold learn nothing** — fewer than `k` shares cannot reconstruct a
  sliced flow; a corrupt shard is detected (per-share MAC), attributed, and routed around.
- **A single relay learns only the next hop** — never the payload; it cannot peel a deeper layer, and
  a **tampered payload avalanches** (Lioness wide-block) so no chosen pattern can be imprinted.
- **An on-path observer sees only ciphertext** — sealed session frames never contain plaintext; the
  handshake is key-confirmed so a replayed m1 never establishes a session.
- **Forged discovery data is rejected** — records are self-certifying + signed; snapshots need k-of-n
  witnesses and cannot be rolled back; the DHT verifies inbound records.
- **A verifiable shuffle is sound and zero-knowledge**, and a committee minority cannot open a request.
- **Global-passive-observer timing sim** — mixing (wired into the live tunnel data plane) decorrelates
  output order from input order.
- **Fuzz-lite / no-panic-on-garbage** parsers, plus `fuzz/` cargo-fuzz targets for the wire formats.

The full adversarial internal review — every finding across all rounds (including two PoC-confirmed
CRITICAL Sphinx breaks, now fixed) with its fix — is in [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md).

Still ahead: REALITY **full-session** indistinguishability (the auth path completes only the ClientHello
— M27); and — the hard gate — the **external security + cryptography audit**. (Live MPC-TLS against a real
server landed in M45 — interop-verified against stock `rustls`, both semi-honest and malicious engines.)
