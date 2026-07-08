# neo — threat model (draft)

> Draft. Sharpen alongside each milestone; this is a living document, not a guarantee.

## Adversaries considered

| Adversary | Capability | neo's answer | Honest limit |
|-----------|-----------|--------------|--------------|
| Local network / ISP | sees your link, does DPI | everything encrypted; transport mimics mainstream TLS/QUIC | traffic *volume* still observable |
| On-path censor | blocks by IP/SNI/protocol, active probing | decentralized DoH rendezvous; obfuscation ladder | REALITY-grade active-probe defense deferred (M6+) |
| Colluding relays | run several nodes on your path | k-of-n slicing: fewer than k shares reveal nothing; onion layering | collusion ≥ k on one request's paths degrades it |
| Global passive observer | watches all links at once | cover traffic + Poisson timing mixing (M5) | costs latency/bandwidth; imperfect at tiny scale |
| Malicious exit | inspects/tamperss with clearnet traffic | fresh per-request exits (M7); MPC-TLS committee (M12) | plaintext to a clearnet site is inherently visible to *some* egress |
| Sybil attacker | floods fake nodes to map/deanonymize | bandwidth credits make identities costly (M10); VRF paths (M11) | open problem; residual risk during bootstrap |
| Quantum "harvest now" | records today, decrypts later | PQ-hybrid handshake + onion packets from day one | depends on PQ primitive assumptions |

## Explicit non-goals (v1)

- Defeating a censor willing to accept large collateral damage (allowlist-only, whole-protocol bans).
- Hiding *that* a clearnet connection happened from the destination server.
- Endpoint security (a compromised device is out of scope).
- Formal, proven anonymity bounds.
