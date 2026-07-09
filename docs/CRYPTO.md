# neo — cryptography notes

> **Not audited.** Do not rely on any of this for real safety until the external audit gate.
> Rule: no home-rolled primitives — vetted crates and established constructions only. The one
> composed construction (Lioness wide-block payload) is built from vetted primitives (a stream cipher
> + keyed hash), not a new cipher.

## Primitives

- Signatures: **Ed25519** (`ed25519-dalek`), always `verify_strict`.
- Classical KEX: **X25519** (`x25519-dalek`).
- Post-quantum KEM: **ML-KEM-768** (`ml-kem`), combined with X25519 as a **hybrid** — secure if
  *either* component holds (defense against harvest-now-decrypt-later).
- AEAD: **ChaCha20-Poly1305** (RustCrypto).
- Hash / KDF / XOF / keyed-MAC: **BLAKE3**; **HKDF-SHA256** for handshake key derivation.
- Group for Sphinx / VRF / commitments: **Ristretto** (`curve25519-dalek`); **schnorrkel** VRF;
  **VOPRF** over Ristretto255 for credits.

## Node identity

`NodeIdentity` = Ed25519 signing + X25519 KEX + ML-KEM-768 KEM keys, plus a Ristretto routing key for
Sphinx derived from the signing seed (never stored separately). The self-certifying
`NodeId = BLAKE3("neo-node-id-v1" ‖ signing_pub ‖ kex_pub ‖ kem_pub)` — so a record's keys can always
be checked against the id it claims. Secret seeds/ephemerals and session keys are zeroized on drop.

## Handshake (M1, hardened in M14)

A **3-message, key-confirmed** PQ-hybrid AKE (`neo-crypto::handshake`):

- m1/m2 carry ephemeral X25519 + ML-KEM keys and each party's **full** long-term key set, signed;
  session keys = `HKDF(x25519_dh ‖ mlkem_ss, transcript)`.
- The **full `NodeId`** (all three keys) is bound into the signed transcript and returned, so a
  handshake authenticates the exact self-certifying identity (no unknown-key-share).
- m3 is a **key-confirmation** MAC: the responder establishes no session and sends no data until the
  initiator proves it derived the same key — so a replayed/forged m1 never yields a confirmed session.
- A **stateless retry cookie** precedes the ML-KEM work: the responder issues a cheap MAC (keyed by a
  per-connection ephemeral secret) that the initiator must echo before any encapsulation, so a
  replayed or connect-and-abandon m1 costs only a MAC — with no cross-connection responder state.
- The record layer is per-direction ChaCha20-Poly1305 with a strictly monotonic counter nonce
  (no reuse) and replay rejection.

## Higher-level constructions

- **Sphinx onion packets** (`neo-crypto::sphinx`) — fixed-size, per-hop blinded, filler-padded, with a
  per-hop header MAC and an **exit-verified, wide-block (Lioness) payload** so any payload tamper
  avalanches the whole block (no tagging channel). Replay tags are recorded only after authentication.
- **Encrypt-then-slice** k-of-n (`neo-slicing`) — AEAD-encrypt, Reed-Solomon erasure-code, with a
  **per-share MAC** so a corrupt shard is detected, attributed, and routed around. Secrecy is
  *computational* (rests on the AEAD key), not Shamir-information-theoretic — stated plainly in-crate.
- **Anonymous credits** (`neo-credits`) — VOPRF (Privacy Pass) unlinkable tokens; earning is bound to
  client-attested proof-of-relay receipts.
- **Committee exit** (`neo-mpc`) — threshold secret-sharing of the request, and **Feldman-verifiable**
  sharing of a session key so a minority learns nothing and a bad share is attributable.
- **Verifiable privacy** (`neo-verify`) — schnorrkel VRF + a commit-then-VRF unbiasable path seed;
  2-server PIR + keyword oblivious lookup; and a **ZK verifiable shuffle** (grand-product multiset
  equality over Pedersen commitments, Fiat–Shamir) that hides the permutation.

## Outstanding

- Full **MPC-TLS** (compute the TLS session under MPC so plaintext is never assembled) and a
  **succinct** ZK shuffle are research; the current constructions are honest, tested cores.
- The **external cryptography audit** is the hard gate before real-world use.
