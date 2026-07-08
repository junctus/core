# neo — cryptography notes (draft)

> Draft. **Not reviewed, not audited.** Do not rely on any of this for real safety yet.
> Rule: no home-rolled primitives — use vetted crates and established formats.

## Primitives (classical)

- Signatures: **Ed25519** (`ed25519-dalek`).
- Key exchange: **X25519** (`x25519-dalek`).
- AEAD: **ChaCha20-Poly1305 / XChaCha20-Poly1305** (RustCrypto).
- Hash / KDF: **BLAKE3**, **HKDF**.

## Post-quantum (from day one)

- KEM: **ML-KEM-768** (`ml-kem`), combined with X25519 as a **hybrid** KEM (defense in depth; secure
  if *either* component holds). Guards against harvest-now-decrypt-later.
- No turnkey PQ-Noise / PQ-Sphinx exists yet, so expect a custom/forked handshake and packet variant
  (Nym's "Outfox" is the reference direction).

## Node identity

`NodeIdentity` = Ed25519 signing + X25519 KEX + ML-KEM-768 KEM keys, plus a Ristretto routing key
(for Sphinx) derived from the signing seed (never stored separately). `NodeId` =
`BLAKE3("neo-node-id-v1" ‖ signing_pub ‖ kex_pub ‖ kem_pub)` — self-certifying and stable.

## Higher-level constructions

- **Onion / Sphinx packets** for multi-hop unlinkability (`neo-crypto`).
- **Encrypt-then-slice** k-of-n so shares are individually meaningless (`neo-slicing`).
- **Anonymous credentials / blind signatures** for bandwidth credits (`neo-credits`).
- **MPC-TLS** for the committee exit (`neo-mpc`).
- **VRF, PIR, ZK verifiable shuffle** for verifiable privacy (`neo-verify`).

## Outstanding

- Secret buffers (seeds, ephemerals) and session keys are zeroized on drop; a full audit of every
  secret's lifetime still remains.
- External cryptography audit is a hard gate before real-world use.
