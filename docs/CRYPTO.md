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
- **Anonymous credits** (`neo-credits`) — **verifiable** VOPRF (Privacy Pass) unlinkable tokens: the
  issuer publishes a committed key and proves each blind evaluation with a **DLEQ proof**, so it cannot
  key-tag earners to de-anonymize spends. Earning is bound to client-attested proof-of-relay receipts,
  each capped so one receipt cannot mint an implausible number of credits.
- **Committee exit** (`neo-mpc`) — threshold secret-sharing of the request; **Feldman-verifiable**
  sharing of a session key (minority learns nothing, a bad share is attributable); and **threshold
  decryption** (`neo-mpc::threshold`) where a message to the committee's joint key is decrypted by
  **client-combined, DLEQ-proved partials** via Lagrange-in-the-exponent — so **no committee node ever
  assembles the key or plaintext** (for the decrypt direction).
- **Two-party MPC-TLS** (`neo-mpc::mpc_tls`) — the real 2PC stack, built and tested bottom-up:
  Chou–Orlandi **oblivious transfer** + **IKNP OT extension** + **KOS maliciously-secure OT extension**
  (`kos`: IKNP plus a `GF(2¹²⁸)` correlation check that **aborts on a cheating receiver**; the
  malicious-security path runs its OT over it); a **garbled-circuit** engine (free-XOR +
  point-and-permute + ZRE15 half-gates); **ChaCha20**, **SHA-256**, and **Poly1305** as boolean circuits
  (each verified against its RFC/NIST KAT); a DECO-style **additively-shared ECDHE**; and — computed
  **under 2PC into XOR-shares** — the ChaCha keystream, the SHA-256 key schedule, the Poly1305 tag, and an
  end-to-end **ChaCha20-Poly1305 record**, so the record key, keystream, and plaintext are **never
  assembled at any one party**. **dualex** adds a dual-execution check that catches a cheating garbler.
  The **DECO EC point→field conversion** (`ectf`, Gilboa MtA over `F_p` + masked inversion, validated against
  the vetted `p256` crate) and the **WRK17 authenticated-share core** (`wrk17`: IT-MAC shares, OT-generated
  `aAND` triples, MAC-checked authenticated evaluation that aborts on tamper) are both built and tested — the
  latter a malicious-*detection* layer, both now running their OT over `kos` (so the aBit/MtA/triple OTs
  abort on a cheating receiver). Semi-honest / malicious-detecting core; see Outstanding for the remaining
  hardening (malicious triple generation, an MtA consistency check, and the audit gate).
- **Persistent circuit tunnels** (`neo-node::circuit`) — a long-lived Sphinx circuit carrying a
  bidirectional byte stream as **counter-keyed onion cells** (no keystream reuse) with a **per-cell
  end-to-end MAC**, and a real **TCP splice** at the exit — TCP-over-onion, integrity to parity with the
  forward path.
- **Probe-resistant transport** (`neo-crypto::reality`, `neo-transport`) — a **REALITY-style**
  authenticator (uniform-random to anyone without the pre-shared server key, epoch-bound) driving a
  silent **authenticate/decoy** split, plus **QUIC/MASQUE** and **WebRTC/DTLS** shape camouflage.
- **Verifiable privacy** (`neo-verify`) — schnorrkel VRF + a commit-then-VRF unbiasable path seed;
  2-server PIR + keyword oblivious lookup; and a **ZK verifiable shuffle** (grand-product multiset
  equality over Pedersen commitments, Fiat–Shamir) that hides the permutation.

## Outstanding

- **Two-party MPC-TLS** runs the **full ChaCha20-Poly1305 AEAD and SHA-256 key schedule under 2PC**
  (`neo-mpc::mpc_tls`), semi-honest, with OT extension and a dual-execution cheating-garbler check. Both of
  the deferred sub-protocols are now built and tested (still semi-honest / malicious-*detecting*):
  ✅ the **full RFC 8439 AEAD** (multi-block Poly1305, matched byte-for-byte against the stock crate) and
  ✅ **TLS 1.3 record framing** (nonce/AAD/content-type, a real `TLSCiphertext`);
  ✅ the **DECO EC point→field conversion** — `ectf::ectf` composes **Gilboa MtA over `F_p`** (on the crate's
  real OT) and a masked inversion into an additive x-coordinate share, its test **validated against P-256
  point addition from the vetted `p256` crate**; its A2B partner (`convert::a2b_shared`) closes the point→bit
  bridge;
  ✅ the **WRK17 authenticated-share core** (`wrk17`) — TinyOT-style IT-MAC shares, **OT-generated `aAND`
  triples**, an authenticated circuit evaluation whose every open is **MAC-checked** so any tampered wire
  **aborts**, plus the **sacrifice check** — a real, tested malicious-*detection* layer (verified against a
  4-bit adder and by tamper-abort tests);
  ✅ the **KOS maliciously-secure OT extension** (`kos`) — IKNP plus a `GF(2¹²⁸)` correlation check that
  **aborts on a cheating receiver** (tested); ECtF's MtA and WRK17's aBit/triple OTs now run over it, closing
  the OT layer's selective-failure channel (the aBit consistency check);
  ✅ WRK17's **bucketing / leakage removal** (`wrk17::combine` + `bucketed_triples`) — the real WRK17 combine
  (open `y1⊕y2`, fold to `(⟨x1⊕x2⟩,⟨y1⟩,⟨z1⊕z2⊕d·x2⟩)`) over random buckets; combine verified exhaustively.
  What remains before **end-to-end malicious** security: the exact WRK17 **leaky-AND hash** primitive (bounds
  the selective failure to one bit — its *security* is not test-establishable, so not shipped as verified), an
  **MtA consistency check** for ECtF, WRK17's **constant-round garbled online** + formal proof, and the
  **external audit** — until then the live session path still carries dual-execution's ≤1-bit leak. Also open:
  **live wiring** to a real TLS socket, a constant-time `F_p` for ECtF, and a **succinct** ZK shuffle. Honest,
  tested cores.
- **Wire-level transport integration** — wiring the REALITY decoy to a genuine upstream TLS site and
  embedding the flight in a true TLS ClientHello; `Camouflage` today mimics observable shape, not full
  QUIC/DTLS protocol crypto (a real QUIC transport lives behind the `quic` feature).
- The **external cryptography audit** is the hard gate before real-world use.
