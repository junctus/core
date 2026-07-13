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
  The **malicious-secure 2PC stack is complete and tested**: the **DECO EC point→pre-master conversion**
  (`ectf`, Gilboa MtA over a **constant-time** `F_p` + masked inversion → `convert::a2b_shared` → the SHA-256
  key schedule, validated against the vetted `p256` + NIST-KAT SHA-256); **KOS maliciously-secure OT** (`kos`);
  the complete **WRK17/KRRW18 malicious 2PC** — malicious `F_pre` (`leaky_and` + bucketing) feeding
  **constant-round authenticated garbling** (`authgarble`, where a corrupted garbled row aborts — exercised on
  the **full SHA-256 compression circuit**, >10k ANDs, not just a toy adder); the **TLS 1.3 key schedule**
  (`hkdf`, matched to the vetted `hmac`/`hkdf` crates); and **SPDZ** authenticated arithmetic (`spdz`) for the
  field path, with `ectf_beaver` running ECtF's point addition over authenticated Beaver. Every layer's abort
  mechanism is tested, and the constructions were **adversarially verified against the published specs**. The formal malicious-security proofs and the
  **external audit** are the security gate, as everywhere in neo.
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

- **Two-party MPC-TLS — crypto stack complete** (audit-gated, as all of neo). The full ChaCha20-Poly1305
  AEAD + TLS 1.3 record framing under 2PC; the DECO **EC point→pre-master** conversion (`ectf` over a
  constant-time `F_p` → A2B → the SHA-256 key schedule end-to-end, validated against `p256`/NIST); the **TLS
  1.3 key schedule** (`hkdf`, matched to the vetted `hmac`/`hkdf` crates); and the complete **WRK17/KRRW18
  malicious 2PC** — malicious OT (`kos`) → malicious `F_pre` (leaky-AND + bucketing) → constant-round
  authenticated garbling (`authgarble`) — plus **SPDZ** authenticated arithmetic (`spdz`) for the field path.
  The authenticated garbling online is exercised on a **real TLS key-schedule circuit** (the full SHA-256
  compression, >10k ANDs — matches the plaintext oracle, aborts on a tampered wire), and `spdz::ectf_beaver`
  runs ECtF's point-addition arithmetic over authenticated Beaver shares (MAC-checked, validated against
  `p256`, aborts on a tampered triple). Every layer's abort mechanism is tested and the constructions were
  **adversarially verified against the published specs**. The stack now **runs live** (`mpc_tls::live`): a
  real TLS 1.3 client state machine drives split-scalar **P-256 ECDHE** → the full **RFC 8446 §7.1 key
  schedule under 2PC** → the record layer (2PC seal **and** open) against an actual server, and is
  **interop-tested against a stock `rustls` TLS 1.3 server** (`TLS_CHACHA20_POLY1305_SHA256`) — the two 2PC
  parties complete a handshake and exchange application data, with rustls verifying the client side and the
  client verifying the server Finished + CertificateVerify. The live session is **engine-selectable**
  (`EngineKind`): the whole thing — key schedule + every record — also runs under the **malicious
  authenticated-garbling online** (`client_handshake_with_engine`); the malicious key schedule is tested to
  match the stock RFC 8446 schedule and a malicious record round-trips (the full malicious handshake is an
  ignored ~15-min interop test). The **networked preprocessing is built end to end** (`mpc_tls::netprep` +
  `kos::cot_sender`/`cot_receiver`): the full TinyOT `F_pre` — malicious KOS-COT authenticated bits →
  distributed shares with a MAC-checked open → authenticated AND triples (cross-term OTs) → the sacrifice
  check → bucketing — runs as a genuine two-party protocol over a `Channel`, **tested over real TCP sockets**
  (honest triples satisfy `c=a∧b`; cheating-receiver, IT-MAC-forgery, and corrupted-triple aborts), and a
  **complete two-party malicious 2PC runs with no in-process modelling** — `netprep::eval_authenticated`
  evaluates a boolean circuit under the distributed shares (XOR/NOT local, each AND a networked Beaver open),
  including the **actual SHA-256 key-schedule circuit** (67k ANDs, via networked input-sharing → F_pre →
  online), TCP-tested to reproduce the plaintext and abort on a forged-MAC open. **KeyUpdate** (RFC 8446 §7.2)
  is implemented + interop-tested against rustls, and the CertificateVerify leaf key is extracted by a proper
  DER `SubjectPublicKeyInfo` parse (OID-validated). What remains is **not crypto-primitive work**: the
  **external audit** (the hard gate) + the formal proofs; routing the *live-TLS record/key-schedule* gadgets
  through this networked engine (they use the bundled in-process online today — a performance question, since
  the interactive online is one round-trip per AND); full **X.509 chain-building** (a caller-supplied
  `webpki`/platform verifier); **AES-GCM / x25519** (each a new 2PC primitive, not hardening); plus the malicious
  ECtF-triple generation (MASCOT `sacrifice`; the arithmetic already runs over authenticated shares); live-TLS
  **hardening** (full X.509 chain-building, other ciphersuites/curves, KeyUpdate); and the KOS **Roy22** fix
  (it ships original
  KOS15). A **succinct** ZK shuffle is separate research.
- **REALITY full-session indistinguishability** — the REALITY authenticator is embedded in a real TLS 1.3
  ClientHello (`neo-transport::tls`, `build/parse_client_hello`) and an active prober is silently
  reverse-proxied to a genuine pinned upstream (`Conn::reverse_proxy_decoy`) — both built and tested. The
  remaining gap is the **flagship property**: the authenticated path completes only the first flight (no
  ServerHello / full session), so active probing or deep inspection *past* the ClientHello can still tell an
  authenticated neo session from a real TLS site. (`Camouflage` deliberately mimics observable *shape*, not
  full QUIC/DTLS crypto — the protocol-faithful transport is the `quic` feature; that is a design boundary,
  not pending work.)
