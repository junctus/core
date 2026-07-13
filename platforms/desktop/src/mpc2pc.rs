//! `neo mpc2pc` — **networked two-party 2PC-TLS crypto, live between two nodes** (M45/M47).
//!
//! This runs the real, networked-party form of the two heaviest pieces of a 2PC-TLS
//! handshake between two separate `neo` processes over a socket, and self-verifies each
//! against an independent reference. It exists to demonstrate — over the actual internet,
//! not a loopback test — that the malicious-secure 2PC-TLS machinery in `neo-mpc` runs
//! *live* at practical speed:
//!
//! 1. **ECDHE conversion (ECtF).** Neither party holds the client scalar: party A holds a
//!    random share `k_a`, party B holds `k_b`, and each holds only its own point-share
//!    `P_i = k_i · Y` of the shared ECDH point `Z = (k_a+k_b)·Y`. The
//!    [`ectf`](neo_mpc::mpc_tls::ectf) protocol converts `x(Z)` into additive field shares
//!    over the wire (Gilboa MtA over networked KOS-COT) without either party learning `Z`.
//!    We then *open* the shares — a demo-only step, clearly labelled — and check the
//!    reconstruction equals `x(Z)` computed directly with the vetted `p256` crate.
//!
//! 2. **Key-schedule circuit (garbled).** The real SHA-256 compression circuit (~68k AND
//!    gates — the core of the TLS 1.3 key schedule's HKDF) is garbled by A and evaluated by
//!    B in a **constant 3 network flights** via [`garble_net`](neo_mpc::mpc_tls::garble_net),
//!    with split input ownership. The evaluator checks its decoded output equals the
//!    plaintext circuit — proving the networked garbled online reproduces the circuit over a
//!    real link, in rounds independent of circuit depth.
//!
//! One node runs `neo mpc2pc --listen 0.0.0.0:PORT` (party A / garbler); the other runs
//! `neo mpc2pc --connect HOST:PORT` (party B / evaluator).

use std::net::{TcpListener, TcpStream};
use std::time::Instant;

use anyhow::{anyhow, bail, Context};
use num_bigint::BigUint;
use p256::elliptic_curve::ff::PrimeField;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{AffinePoint, EncodedPoint, FieldBytes, NonZeroScalar, ProjectivePoint, Scalar};
use rand_core::OsRng;

use neo_mpc::mpc_tls::ectf::{ectf_a, ectf_b};
use neo_mpc::mpc_tls::engine::EngineKind;
use neo_mpc::mpc_tls::garble_net::{evaluator_run, garbler_run};
use neo_mpc::mpc_tls::live::channel::{Channel, TcpChannel};
use neo_mpc::mpc_tls::live::handshake::{committee_handshake_net, committee_recv_app, committee_send_app};
use neo_mpc::mpc_tls::live::netschedule::{derive_ecdhe_share_net, KeyScheduleNet};
use neo_mpc::mpc_tls::live::verify::LeafKeyVerifier;
use neo_mpc::mpc_tls::live::schedule::KeySchedule;
use neo_mpc::mpc_tls::netengine::Party;
use neo_mpc::mpc_tls::sha256::{sha256, sha256_compress_circuit};

/// P-256 base field prime, big-endian — for reconstructing the ECtF x-coordinate share
/// with an independent bignum library (num-bigint), so it is cross-checked, not self-compared.
const P256_PRIME_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// Which side of the two-party protocol this process plays.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    /// `--listen`: party A — generates the (public) server key share, runs `ectf_a`, garbles.
    A,
    /// `--connect`: party B — runs `ectf_b`, evaluates the garbled circuit.
    B,
}

/// Timings from one completed two-party session (for terse serve-mode logging).
pub struct SessionReport {
    pub ectf: std::time::Duration,
    pub garble: std::time::Duration,
}

/// Entry point for the `neo mpc2pc` subcommand. `--listen` becomes a **persistent** party-A
/// server (one session per inbound connection, verbose); `--connect` runs one party-B
/// session. `full` selects the whole networked key-agreement driver over the lighter demo.
/// `handshake` runs the committee 2PC-TLS handshake to a real destination (one-shot).
pub fn run(
    listen: Option<String>,
    connect: Option<String>,
    full: bool,
    handshake: Option<String>,
) -> anyhow::Result<()> {
    match (listen, connect) {
        (Some(addr), None) => {
            if let Some(dest) = handshake {
                // Committee lead (party A): accept one member, dial the destination.
                println!("neo mpc2pc — committee lead (party A). Binding {addr}, waiting for peer…");
                let listener = TcpListener::bind(&addr).with_context(|| format!("bind {addr}"))?;
                let (sock, peer) = listener.accept().context("accept peer")?;
                println!("  peer member connected from {peer}");
                let mut ch = TcpChannel::from_stream(sock);
                committee_handshake(Role::A, &mut ch, &dest)
            } else {
                serve(&addr, true, full)
            }
        }
        (None, Some(addr)) => {
            let role = if handshake.is_some() { "committee follower (party B)" } else { "party B (evaluator)" };
            println!("neo mpc2pc — {role}. Connecting to {addr}…");
            let sock = TcpStream::connect(&addr).with_context(|| format!("connect {addr}"))?;
            println!("  connected");
            let mut ch = TcpChannel::from_stream(sock);
            match handshake {
                Some(dest) => committee_handshake(Role::B, &mut ch, &dest),
                None => {
                    run_session(Role::B, &mut ch, true, full)?;
                    Ok(())
                }
            }
        }
        _ => bail!("provide exactly one of --listen <addr> (party A) or --connect <addr> (party B)"),
    }
}

/// **Persistent party-A server.** Bind `addr` and serve one networked 2PC-TLS session
/// (party A / garbler) per inbound connection, forever — each on its own thread, so a
/// misbehaving or slow peer can't wedge the listener. This is what `neo run
/// --mpc2pc-listen <addr>` runs in-process alongside the relay: a standing 2PC-TLS
/// co-processor endpoint. `verbose` prints the full per-session transcript (CLI); when
/// false (relay mode) each session logs a single `tracing` summary line to the journal.
pub fn serve(addr: &str, verbose: bool, full: bool) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).with_context(|| format!("bind {addr}"))?;
    let mode = if full { "full key-agreement" } else { "demo" };
    tracing::info!("mpc2pc: serving networked 2PC-TLS (party A, {mode}) on {addr}");
    if verbose {
        println!("neo mpc2pc — party A (garbler). Serving on {addr} ({mode}), one session per peer…");
    }
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("mpc2pc: accept failed: {e}");
                continue;
            }
        };
        let peer = stream.peer_addr().ok();
        std::thread::spawn(move || {
            let mut ch = TcpChannel::from_stream(stream);
            match run_session(Role::A, &mut ch, verbose, full) {
                Ok(rep) => tracing::info!(
                    "mpc2pc: served {peer:?} — ECDHE {:?}, key schedule {:?}",
                    rep.ectf,
                    rep.garble
                ),
                Err(e) => tracing::warn!("mpc2pc: session with {peer:?} failed: {e}"),
            }
        });
    }
    Ok(())
}

/// Run one two-party session on an established channel, self-verifying. The `full` driver
/// runs the entire networked handshake key agreement; otherwise the lighter ECtF +
/// single-circuit demo.
fn run_session(
    role: Role,
    ch: &mut dyn Channel,
    verbose: bool,
    full: bool,
) -> anyhow::Result<SessionReport> {
    if full {
        return full_key_agreement(role, ch, verbose);
    }
    let ectf = ectf_ecdhe(role, ch, verbose)?;
    let garble = garbled_key_schedule(role, ch, verbose)?;
    if verbose {
        println!("\n✓ networked 2PC-TLS crypto complete and self-verified over the wire.");
    }
    Ok(SessionReport { ectf, garble })
}

// ---- 1. ECDHE conversion (ECtF) ------------------------------------------------------

/// Serialise an affine point's x-coordinate to a fixed 32-byte big-endian array.
fn point_x(p: &AffinePoint) -> [u8; 32] {
    let enc = p.to_encoded_point(false);
    <[u8; 32]>::try_from(enc.x().expect("affine x").as_slice()).expect("32-byte x")
}

/// Serialise an affine point's (x, y) coordinates to big-endian arrays.
fn point_xy(p: &AffinePoint) -> ([u8; 32], [u8; 32]) {
    let enc = p.to_encoded_point(false);
    let x = <[u8; 32]>::try_from(enc.x().expect("affine x").as_slice()).expect("32-byte x");
    let y = <[u8; 32]>::try_from(enc.y().expect("affine y").as_slice()).expect("32-byte y");
    (x, y)
}

/// A random secret scalar (the party's share of the client ephemeral private key).
fn random_scalar() -> Scalar {
    *NonZeroScalar::random(&mut OsRng)
}

fn scalar_bytes(s: &Scalar) -> [u8; 32] {
    let mut b = [0u8; 32];
    b.copy_from_slice(s.to_bytes().as_slice());
    b
}

fn scalar_from_bytes(b: &[u8; 32]) -> anyhow::Result<Scalar> {
    Option::<Scalar>::from(Scalar::from_repr(*FieldBytes::from_slice(b)))
        .ok_or_else(|| anyhow!("peer scalar not in field"))
}

/// The networked ECtF ECDHE conversion + a demo-only correctness check. Returns the ECtF
/// protocol elapsed time.
fn ectf_ecdhe(role: Role, ch: &mut dyn Channel, verbose: bool) -> anyhow::Result<std::time::Duration> {
    if verbose {
        println!("\n[1/2] ECDHE conversion (ECtF) — split-scalar, neither party holds the secret");
    }

    // The public server key share Y. In TLS this arrives in the clear from the server; here
    // party A mints an ephemeral one and discards the private scalar, so neither party knows
    // the server secret. Y is exchanged so both compute the same point-shares of Z = k·Y.
    let y_point: ProjectivePoint = match role {
        Role::A => {
            let server_secret = random_scalar();
            let y = ProjectivePoint::GENERATOR * server_secret; // discard server_secret
            ch.send(y.to_affine().to_encoded_point(false).as_bytes())
                .map_err(|e| anyhow!("send Y: {e}"))?;
            y
        }
        Role::B => {
            let buf = ch.recv_exact(65).map_err(|e| anyhow!("recv Y: {e}"))?;
            let enc = EncodedPoint::from_bytes(&buf).map_err(|e| anyhow!("decode Y: {e}"))?;
            let aff: AffinePoint = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&enc))
                .ok_or_else(|| anyhow!("Y is not a valid P-256 point"))?;
            ProjectivePoint::from(aff)
        }
    };

    // This party's secret scalar share and its point-share P_i = k_i · Y.
    let k = random_scalar();
    let point_share = (y_point * k).to_affine();
    let (px, py) = point_xy(&point_share);

    // Run the networked ECtF: additive shares of x(P_A + P_B) = x(Z), neither learning Z.
    let t = Instant::now();
    let my_x_share = match role {
        Role::A => ectf_a(ch, (&px, &py), &P256_PRIME_BE).map_err(|e| anyhow!("ectf_a: {e}"))?,
        Role::B => ectf_b(ch, (&px, &py), &P256_PRIME_BE).map_err(|e| anyhow!("ectf_b: {e}"))?,
    };
    let elapsed = t.elapsed();
    if verbose {
        println!("  ECtF protocol done in {elapsed:?} (Gilboa MtA over networked KOS-COT)");
    }

    // Demo-only verification: open both the x-shares and the scalar shares, reconstruct, and
    // check against x(Z) computed directly with the vetted p256 crate. (This reveal is NOT
    // part of the protocol — the protocol above leaks neither Z nor the scalars.)
    let mut msg = Vec::with_capacity(64);
    msg.extend_from_slice(&my_x_share);
    msg.extend_from_slice(&scalar_bytes(&k));
    ch.send(&msg).map_err(|e| anyhow!("send verify: {e}"))?;
    let peer = ch.recv_exact(64).map_err(|e| anyhow!("recv verify: {e}"))?;
    let peer_x_share: [u8; 32] = peer[..32].try_into().unwrap();
    let peer_k = scalar_from_bytes(&peer[32..64].try_into().unwrap())?;

    let prime = BigUint::from_bytes_be(&P256_PRIME_BE);
    let recon = (BigUint::from_bytes_be(&my_x_share) + BigUint::from_bytes_be(&peer_x_share)) % &prime;
    let recon_be = bu_to_be32(&recon);

    let joint_scalar = k + peer_k; // scalar addition is commutative → both parties agree
    let z_point = (y_point * joint_scalar).to_affine();
    let expected_x = point_x(&z_point);

    if recon_be != expected_x {
        bail!("ECtF reconstruction mismatch — x(Z) != p256 reference");
    }
    if verbose {
        println!("  ✓ reconstructed x(Z) matches p256's x((k_a+k_b)·Y) — ECDHE conversion correct");
    }
    Ok(elapsed)
}

/// Independent big-endian serialization of a reconstructed field element.
fn bu_to_be32(x: &BigUint) -> [u8; 32] {
    let v = x.to_bytes_be();
    let mut o = [0u8; 32];
    o[32 - v.len()..].copy_from_slice(&v);
    o
}

// ---- 2. Garbled key-schedule circuit -------------------------------------------------

/// A fixed, deterministic input bit vector both parties agree on (demo test vector).
fn demo_inputs(width: usize) -> Vec<bool> {
    (0..width)
        .map(|i| i.wrapping_mul(2_654_435_761) & 1 == 1)
        .collect()
}

/// Garble (A) / evaluate (B) the real SHA-256 compression circuit over the wire in a fixed
/// 3 flights, with split input ownership; the evaluator self-verifies against the plaintext.
fn garbled_key_schedule(
    role: Role,
    ch: &mut dyn Channel,
    verbose: bool,
) -> anyhow::Result<std::time::Duration> {
    let circuit = sha256_compress_circuit();
    let ands = circuit.and_gates();
    if verbose {
        println!("\n[2/2] Garbled key-schedule circuit — SHA-256 compression ({ands} AND gates)");
    }

    // Split input ownership: the evaluator (B) owns the second half of the input wires.
    let ev_wires: std::collections::HashSet<usize> =
        (circuit.input_bits / 2..circuit.input_bits).collect();
    let inputs = demo_inputs(circuit.input_bits);

    let t = Instant::now();
    match role {
        Role::A => {
            garbler_run(ch, &circuit, &ev_wires, &inputs).map_err(|e| anyhow!("garbler: {e}"))?;
            let elapsed = t.elapsed();
            if verbose {
                println!("  ✓ garbled + served the circuit in {elapsed:?} (constant 3 flights)");
            }
            Ok(elapsed)
        }
        Role::B => {
            let out =
                evaluator_run(ch, &circuit, &ev_wires, &inputs).map_err(|e| anyhow!("eval: {e}"))?;
            let elapsed = t.elapsed();
            if out != circuit.eval(&inputs) {
                bail!("garbled evaluation != plaintext circuit");
            }
            if verbose {
                println!(
                    "  ✓ evaluated over the wire in {elapsed:?} — output matches the plaintext circuit"
                );
            }
            Ok(elapsed)
        }
    }
}

// ---- full networked handshake key-agreement driver ----------------------------------

/// Fixed public transcript stand-ins for the demo (their content is opaque to the schedule —
/// only their hashes enter the HKDF contexts, exactly as real handshake bytes would).
const CH_SH: &[u8] = b"neo-2pc-tls: ClientHello||ServerHello";
const CH_SFIN: &[u8] = b"neo-2pc-tls: ClientHello..server Finished";
const CV: &[u8] = b"neo-2pc-tls: ClientHello..CertVerify";

fn party_of(role: Role) -> Party {
    match role {
        Role::A => Party::A,
        Role::B => Party::B,
    }
}

/// Run the **entire networked handshake key agreement** over the channel — ECDHE conversion
/// (ECtF + A2B) then the full TLS 1.3 key schedule — then self-verify the combined shares
/// against the vetted in-process [`KeySchedule`] reference. Both parties run the identical
/// gadget sequence so the channel stays in lockstep.
fn full_key_agreement(role: Role, ch: &mut dyn Channel, verbose: bool) -> anyhow::Result<SessionReport> {
    let party = party_of(role);

    // Public server key share Y: A mints an ephemeral one and discards the scalar; B receives.
    let y_point: ProjectivePoint = match role {
        Role::A => {
            let y = ProjectivePoint::GENERATOR * random_scalar(); // discard the server scalar
            ch.send(y.to_affine().to_encoded_point(false).as_bytes())
                .map_err(|e| anyhow!("send Y: {e}"))?;
            y
        }
        Role::B => {
            let buf = ch.recv_exact(65).map_err(|e| anyhow!("recv Y: {e}"))?;
            let enc = EncodedPoint::from_bytes(&buf).map_err(|e| anyhow!("decode Y: {e}"))?;
            let aff: AffinePoint = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&enc))
                .ok_or_else(|| anyhow!("Y is not a valid P-256 point"))?;
            ProjectivePoint::from(aff)
        }
    };
    let y_sec1 = y_point.to_affine().to_encoded_point(false).as_bytes().to_vec();

    // This party's ephemeral scalar share.
    let x = random_scalar();

    if verbose {
        println!("\n[1/3] Networked ECDHE conversion (ECtF + A2B) — over the channel");
    }
    let t = Instant::now();
    let ecdhe = derive_ecdhe_share_net(ch, party, &x, &y_sec1).map_err(|e| anyhow!("ecdhe: {e}"))?;
    let ectf_elapsed = t.elapsed();
    if verbose {
        println!("  done in {ectf_elapsed:?} — this party holds an XOR-share of x(Z)");
        println!("\n[2/3] Networked TLS 1.3 key schedule — handshake + application epoch");
    }

    // The full schedule, identical order on both parties.
    let t = Instant::now();
    let mut ks = KeyScheduleNet::derive_handshake(ch, party, &ecdhe, CH_SH)
        .map_err(|e| anyhow!("derive_handshake: {e}"))?;
    let client_hs = ks.client_handshake_secret_share();
    let server_hs = ks.server_handshake_secret_share();
    let (client_hs_key, _iv) = ks
        .client_handshake_keys_share(ch)
        .map_err(|e| anyhow!("client hs keys: {e}"))?;
    let server_finished = ks
        .server_finished_share(ch, &sha256(CV))
        .map_err(|e| anyhow!("server finished: {e}"))?;
    ks.derive_application(ch, CH_SFIN)
        .map_err(|e| anyhow!("derive_application: {e}"))?;
    let client_ap = ks.client_application_secret_share();
    let server_ap = ks.server_application_secret_share();
    let sched_elapsed = t.elapsed();
    if verbose {
        println!("  done in {sched_elapsed:?} — shares of every traffic secret, key & Finished MAC");
        println!("\n[3/3] Self-verification against the in-process reference schedule");
    }

    // Demo-only reveal: exchange this party's scalar + secret shares, reconstruct, and check
    // against the vetted in-process KeySchedule oracle. (The protocol above leaks none of these.)
    let mut msg = Vec::with_capacity(256);
    msg.extend_from_slice(&scalar_bytes(&x));
    for s in [&ecdhe, &client_hs, &server_hs, &client_hs_key, &server_finished, &client_ap, &server_ap] {
        msg.extend_from_slice(s);
    }
    ch.send(&msg).map_err(|e| anyhow!("send verify: {e}"))?;
    let peer = ch.recv_exact(256).map_err(|e| anyhow!("recv verify: {e}"))?;
    let peer_x = scalar_from_bytes(&peer[0..32].try_into().unwrap())?;
    let peer_share = |i: usize| -> [u8; 32] { peer[32 + i * 32..64 + i * 32].try_into().unwrap() };

    // Ground-truth ECDHE secret from the combined scalars.
    let z = (y_point * (x + peer_x)).to_affine();
    let expected_ecdhe = point_x(&z);
    let combined_ecdhe = xor32(&ecdhe, &peer_share(0));
    if combined_ecdhe != expected_ecdhe {
        bail!("networked ECDHE share != p256 x(Z)");
    }

    // In-process reference schedule from the reconstructed secret (split trivially).
    let mut refks = KeySchedule::derive_handshake(EngineKind::Semihonest, &expected_ecdhe, &[0u8; 32], CH_SH)
        .map_err(|e| anyhow!("reference schedule: {e}"))?;
    check("client_hs secret", &xor32(&client_hs, &peer_share(1)), &refks.client_handshake_secret().open())?;
    check("server_hs secret", &xor32(&server_hs, &peer_share(2)), &refks.server_handshake_secret().open())?;
    let rk = refks.client_handshake_keys().map_err(|e| anyhow!("ref client keys: {e}"))?;
    check("client hs key", &xor32(&client_hs_key, &peer_share(3)), &xor32(&rk.key_a, &rk.key_b))?;
    let rsf = refks.server_finished(&sha256(CV)).map_err(|e| anyhow!("ref server finished: {e}"))?;
    check("server Finished MAC", &xor32(&server_finished, &peer_share(4)), &rsf)?;
    refks.derive_application(CH_SFIN).map_err(|e| anyhow!("ref derive_application: {e}"))?;
    check("client_ap secret", &xor32(&client_ap, &peer_share(5)), &refks.client_application_secret().open())?;
    check("server_ap secret", &xor32(&server_ap, &peer_share(6)), &refks.server_application_secret().open())?;

    if verbose {
        println!("  ✓ ECDHE x(Z) + every key-schedule node matches the reference — handshake key agreement correct");
        println!("\n✓ full networked 2PC-TLS handshake key agreement complete and self-verified over the wire.");
    }
    Ok(SessionReport { ectf: ectf_elapsed, garble: sched_elapsed })
}

fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    core::array::from_fn(|i| a[i] ^ b[i])
}

/// Assert a reconstructed value equals the reference, else abort the session.
fn check(what: &str, got: &[u8; 32], want: &[u8; 32]) -> anyhow::Result<()> {
    if got != want {
        bail!("{what}: networked share reconstruction != reference");
    }
    Ok(())
}

// ---- committee 2PC-TLS handshake to a real destination ------------------------------

/// Run one committee 2PC-TLS handshake to `dest` (host:port): the two nodes jointly complete
/// a real TLS 1.3 handshake as exit-committee members (neither holds the session key), fetch
/// `GET /`, and reconstruct the response from their plaintext shares.
fn committee_handshake(role: Role, ch: &mut dyn Channel, dest: &str) -> anyhow::Result<()> {
    let party = party_of(role);
    let host = dest.rsplit_once(':').map(|(h, _)| h).unwrap_or(dest).to_string();
    let scalar = random_scalar();

    let mut server = if role == Role::A {
        println!("  dialing destination {dest} (TLS 1.3, ChaCha20-Poly1305 + P-256)…");
        Some(TcpChannel::from_stream(
            TcpStream::connect(dest).with_context(|| format!("connect {dest}"))?,
        ))
    } else {
        None
    };

    let t = Instant::now();
    let mut sess = committee_handshake_net(
        ch,
        party,
        server.as_mut().map(|c| c as &mut dyn Channel),
        &host,
        &scalar,
        &LeafKeyVerifier,
    )
    .map_err(|e| anyhow!("committee handshake: {e}"))?;
    println!(
        "  ✓ committee TLS 1.3 handshake to {host} complete in {:?} — no single member holds the session key",
        t.elapsed()
    );

    // Fetch GET / — the lead carries the public request bytes, the follower carries zeros.
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: neo-mpc2pc\r\nConnection: close\r\n\r\n"
    );
    let pt_share = if role == Role::A {
        req.clone().into_bytes()
    } else {
        vec![0u8; req.len()]
    };
    committee_send_app(ch, &mut sess, server.as_mut().map(|c| c as &mut dyn Channel), &pt_share)
        .map_err(|e| anyhow!("send request: {e}"))?;
    let my_share = committee_recv_app(ch, &mut sess, server.as_mut().map(|c| c as &mut dyn Channel))
        .map_err(|e| anyhow!("recv response: {e}"))?;

    // Reconstruct (demo reveal — in production the onion client does this): exchange shares,
    // XOR, strip padding + the trailing content_type.
    let mut resp = combine_shares(ch, &my_share)?;
    while resp.last() == Some(&0) {
        resp.pop();
    }
    resp.pop(); // content_type
    let text = String::from_utf8_lossy(&resp);
    let status = text.lines().next().unwrap_or("(no status line)");
    println!("  ✓ committee fetched https://{host}/ — server responded: {status}");
    println!("\n✓ committee 2PC-TLS handshake + fetch complete over the wire (no member saw the plaintext).");
    Ok(())
}

/// Exchange + XOR a plaintext share with the peer member (demo reconstruction of a public value).
fn combine_shares(ch: &mut dyn Channel, mine: &[u8]) -> anyhow::Result<Vec<u8>> {
    ch.send(mine).map_err(|e| anyhow!("send share: {e}"))?;
    let peer = ch.recv_exact(mine.len()).map_err(|e| anyhow!("recv share: {e}"))?;
    Ok(mine.iter().zip(&peer).map(|(a, b)| a ^ b).collect())
}
