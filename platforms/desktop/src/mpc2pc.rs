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

use neo_mpc::mpc_tls::circuit::Circuit;
use neo_mpc::mpc_tls::ectf::{ectf_a, ectf_b};
use neo_mpc::mpc_tls::garble_net::{evaluator_run, garbler_run};
use neo_mpc::mpc_tls::live::channel::{Channel, TcpChannel};
use neo_mpc::mpc_tls::sha256::sha256_compress_circuit;

/// P-256 base field prime, big-endian — for reconstructing the ECtF x-coordinate share
/// with an independent bignum library (num-bigint), so it is cross-checked, not self-compared.
const P256_PRIME_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// Which side of the two-party protocol this process plays.
#[derive(Clone, Copy)]
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
/// server (one session per inbound connection, verbose); `--connect` runs one party-B session.
pub fn run(listen: Option<String>, connect: Option<String>) -> anyhow::Result<()> {
    match (listen, connect) {
        (Some(addr), None) => serve(&addr, true),
        (None, Some(addr)) => {
            println!("neo mpc2pc — party B (evaluator). Connecting to {addr}…");
            let sock = TcpStream::connect(&addr).with_context(|| format!("connect {addr}"))?;
            println!("  connected");
            let mut ch = TcpChannel::from_stream(sock);
            run_session(Role::B, &mut ch, true)?;
            Ok(())
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
pub fn serve(addr: &str, verbose: bool) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).with_context(|| format!("bind {addr}"))?;
    tracing::info!("mpc2pc: serving networked 2PC-TLS (party A) on {addr}");
    if verbose {
        println!("neo mpc2pc — party A (garbler). Serving on {addr}, one session per peer…");
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
            match run_session(Role::A, &mut ch, verbose) {
                Ok(rep) => tracing::info!(
                    "mpc2pc: served {peer:?} — ECtF {:?}, garbled SHA-256 {:?}",
                    rep.ectf,
                    rep.garble
                ),
                Err(e) => tracing::warn!("mpc2pc: session with {peer:?} failed: {e}"),
            }
        });
    }
    Ok(())
}

/// Run the full two-party session on an established channel: ECtF ECDHE conversion, then
/// the garbled SHA-256 key-schedule circuit, self-verifying each.
fn run_session(role: Role, ch: &mut dyn Channel, verbose: bool) -> anyhow::Result<SessionReport> {
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
    let circuit: Circuit = sha256_compress_circuit();
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
