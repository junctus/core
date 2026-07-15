//! **Client-reconstruct committee 2PC-TLS exit** — the split-trust exit as an explicit,
//! opt-in client capability (distinct from the M28 *threshold* committee, whose exit member
//! sees the plaintext). Three roles:
//!
//! - **lead** (committee member A): holds the destination socket; runs the 2PC-TLS lead.
//! - **follower** (committee member B): the 2PC-TLS follower.
//! - **client**: XOR-shares its request across the two members and reconstructs the response
//!   from their two plaintext shares.
//!
//! The two members jointly complete a real TLS 1.3 handshake to the destination and seal /
//! open every application record **under 2PC** — so **neither member ever holds the session
//! key or the plaintext** (of the request body/headers or the response). The client sends
//! member A share `rₐ` and member B share `r_b = request ⊕ rₐ`; the 2PC seals `rₐ ⊕ r_b`, so
//! a member sees only its random share. Each member returns its XOR-share of the decrypted
//! response; the client XORs the two to recover the plaintext.
//!
//! **What this is / isn't (honest boundary):**
//! - The destination *host* is unavoidably known to the lead (it dials it); the request
//!   *path/headers/body* are hidden (XOR-shared), and the response is hidden (2PC).
//! - The client is NOT yet anonymized from the members here — it connects to them directly.
//!   Routing the client→committee leg through the onion (so members don't learn the client
//!   IP) is the next layer.
//! - One flow per invocation (matches the demo). A persistent per-flow service is a refinement.
//! - Audit-gated, like all of `mpc_tls::live`: an explicit experimental capability, not a
//!   default. Uses `LeafKeyVerifier` (as the `mpc2pc` demo does); a webpki chain-building
//!   verifier is the production upgrade.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use anyhow::{anyhow, bail, Context};
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use p256::{NonZeroScalar, Scalar};

use neo_mpc::mpc_tls::live::channel::{AmortizingChannel, Channel, TcpChannel};
use neo_mpc::mpc_tls::live::handshake::{
    committee_handshake_net, committee_recv_app, committee_send_app,
};
use neo_mpc::mpc_tls::live::verify::LeafKeyVerifier;
use neo_mpc::mpc_tls::netengine::Party;

/// Max bytes accepted in one length-prefixed frame (request/response share) — 8 MiB.
const MAX_FRAME: usize = 8 * 1024 * 1024;

/// Write a `u32`-length-prefixed frame.
fn send_frame(s: &mut TcpStream, buf: &[u8]) -> anyhow::Result<()> {
    s.write_all(&(buf.len() as u32).to_be_bytes())?;
    s.write_all(buf)?;
    s.flush()?;
    Ok(())
}

/// Read a `u32`-length-prefixed frame (bounded).
fn recv_frame(s: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME {
        bail!("committee2pc: oversized frame ({n} bytes)");
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

fn random_scalar() -> Scalar {
    *NonZeroScalar::random(&mut OsRng)
}

/// The host portion of a `host:port` destination (for TLS SNI).
fn host_of(dest: &str) -> &str {
    dest.rsplit_once(':').map(|(h, _)| h).unwrap_or(dest)
}

/// Entry point for `neo committee2pc --role <lead|follower|client> …`.
#[allow(clippy::too_many_arguments)]
pub fn run(
    role: &str,
    party: Option<String>,
    client_listen: Option<String>,
    lead: Option<String>,
    follower: Option<String>,
    dest: Option<String>,
    request: Option<String>,
) -> anyhow::Result<()> {
    match role {
        "lead" => member(
            Party::A,
            party.context("--party <bind addr for follower> required for lead")?,
            client_listen.context("--client-listen <addr> required for lead")?,
        ),
        "follower" => member(
            Party::B,
            party.context("--party <lead addr> required for follower")?,
            client_listen.context("--client-listen <addr> required for follower")?,
        ),
        "client" => client(
            lead.context("--lead <member-A client addr> required for client")?,
            follower.context("--follower <member-B client addr> required for client")?,
            dest.context("--dest <host:port> required for client")?,
            request,
        ),
        other => bail!("committee2pc: --role must be lead|follower|client (got {other})"),
    }
}

/// A committee member (lead = Party::A holds the destination socket; follower = Party::B).
/// Establishes the member↔member party channel, accepts one client, reads `(dest,
/// request_share)`, runs the joint 2PC-TLS session, and returns its response XOR-share to the
/// client. Never reconstructs the plaintext.
fn member(role: Party, party_addr: String, client_addr: String) -> anyhow::Result<()> {
    let lead = role == Party::A;
    let tag = if lead {
        "lead (member A)"
    } else {
        "follower (member B)"
    };

    // Member↔member party channel: the lead binds and the follower dials it, so the 2PC
    // channel exists before any client is served.
    let party_sock = if lead {
        println!("neo committee2pc — {tag}. Binding party channel {party_addr}, waiting for the follower…");
        let l =
            TcpListener::bind(&party_addr).with_context(|| format!("bind party {party_addr}"))?;
        let (s, peer) = l.accept().context("accept follower")?;
        println!("  follower connected from {peer}");
        s
    } else {
        println!("neo committee2pc — {tag}. Connecting to the lead's party channel {party_addr}…");
        let s = TcpStream::connect(&party_addr)
            .with_context(|| format!("connect party {party_addr}"))?;
        println!("  connected to lead");
        s
    };

    // Accept one client.
    println!("  binding client endpoint {client_addr}, waiting for a client…");
    let cl =
        TcpListener::bind(&client_addr).with_context(|| format!("bind client {client_addr}"))?;
    // Do not print the client's source address: co-locating it with `dest` (below) on one
    // member's stdout would materialise a client↔destination correlation. The member sees
    // the socket regardless (direct-connect demo), but it must not be logged next to dest.
    let (mut client, _cpeer) = cl.accept().context("accept client")?;
    println!("  client connected");

    // The client tells us the destination + this member's request share.
    let dest = String::from_utf8(recv_frame(&mut client)?).context("dest not utf-8")?;
    let request_share = recv_frame(&mut client)?;
    println!(
        "  serving committee 2PC-TLS to {dest} ({} req-share bytes)",
        request_share.len()
    );

    // The lead dials the destination; the follower has no server socket.
    let mut server = if lead {
        Some(TcpChannel::from_stream(
            TcpStream::connect(&dest).with_context(|| format!("dial destination {dest}"))?,
        ))
    } else {
        None
    };

    // Wrap the party channel so the whole session shares one KOS base-OT setup.
    let mut inner_ch = TcpChannel::from_stream(party_sock);
    let mut party_ch = AmortizingChannel::new(&mut inner_ch);

    let scalar = random_scalar();
    let t = std::time::Instant::now();
    let mut sess = committee_handshake_net(
        &mut party_ch,
        role,
        server.as_mut().map(|c| c as &mut dyn Channel),
        host_of(&dest),
        &scalar,
        &LeafKeyVerifier,
    )
    .map_err(|e| anyhow!("committee handshake: {e}"))?;
    println!(
        "  ✓ joint TLS 1.3 handshake to {dest} in {:?} — no member holds the session key",
        t.elapsed()
    );

    // Seal this member's request share under 2PC; the lead writes the record to the server.
    committee_send_app(
        &mut party_ch,
        &mut sess,
        server.as_mut().map(|c| c as &mut dyn Channel),
        &request_share,
    )
    .map_err(|e| anyhow!("send request share: {e}"))?;

    // Open the response under 2PC → this member's XOR-share of the plaintext.
    let resp_share = committee_recv_app(
        &mut party_ch,
        &mut sess,
        server.as_mut().map(|c| c as &mut dyn Channel),
    )
    .map_err(|e| anyhow!("recv response share: {e}"))?;

    // Hand our share to the client (never combined here).
    send_frame(&mut client, &resp_share)?;
    println!(
        "  ✓ returned {}-byte response share to the client (plaintext never reconstructed here)",
        resp_share.len()
    );
    Ok(())
}

/// The client: XOR-share the request across the two members, collect their response shares,
/// and reconstruct the plaintext locally.
fn client(
    lead_addr: String,
    follower_addr: String,
    dest: String,
    request: Option<String>,
) -> anyhow::Result<()> {
    let host = host_of(&dest).to_string();
    let request = request.unwrap_or_else(|| {
        format!("GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: neo-committee2pc\r\nConnection: close\r\n\r\n")
    });
    let req = request.into_bytes();

    // XOR-share the request: member A gets random rₐ, member B gets request ⊕ rₐ.
    let mut share_a = vec![0u8; req.len()];
    OsRng.fill_bytes(&mut share_a);
    let share_b: Vec<u8> = req.iter().zip(&share_a).map(|(r, a)| r ^ a).collect();

    println!("neo committee2pc — client. Committee 2PC-TLS fetch of {dest} via lead {lead_addr} + follower {follower_addr}");
    let mut a =
        TcpStream::connect(&lead_addr).with_context(|| format!("connect lead {lead_addr}"))?;
    let mut b = TcpStream::connect(&follower_addr)
        .with_context(|| format!("connect follower {follower_addr}"))?;

    // Each member: (destination, its request share).
    send_frame(&mut a, dest.as_bytes())?;
    send_frame(&mut a, &share_a)?;
    send_frame(&mut b, dest.as_bytes())?;
    send_frame(&mut b, &share_b)?;
    println!(
        "  sent XOR-shared request ({} bytes) to both members",
        req.len()
    );

    // Collect the two response shares and XOR → plaintext.
    let resp_a = recv_frame(&mut a)?;
    let resp_b = recv_frame(&mut b)?;
    if resp_a.len() != resp_b.len() {
        bail!(
            "committee2pc: response shares differ in length ({} vs {})",
            resp_a.len(),
            resp_b.len()
        );
    }
    let mut inner: Vec<u8> = resp_a.iter().zip(&resp_b).map(|(x, y)| x ^ y).collect();
    // Strip TLS 1.3 inner padding + the trailing content_type byte.
    while inner.last() == Some(&0) {
        inner.pop();
    }
    inner.pop();

    let text = String::from_utf8_lossy(&inner);
    let status = text.lines().next().unwrap_or("(no status line)");
    println!(
        "  ✓ reconstructed {}-byte response from the two members' shares",
        inner.len()
    );
    println!("  server responded: {status}");
    println!("\n✓ committee 2PC-TLS fetch complete — neither member saw the request body or the response.");
    Ok(())
}
