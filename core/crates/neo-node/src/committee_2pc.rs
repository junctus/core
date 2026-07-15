//! **Committee 2PC-TLS exit — relay-side member (self-forming, mandatory).**
//!
//! Every relay's service can be selected into a committee for a flow (no opt-out): two
//! members jointly complete a TLS 1.3 handshake to the destination and seal/open every
//! application record **under 2PC**, so neither holds the session key or plaintext. Roles are
//! assigned by circuit position — the exit member (dials the destination = egresses, so must
//! be exit-capable) is **Party A**; the prior member is **Party B**. The client XOR-shares its
//! request across the members and reconstructs the response from their two shares; a third,
//! non-committee relay anonymizes the client from the members (the onion hop).
//!
//! The 2PC engine ([`neo_mpc::mpc_tls::live`]) is **synchronous** (`std::net`), while the node
//! is async (tokio). [`run_member`] is the bridge: it converts the tokio member↔member link to
//! a blocking socket and drives the interactive 2PC on a [`spawn_blocking`](tokio::task::spawn_blocking)
//! thread. This module is the per-member primitive; the Sphinx transport that carries the
//! request-shares in and the response-shares out (the `FRAME_COMMITTEE_2PC` handler + client
//! selection) wraps it.

use std::net::TcpStream as StdTcpStream;

use neo_core::{Error, Result};
use p256::elliptic_curve::rand_core::OsRng;
use p256::{NonZeroScalar, Scalar};
use tokio::net::TcpStream;

use neo_mpc::mpc_tls::live::channel::{AmortizingChannel, Channel, TcpChannel};
use neo_mpc::mpc_tls::live::handshake::{
    committee_handshake_net, committee_recv_app, committee_send_app,
};
use neo_mpc::mpc_tls::live::verify::LeafKeyVerifier;
use neo_mpc::mpc_tls::netengine::Party;

/// The host portion of a `host:port` destination (TLS SNI).
fn host_of(dest: &str) -> &str {
    dest.rsplit_once(':').map(|(h, _)| h).unwrap_or(dest)
}

/// Run this member's **blocking** 2PC-TLS session over the member↔member link `party_std`.
/// `role == Party::A` is the lead: it dials `dest` (egress) and holds the server socket;
/// `Party::B` is the follower (no server socket). `request_share` is this member's XOR-share
/// of the request. Returns this member's XOR-share of the response plaintext (the record
/// inner — the caller strips TLS padding + content-type after XOR-combining both shares).
///
/// **Blocking** — invoked under `spawn_blocking` by [`run_member`].
fn member_2pc_blocking(
    role: Party,
    party_std: StdTcpStream,
    dest: &str,
    request_share: &[u8],
) -> Result<Vec<u8>> {
    // Wrap the member link so the whole session shares one KOS base-OT setup.
    let mut inner = TcpChannel::from_stream(party_std);
    let mut party = AmortizingChannel::new(&mut inner);

    // The lead dials the destination; the follower has no server socket.
    let mut server = if role == Party::A {
        let sock = StdTcpStream::connect(dest)
            .map_err(|e| Error::Config(format!("committee2pc: dial destination {dest}: {e}")))?;
        Some(TcpChannel::from_stream(sock))
    } else {
        None
    };

    let scalar: Scalar = *NonZeroScalar::random(&mut OsRng);
    let mut sess = committee_handshake_net(
        &mut party,
        role,
        server.as_mut().map(|c| c as &mut dyn Channel),
        host_of(dest),
        &scalar,
        &LeafKeyVerifier,
    )
    .map_err(|e| Error::Crypto(format!("committee2pc handshake: {e}")))?;

    committee_send_app(
        &mut party,
        &mut sess,
        server.as_mut().map(|c| c as &mut dyn Channel),
        request_share,
    )
    .map_err(|e| Error::Crypto(format!("committee2pc send: {e}")))?;

    committee_recv_app(
        &mut party,
        &mut sess,
        server.as_mut().map(|c| c as &mut dyn Channel),
    )
    .map_err(|e| Error::Crypto(format!("committee2pc recv: {e}")))
}

/// **Async bridge.** Run this member's 2PC-TLS session over the tokio member↔member link
/// `party`, returning this member's XOR-share of the response. Converts `party` to a blocking
/// socket and drives the sync 2PC on a blocking thread (the engine is `std::net`, blocking).
pub async fn run_member(
    role: Party,
    party: TcpStream,
    dest: String,
    request_share: Vec<u8>,
) -> Result<Vec<u8>> {
    let std_stream = party
        .into_std()
        .map_err(|e| Error::Config(format!("committee2pc: into_std: {e}")))?;
    std_stream
        .set_nonblocking(false)
        .map_err(|e| Error::Config(format!("committee2pc: set blocking: {e}")))?;
    tokio::task::spawn_blocking(move || member_2pc_blocking(role, std_stream, &dest, &request_share))
        .await
        .map_err(|e| Error::Config(format!("committee2pc: blocking task join: {e}")))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// Validate the async→sync bridge mechanism in isolation: a tokio stream converted to a
    /// blocking `Channel` (as `run_member` does) round-trips bytes on a `spawn_blocking`
    /// thread while the async peer drives it. This is the load-bearing plumbing; the full 2PC
    /// over it is proven by the live inter-relay test.
    #[tokio::test]
    async fn tokio_stream_bridges_to_blocking_channel() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server side: accept, convert to a blocking neo-mpc Channel under spawn_blocking,
        // recv 4 bytes, echo them back — exactly the bridge run_member performs.
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let std_sock = sock.into_std().unwrap();
            std_sock.set_nonblocking(false).unwrap();
            tokio::task::spawn_blocking(move || {
                let mut ch = TcpChannel::from_stream(std_sock);
                let got = ch.recv_exact(4).unwrap();
                ch.send(&got).unwrap();
            })
            .await
            .unwrap();
        });

        // Async client drives the blocking bridge on the other end.
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping", "blocking Channel over a bridged tokio stream round-trips");
        server.await.unwrap();
    }
}
