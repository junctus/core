//! Networked node roles over a plain TCP transport.
//!
//! M1 uses TCP directly so the handshake and encrypted session are runnable and
//! testable without cert plumbing. The pluggable, DPI-resistant transport
//! (QUIC / MASQUE / WebRTC) arrives in milestone M6 and slots in behind these
//! same handshake calls.

use std::time::Duration;

use neo_core::{Error, NodeId, NodeIdentity, Result};
use neo_crypto::{
    initiator_finish, initiator_message1, responder_confirm, responder_cookie, responder_process,
    CookieKey, HandshakeResult,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A handshake (either side) must complete within this bound, so a stalled or
/// slowloris peer cannot hold a connection/slot open indefinitely.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Reject absurd frame sizes early. The largest legitimate frame is a PQ-hybrid
/// handshake message (~2.5 KB: two ML-KEM keys) or a fixed-size onion packet
/// (~2.4 KB); 64 KiB is a generous ceiling that bounds the per-connection
/// allocation an attacker can trigger with a forged length prefix.
const MAX_FRAME: usize = 64 * 1024;

/// Connection mode: the first sealed frame a peer sends after the handshake is a
/// single mode byte declaring how the rest of the connection behaves, so one
/// relay port serves both one-shot onion messages and persistent circuits. The
/// mode is carried inside the session (authenticated by the immediate peer) and
/// re-sent to each next hop, so it propagates along the path.
///
/// A one-shot Sphinx onion message (`neo send`, forwarded/delivered once).
pub const FRAME_MESSAGE: u8 = 1;
/// A persistent TCP-over-onion circuit (setup packet, then streamed cells; the
/// exit splices a real TCP connection).
pub const FRAME_CIRCUIT: u8 = 2;
/// A committee-exit circuit (M28): the exit encrypts its response to the
/// committee's joint key and each hop seals a threshold partial on the return
/// path, so only the client recovers the response. See [`crate::committee`].
pub const FRAME_COMMITTEE: u8 = 3;

/// Write a length-prefixed frame to any writer (a stream or a split write half).
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    writer.write_all(&(data.len() as u32).to_be_bytes()).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a length-prefixed frame from any reader (a stream or a split read half).
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    reader.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(Error::Decode("frame exceeds maximum size".into()));
    }
    let mut buf = vec![0u8; n];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Dial `addr` and run the initiator side of the handshake: init → cookie
/// challenge → cookied init → m2 → key-confirmation m3.
pub async fn connect(addr: &str, identity: &NodeIdentity) -> Result<(TcpStream, HandshakeResult)> {
    connect_with_timeout(addr, identity, HANDSHAKE_TIMEOUT).await
}

async fn connect_with_timeout(
    addr: &str,
    identity: &NodeIdentity,
    timeout: Duration,
) -> Result<(TcpStream, HandshakeResult)> {
    tokio::time::timeout(timeout, async {
        let mut stream = crate::netif::connect_scoped(addr).await?;
        let (state, init1) = initiator_message1(identity)?;
        write_frame(&mut stream, &init1).await?;
        // Anti-DoS cookie round-trip: echo the responder's challenge in a re-sent m1.
        let cookie = read_frame(&mut stream).await?;
        let init2 = state.with_cookie(&cookie);
        write_frame(&mut stream, &init2).await?;
        let msg2 = read_frame(&mut stream).await?;
        let (msg3, result) = initiator_finish(state, &msg2)?;
        write_frame(&mut stream, &msg3).await?;
        Ok((stream, result))
    })
    .await
    .map_err(|_| Error::Crypto("initiator handshake timed out".into()))?
}

/// Connect with a fresh one-use initiator identity. Client entry relays need to
/// authenticate as the selected node, but they do not need a stable identifier for
/// the client; rotating this pseudonym per circuit prevents cross-flow linkage.
pub async fn connect_ephemeral(addr: &str) -> Result<(TcpStream, HandshakeResult)> {
    let identity = NodeIdentity::generate()?;
    connect(addr, &identity).await
}

/// Like [`connect`], but require the peer to authenticate as the `expected`
/// [`NodeId`] — the identity the caller trusted from the witness-signed snapshot
/// (a chosen relay, or a Sphinx-peeled next hop). The handshake re-derives the
/// peer's NodeId in-band from all three of its long-term keys, so this rejects a
/// transport MITM (or a stale/hijacked address) **before any frame is sent**, and
/// enforces a compact record's key commitment at dial time. Every dial that
/// targets a snapshot-selected identity should use this, not bare [`connect`], so
/// the check can't be forgotten.
pub async fn connect_verified(
    addr: &str,
    identity: &NodeIdentity,
    expected: &NodeId,
) -> Result<(TcpStream, HandshakeResult)> {
    let (stream, result) = connect(addr, identity).await?;
    if &result.peer_id != expected {
        return Err(Error::Crypto(format!(
            "peer at {addr} authenticated as {} but the snapshot expected {expected}",
            result.peer_id
        )));
    }
    Ok((stream, result))
}

/// As [`connect_verified`], using a fresh one-use client transport identity.
/// Relay-to-relay callers should continue using [`connect_verified`] with their
/// stable relay identity so the next hop can authorize the authenticated peer.
pub async fn connect_verified_ephemeral(
    addr: &str,
    expected: &NodeId,
) -> Result<(TcpStream, HandshakeResult)> {
    let identity = NodeIdentity::generate()?;
    connect_verified(addr, &identity, expected).await
}

/// Accept one connection and run the responder side of the handshake. A
/// per-connection cookie is issued **before** any ML-KEM work (so a replayed or
/// abandoned m1 costs only a MAC), and the session is returned only after the
/// initiator's key confirmation (m3) — so a replayed/forged m1 never yields a
/// usable session.
pub async fn accept(
    listener: &TcpListener,
    identity: &NodeIdentity,
) -> Result<(TcpStream, HandshakeResult)> {
    let (stream, _peer_addr) = listener.accept().await?;
    responder_handshake(stream, identity).await
}

/// Run the responder handshake on an already-accepted `stream`. Split out from
/// [`accept`] so a server can `listener.accept()` cheaply on its accept loop and
/// run this (the slow part) in a spawned per-connection task — a stalled client
/// then can't head-of-line-block new connections. Bounded by [`HANDSHAKE_TIMEOUT`].
pub async fn responder_handshake(
    mut stream: TcpStream,
    identity: &NodeIdentity,
) -> Result<(TcpStream, HandshakeResult)> {
    let result = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let cookie_key = CookieKey::generate()?;
        let init1 = read_frame(&mut stream).await?;
        let challenge = responder_cookie(&cookie_key, &init1)?;
        write_frame(&mut stream, &challenge).await?;
        let init2 = read_frame(&mut stream).await?;
        let (msg2, pending) = responder_process(identity, &init2, &cookie_key)?;
        write_frame(&mut stream, &msg2).await?;
        let msg3 = read_frame(&mut stream).await?;
        responder_confirm(pending, &msg3)
    })
    .await
    .map_err(|_| Error::Crypto("responder handshake timed out".into()))??;
    Ok((stream, result))
}

/// Connect, handshake, and exchange an encrypted ping/pong. Returns the peer's
/// authenticated Ed25519 key bytes.
pub async fn ping_client(addr: &str, identity: &NodeIdentity) -> Result<[u8; 32]> {
    let (mut stream, mut result) = connect(addr, identity).await?;
    let ping = result.session.seal(b"ping")?;
    write_frame(&mut stream, &ping).await?;
    let reply = read_frame(&mut stream).await?;
    if result.session.open(&reply)? != b"pong" {
        return Err(Error::Crypto("unexpected reply to ping".into()));
    }
    Ok(result.peer.to_bytes())
}

/// Accept one connection, handshake, and answer an encrypted ping with a pong.
/// Returns the peer's authenticated Ed25519 key bytes.
pub async fn ping_server(listener: &TcpListener, identity: &NodeIdentity) -> Result<[u8; 32]> {
    let (mut stream, mut result) = accept(listener, identity).await?;
    let ping = read_frame(&mut stream).await?;
    if result.session.open(&ping)? != b"ping" {
        return Err(Error::Crypto("unexpected greeting".into()));
    }
    let pong = result.session.seal(b"pong")?;
    write_frame(&mut stream, &pong).await?;
    Ok(result.peer.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tcp_handshake_and_encrypted_ping_pong() {
        let server_id = NodeIdentity::generate().unwrap();
        let client_id = NodeIdentity::generate().unwrap();
        let server_key = server_id.public().signing.to_bytes();
        let client_key = client_id.public().signing.to_bytes();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let server = tokio::spawn(async move { ping_server(&listener, &server_id).await });
        let client_saw = ping_client(&addr, &client_id).await.unwrap();
        let server_saw = server.await.unwrap().unwrap();

        // Each side cryptographically authenticated the other.
        assert_eq!(client_saw, server_key);
        assert_eq!(server_saw, client_key);
    }

    #[tokio::test]
    async fn ephemeral_connect_rotates_the_client_node_id() {
        let server_id = NodeIdentity::generate().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (_, first) = accept(&listener, &server_id).await.unwrap();
            let (_, second) = accept(&listener, &server_id).await.unwrap();
            (first.peer_id, second.peer_id)
        });

        connect_ephemeral(&addr).await.unwrap();
        connect_ephemeral(&addr).await.unwrap();
        let (first, second) = server.await.unwrap();
        assert_ne!(
            first, second,
            "entry peers must not receive a durable client id"
        );
    }

    #[tokio::test]
    async fn initiator_handshake_times_out_on_a_stalled_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let stalled = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let identity = NodeIdentity::generate().unwrap();
        let err = match connect_with_timeout(&addr, &identity, Duration::from_millis(25)).await {
            Ok(_) => panic!("stalled peer completed the handshake"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("timed out"));
        stalled.abort();
    }
}
