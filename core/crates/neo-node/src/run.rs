//! Networked node roles over a plain TCP transport.
//!
//! M1 uses TCP directly so the handshake and encrypted session are runnable and
//! testable without cert plumbing. The pluggable, DPI-resistant transport
//! (QUIC / MASQUE / WebRTC) arrives in milestone M6 and slots in behind these
//! same handshake calls.

use neo_core::{Error, NodeIdentity, Result};
use neo_crypto::{initiator_finish, initiator_message1, responder_process, HandshakeResult};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Reject absurd frame sizes early (handshake messages are a few KB).
const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Write a length-prefixed frame.
pub async fn write_frame(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    stream.write_all(&(data.len() as u32).to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

/// Read a length-prefixed frame.
pub async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(Error::Decode("frame exceeds maximum size".into()));
    }
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Dial `addr` and run the initiator side of the handshake.
pub async fn connect(addr: &str, identity: &NodeIdentity) -> Result<(TcpStream, HandshakeResult)> {
    let mut stream = TcpStream::connect(addr).await?;
    let (state, msg1) = initiator_message1(identity)?;
    write_frame(&mut stream, &msg1).await?;
    let msg2 = read_frame(&mut stream).await?;
    let result = initiator_finish(state, &msg2)?;
    Ok((stream, result))
}

/// Accept one connection and run the responder side of the handshake.
pub async fn accept(
    listener: &TcpListener,
    identity: &NodeIdentity,
) -> Result<(TcpStream, HandshakeResult)> {
    let (mut stream, _peer_addr) = listener.accept().await?;
    let msg1 = read_frame(&mut stream).await?;
    let (msg2, result) = responder_process(identity, &msg1)?;
    write_frame(&mut stream, &msg2).await?;
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
}
