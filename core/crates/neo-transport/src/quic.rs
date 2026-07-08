//! A real QUIC transport (via `quinn`) — a strong, ubiquitous-looking transport.
//!
//! QUIC over UDP/443 blends with the mainstream web (HTTP/3), is hard to
//! fingerprint by protocol alone, and gives multiplexed, congestion-controlled
//! streams. Certificates are self-signed and **not verified** — neo does its own
//! mutual authentication in the handshake layer above this, so QUIC's TLS is only
//! the transport wrapper.
//!
//! This is one strong transport; MASQUE (CONNECT-UDP over HTTP/3), Snowflake-style
//! WebRTC, and REALITY remain further options behind the same idea.

use std::net::SocketAddr;
use std::sync::Arc;

use neo_core::Error;
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

const MAX_FRAME: usize = 16 * 1024 * 1024;

/// A QUIC listener.
pub struct QuicServer {
    endpoint: Endpoint,
}

impl QuicServer {
    /// Bind a QUIC server with a fresh self-signed certificate.
    pub async fn bind(addr: &str) -> neo_core::Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        let cert = rcgen::generate_simple_self_signed(vec!["neo".to_string()])
            .map_err(|e| Error::Crypto(format!("self-signed cert: {e}")))?;
        let cert_der = cert.cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

        let crypto = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Crypto(format!("tls versions: {e}")))?
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|e| Error::Crypto(format!("server cert: {e}")))?;

        let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
            .map_err(|e| Error::Crypto(format!("quic server crypto: {e}")))?;
        let server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));

        let addr: SocketAddr = addr
            .parse()
            .map_err(|e| Error::Config(format!("bad address: {e}")))?;
        let endpoint = Endpoint::server(server_config, addr).map_err(Error::Io)?;
        Ok(Self { endpoint })
    }

    /// The bound local address.
    pub fn local_addr(&self) -> neo_core::Result<String> {
        Ok(self.endpoint.local_addr().map_err(Error::Io)?.to_string())
    }

    /// Accept one connection and its first bidirectional stream.
    pub async fn accept(&self) -> neo_core::Result<QuicConn> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| Error::Io(std::io::Error::from(std::io::ErrorKind::BrokenPipe)))?;
        let connection = incoming
            .await
            .map_err(|e| Error::Config(format!("accept: {e}")))?;
        let (send, recv) = connection
            .accept_bi()
            .await
            .map_err(|e| Error::Config(format!("accept_bi: {e}")))?;
        Ok(QuicConn { send, recv })
    }
}

/// A QUIC client.
pub struct QuicClient {
    endpoint: Endpoint,
    config: ClientConfig,
}

impl QuicClient {
    /// Build a client that accepts self-signed server certificates.
    pub fn new() -> neo_core::Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let crypto = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Crypto(format!("tls versions: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification(provider)))
            .with_no_client_auth();

        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| Error::Crypto(format!("quic client crypto: {e}")))?;
        let config = ClientConfig::new(Arc::new(quic_crypto));

        let endpoint =
            Endpoint::client("0.0.0.0:0".parse().expect("valid addr")).map_err(Error::Io)?;
        Ok(Self { endpoint, config })
    }

    /// Connect to a QUIC server and open a bidirectional stream.
    pub async fn connect(&self, addr: &str) -> neo_core::Result<QuicConn> {
        let addr: SocketAddr = addr
            .parse()
            .map_err(|e| Error::Config(format!("bad address: {e}")))?;
        let connection = self
            .endpoint
            .connect_with(self.config.clone(), addr, "neo")
            .map_err(|e| Error::Config(format!("connect: {e}")))?
            .await
            .map_err(|e| Error::Config(format!("connect handshake: {e}")))?;
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| Error::Config(format!("open_bi: {e}")))?;
        Ok(QuicConn { send, recv })
    }
}

/// A message-oriented QUIC connection over one bidirectional stream.
pub struct QuicConn {
    send: SendStream,
    recv: RecvStream,
}

impl QuicConn {
    /// Send one length-prefixed message.
    pub async fn send(&mut self, payload: &[u8]) -> neo_core::Result<()> {
        self.send
            .write_all(&(payload.len() as u32).to_be_bytes())
            .await
            .map_err(|e| Error::Io(std::io::Error::other(e)))?;
        self.send
            .write_all(payload)
            .await
            .map_err(|e| Error::Io(std::io::Error::other(e)))?;
        Ok(())
    }

    /// Receive one length-prefixed message.
    pub async fn recv(&mut self) -> neo_core::Result<Vec<u8>> {
        let mut len = [0u8; 4];
        self.recv
            .read_exact(&mut len)
            .await
            .map_err(|e| Error::Decode(format!("quic read: {e}")))?;
        let n = u32::from_be_bytes(len) as usize;
        if n > MAX_FRAME {
            return Err(Error::Decode("frame exceeds maximum size".into()));
        }
        let mut buf = vec![0u8; n];
        self.recv
            .read_exact(&mut buf)
            .await
            .map_err(|e| Error::Decode(format!("quic read: {e}")))?;
        Ok(buf)
    }
}

/// Accepts any server certificate (neo authenticates in its own handshake layer).
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn quic_transport_roundtrips() {
        let server = QuicServer::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let client = QuicClient::new().unwrap();

        // Keep both endpoints and connections alive for the whole exchange
        // (dropping an endpoint tears the connection down).
        let (server_side, client_side) = tokio::join!(
            async {
                let mut conn = server.accept().await.unwrap();
                let msg = conn.recv().await.unwrap();
                conn.send(b"pong").await.unwrap();
                (conn, msg)
            },
            async {
                let mut conn = client.connect(&addr).await.unwrap();
                conn.send(b"ping").await.unwrap();
                let reply = conn.recv().await.unwrap();
                (conn, reply)
            },
        );

        assert_eq!(server_side.1, b"ping");
        assert_eq!(client_side.1, b"pong");
    }
}
