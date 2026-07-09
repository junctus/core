//! `neo-transport` — pluggable, DPI-resistant transport.
//!
//! A [`Transport`] carries neo's own encrypted protocol (and all `libp2p`
//! traffic, whose wire protocol is itself fingerprintable) under an
//! [`Obfuscation`] strategy chosen at runtime:
//! - [`Plain`] — no obfuscation (baseline / development),
//! - [`Bucketed`] — quantizes every record's length to a multiple of a bucket
//!   size with random padding, so an observer sees only coarse, uniform lengths, and
//! - [`Camouflage`] — shapes each record to *look like* a QUIC/MASQUE datagram or
//!   a WebRTC/DTLS record (recognizable header bytes + datagram-ish sizing), so a
//!   fingerprinter classifying by shape sees a familiar protocol, not neo.
//!
//! On top of framing, [`Transport::dial_reality`] / [`Listener::accept_reality`]
//! run a **REALITY-style authenticated first flight** ([`neo_crypto::reality`]):
//! a legitimate client proves possession of a pre-shared capability with an
//! authenticator indistinguishable from random, while an active prober is silently
//! routed to a **decoy** path — so probing cannot tell a neo bridge from an
//! ordinary server.
//!
//! **Honest boundary.** `Camouflage` mimics the observable *shape* of QUIC/DTLS,
//! not the full protocol crypto (a real QUIC transport lives behind the `quic`
//! feature). The REALITY integration implements the authenticator and the silent
//! authenticate/decoy split; wiring the decoy to a genuine upstream TLS site and
//! embedding the flight inside a real TLS ClientHello are the remaining
//! integration steps. Rendezvous uses DoH, not domain fronting (which is dead).

#![forbid(unsafe_code)]

#[cfg(feature = "quic")]
pub mod quic;

use neo_core::{Error, Result};
use neo_crypto::{RealityKey, RealitySecret, Verdict};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MAX_RECORD: usize = 16 * 1024 * 1024;

/// A reversible transformation applied to each record before it hits the wire.
pub trait Obfuscation: Clone + Send + Sync + 'static {
    /// Turn an application payload into a wire record.
    fn frame(&self, payload: &[u8]) -> Result<Vec<u8>>;
    /// Recover the payload from a wire record.
    fn unframe(&self, record: &[u8]) -> Result<Vec<u8>>;
}

/// No obfuscation: the record is the payload. Baseline and for development.
#[derive(Clone, Copy, Debug, Default)]
pub struct Plain;

impl Obfuscation for Plain {
    fn frame(&self, payload: &[u8]) -> Result<Vec<u8>> {
        Ok(payload.to_vec())
    }
    fn unframe(&self, record: &[u8]) -> Result<Vec<u8>> {
        Ok(record.to_vec())
    }
}

/// Pads every record up to a multiple of `bucket` bytes with random data, so the
/// observable length is quantized rather than exact.
#[derive(Clone, Copy, Debug)]
pub struct Bucketed {
    bucket: usize,
}

impl Bucketed {
    /// Create a bucketed obfuscator with the given quantum (must be > 0).
    pub fn new(bucket: usize) -> Result<Self> {
        if bucket == 0 {
            return Err(Error::Config("bucket size must be > 0".into()));
        }
        Ok(Self { bucket })
    }
}

impl Obfuscation for Bucketed {
    fn frame(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut record = Vec::with_capacity(payload.len() + self.bucket);
        record.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        record.extend_from_slice(payload);

        let target = record.len().div_ceil(self.bucket) * self.bucket;
        let pad = target - record.len();
        let mut padding = vec![0u8; pad];
        getrandom::getrandom(&mut padding).map_err(|e| Error::Rng(e.to_string()))?;
        record.extend_from_slice(&padding);
        Ok(record)
    }

    fn unframe(&self, record: &[u8]) -> Result<Vec<u8>> {
        if record.len() < 4 {
            return Err(Error::Decode("obfuscated record too short".into()));
        }
        let len = u32::from_be_bytes(record[..4].try_into().expect("checked")) as usize;
        if record.len() < 4 + len {
            return Err(Error::Decode("obfuscated record truncated".into()));
        }
        Ok(record[4..4 + len].to_vec())
    }
}

/// The protocol whose observable *shape* a [`Camouflage`] record imitates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// A QUIC short-header packet (as MASQUE/HTTP-3 datagrams ride on).
    QuicMasque,
    /// A WebRTC media/data record (DTLS 1.2 `application_data`).
    WebRtcDtls,
}

impl Shape {
    /// Bytes of shape-specific header before the 2-byte inner length.
    fn prefix_len(self) -> usize {
        match self {
            // short-header byte + 8-byte connection id
            Shape::QuicMasque => 1 + 8,
            // content type + 2-byte version + 2-byte epoch + 6-byte sequence
            Shape::WebRtcDtls => 1 + 2 + 2 + 6,
        }
    }

    fn write_header(self, out: &mut Vec<u8>) -> Result<()> {
        let mut rnd = [0u8; 8];
        getrandom::getrandom(&mut rnd).map_err(|e| Error::Rng(e.to_string()))?;
        match self {
            Shape::QuicMasque => {
                // Short header: MSB 0 (not long-header), fixed bit 1, rest varied.
                out.push(0x40 | (rnd[0] & 0x3f));
                out.extend_from_slice(&rnd); // 8-byte pseudo connection id
            }
            Shape::WebRtcDtls => {
                out.extend_from_slice(&[0x17, 0xfe, 0xfd]); // application_data, DTLS 1.2
                out.extend_from_slice(&rnd[..2]); // epoch
                out.extend_from_slice(&rnd[..6]); // sequence number
            }
        }
        Ok(())
    }

    fn header_matches(self, record: &[u8]) -> bool {
        match self {
            Shape::QuicMasque => !record.is_empty() && record[0] & 0xc0 == 0x40,
            Shape::WebRtcDtls => record.len() >= 3 && record[..3] == [0x17, 0xfe, 0xfd],
        }
    }
}

/// Shapes each record to imitate a chosen [`Shape`]: a recognizable header, the
/// payload, and random padding up to a datagram-sized bucket — so a fingerprinter
/// classifying by wire shape sees that protocol, not neo. Reversible.
///
/// This mimics the observable **shape**, not the full protocol crypto; a real
/// QUIC transport lives behind the `quic` feature.
#[derive(Clone, Copy, Debug)]
pub struct Camouflage {
    shape: Shape,
    bucket: usize,
}

impl Camouflage {
    /// A camouflage obfuscator imitating `shape`, padded to 128-byte buckets.
    pub fn new(shape: Shape) -> Self {
        Self { shape, bucket: 128 }
    }

    /// As [`new`](Camouflage::new) but with an explicit padding bucket (> 0).
    pub fn with_bucket(shape: Shape, bucket: usize) -> Result<Self> {
        if bucket == 0 {
            return Err(Error::Config("bucket size must be > 0".into()));
        }
        Ok(Self { shape, bucket })
    }
}

impl Obfuscation for Camouflage {
    fn frame(&self, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() > u16::MAX as usize {
            return Err(Error::Config("camouflage record payload too large".into()));
        }
        let mut record = Vec::with_capacity(self.shape.prefix_len() + 2 + payload.len());
        self.shape.write_header(&mut record)?;
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);

        let target = record.len().div_ceil(self.bucket) * self.bucket;
        let mut pad = vec![0u8; target - record.len()];
        getrandom::getrandom(&mut pad).map_err(|e| Error::Rng(e.to_string()))?;
        record.extend_from_slice(&pad);
        Ok(record)
    }

    fn unframe(&self, record: &[u8]) -> Result<Vec<u8>> {
        if !self.shape.header_matches(record) {
            return Err(Error::Decode("camouflage header shape mismatch".into()));
        }
        let off = self.shape.prefix_len();
        if record.len() < off + 2 {
            return Err(Error::Decode("camouflage record too short".into()));
        }
        let len = u16::from_be_bytes(record[off..off + 2].try_into().expect("checked")) as usize;
        if record.len() < off + 2 + len {
            return Err(Error::Decode("camouflage record truncated".into()));
        }
        Ok(record[off + 2..off + 2 + len].to_vec())
    }
}

/// A transport that dials and listens with a chosen obfuscation strategy.
#[derive(Clone)]
pub struct Transport<O: Obfuscation> {
    obfuscation: O,
}

impl<O: Obfuscation> Transport<O> {
    /// Create a transport using the given obfuscation.
    pub fn new(obfuscation: O) -> Self {
        Self { obfuscation }
    }

    /// Dial a peer.
    pub async fn dial(&self, addr: &str) -> Result<Conn<O>> {
        let stream = TcpStream::connect(addr).await?;
        Ok(Conn {
            stream,
            obfuscation: self.obfuscation.clone(),
        })
    }

    /// Dial a peer and open with a **REALITY authenticated first flight**: prove
    /// possession of the pre-shared `key` for `epoch`, then return the connection
    /// and the shared `session_seed` the server independently derived. To a censor
    /// the flight is indistinguishable from random.
    pub async fn dial_reality(
        &self,
        addr: &str,
        key: &RealityKey,
        epoch: u64,
    ) -> Result<(Conn<O>, [u8; 32])> {
        let mut stream = TcpStream::connect(addr).await?;
        let (hello, seed) = key.client_hello(epoch)?;
        write_blob(&mut stream, &hello).await?;
        Ok((
            Conn {
                stream,
                obfuscation: self.obfuscation.clone(),
            },
            seed,
        ))
    }

    /// Bind a listener.
    pub async fn listen(&self, addr: &str) -> Result<Listener<O>> {
        Ok(Listener {
            listener: TcpListener::bind(addr).await?,
            obfuscation: self.obfuscation.clone(),
        })
    }
}

/// A bound listener that accepts obfuscated connections.
pub struct Listener<O: Obfuscation> {
    listener: TcpListener,
    obfuscation: O,
}

impl<O: Obfuscation> Listener<O> {
    /// Accept one connection.
    pub async fn accept(&self) -> Result<Conn<O>> {
        let (stream, _addr) = self.listener.accept().await?;
        Ok(Conn {
            stream,
            obfuscation: self.obfuscation.clone(),
        })
    }

    /// Accept one connection and read its **REALITY first flight**, silently
    /// classifying it with the server `secret` at `epoch`. A legitimate client
    /// yields [`RealityAccept::Authenticated`] (with the shared session seed); an
    /// active prober — wrong capability, random bytes, or none — yields
    /// [`RealityAccept::Decoy`] on the same connection, which the caller should
    /// handle exactly as any non-neo peer (e.g. proxy to an upstream site).
    pub async fn accept_reality(
        &self,
        secret: &RealitySecret,
        epoch: u64,
    ) -> Result<RealityAccept<O>> {
        let (mut stream, _addr) = self.listener.accept().await?;
        let hello = read_blob(&mut stream).await?;
        let conn = Conn {
            stream,
            obfuscation: self.obfuscation.clone(),
        };
        match secret.classify(&hello, epoch) {
            Verdict::Authenticated { session_seed } => {
                Ok(RealityAccept::Authenticated { conn, session_seed })
            }
            Verdict::Decoy => Ok(RealityAccept::Decoy { conn }),
        }
    }

    /// The local address the listener is bound to.
    pub fn local_addr(&self) -> Result<String> {
        Ok(self.listener.local_addr()?.to_string())
    }
}

/// The outcome of [`Listener::accept_reality`]: a silent authenticate/decoy split.
pub enum RealityAccept<O: Obfuscation> {
    /// A legitimate neo client. `session_seed` is shared with the client.
    Authenticated {
        /// The accepted connection.
        conn: Conn<O>,
        /// The 32-byte seed both sides derived for the ensuing session.
        session_seed: [u8; 32],
    },
    /// Not authenticated — treat exactly as any non-neo peer (decoy / upstream).
    Decoy {
        /// The accepted connection, to run the fallback on.
        conn: Conn<O>,
    },
}

/// Write a length-prefixed blob (the raw first flight, before any obfuscation).
async fn write_blob(stream: &mut TcpStream, blob: &[u8]) -> Result<()> {
    stream.write_all(&(blob.len() as u32).to_be_bytes()).await?;
    stream.write_all(blob).await?;
    stream.flush().await?;
    Ok(())
}

/// Read a length-prefixed blob written by [`write_blob`].
async fn read_blob(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_RECORD {
        return Err(Error::Decode("first flight exceeds maximum size".into()));
    }
    let mut blob = vec![0u8; n];
    stream.read_exact(&mut blob).await?;
    Ok(blob)
}

/// A message-oriented connection that obfuscates every record.
pub struct Conn<O: Obfuscation> {
    stream: TcpStream,
    obfuscation: O,
}

impl<O: Obfuscation> Conn<O> {
    /// Send one payload as an obfuscated, length-prefixed record.
    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        let record = self.obfuscation.frame(payload)?;
        self.stream
            .write_all(&(record.len() as u32).to_be_bytes())
            .await?;
        self.stream.write_all(&record).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Receive one payload.
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        let mut len = [0u8; 4];
        self.stream.read_exact(&mut len).await?;
        let n = u32::from_be_bytes(len) as usize;
        if n > MAX_RECORD {
            return Err(Error::Decode("record exceeds maximum size".into()));
        }
        let mut record = vec![0u8; n];
        self.stream.read_exact(&mut record).await?;
        self.obfuscation.unframe(&record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucketed_quantizes_length_and_roundtrips() {
        let obf = Bucketed::new(256).unwrap();
        for size in [0usize, 1, 100, 255, 256, 300, 1000] {
            let payload = vec![0xabu8; size];
            let record = obf.frame(&payload).unwrap();
            assert_eq!(record.len() % 256, 0, "record length must be quantized");
            assert!(record.len() > size, "padding must be present");
            assert_eq!(obf.unframe(&record).unwrap(), payload);
        }
    }

    #[test]
    fn distinct_payload_sizes_can_share_a_bucket() {
        let obf = Bucketed::new(256).unwrap();
        // 100 and 200 byte payloads both fit one 256-byte bucket → same wire length.
        assert_eq!(
            obf.frame(&[1u8; 100]).unwrap().len(),
            obf.frame(&[2u8; 200]).unwrap().len()
        );
    }

    #[tokio::test]
    async fn obfuscated_transport_roundtrips_over_tcp() {
        let transport = Transport::new(Bucketed::new(512).unwrap());
        let listener = transport.listen("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut conn = listener.accept().await.unwrap();
            let msg = conn.recv().await.unwrap();
            conn.send(b"pong").await.unwrap();
            msg
        });

        let mut client = transport.dial(&addr).await.unwrap();
        client.send(b"ping").await.unwrap();
        assert_eq!(client.recv().await.unwrap(), b"pong");
        assert_eq!(server.await.unwrap(), b"ping");
    }

    #[test]
    fn camouflage_imitates_shape_and_roundtrips() {
        for shape in [Shape::QuicMasque, Shape::WebRtcDtls] {
            let obf = Camouflage::new(shape);
            for size in [0usize, 1, 100, 127, 128, 500] {
                let payload = vec![0x5au8; size];
                let record = obf.frame(&payload).unwrap();
                assert!(
                    shape.header_matches(&record),
                    "{shape:?} header must be present"
                );
                assert_eq!(record.len() % 128, 0, "record padded to a datagram bucket");
                assert_eq!(obf.unframe(&record).unwrap(), payload);
            }
        }
    }

    #[test]
    fn camouflage_rejects_the_wrong_shape() {
        let quic = Camouflage::new(Shape::QuicMasque);
        let dtls = Camouflage::new(Shape::WebRtcDtls);
        let record = quic.frame(b"hello").unwrap();
        // A DTLS parser must not accept a QUIC-shaped record.
        assert!(dtls.unframe(&record).is_err());
    }

    #[tokio::test]
    async fn reality_authenticates_a_client_and_decoys_a_prober() {
        const EPOCH: u64 = 9_000;
        let secret = RealitySecret::generate().unwrap();
        let key = secret.public();
        let transport = Transport::new(Camouflage::new(Shape::QuicMasque));
        let listener = transport.listen("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            // First connection: a legitimate client.
            let auth_seed = match listener.accept_reality(&secret, EPOCH).await.unwrap() {
                RealityAccept::Authenticated {
                    mut conn,
                    session_seed,
                } => {
                    assert_eq!(conn.recv().await.unwrap(), b"authed payload");
                    Some(session_seed)
                }
                RealityAccept::Decoy { .. } => None,
            };
            // Second connection: an active prober with the wrong capability.
            let prober_is_decoy = matches!(
                listener.accept_reality(&secret, EPOCH).await.unwrap(),
                RealityAccept::Decoy { .. }
            );
            (auth_seed, prober_is_decoy)
        });

        // Legitimate client authenticates and sends an obfuscated payload.
        let (mut conn, seed) = transport.dial_reality(&addr, &key, EPOCH).await.unwrap();
        conn.send(b"authed payload").await.unwrap();

        // Prober without the capability: its flight must land on the decoy path.
        let wrong = RealitySecret::generate().unwrap().public();
        let (_probe, _) = transport.dial_reality(&addr, &wrong, EPOCH).await.unwrap();

        let (auth_seed, prober_is_decoy) = server.await.unwrap();
        assert_eq!(
            auth_seed,
            Some(seed),
            "server and client share the session seed"
        );
        assert!(prober_is_decoy, "a prober must be silently decoyed");
    }
}
