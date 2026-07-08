//! Full Sphinx packet format for multi-hop onion routing (M2).
//!
//! A proper Sphinx over the prime-order **Ristretto** group:
//! - **Fixed-size packets** — every packet is the same size regardless of path
//!   length or a hop's position, so size never leaks routing information.
//! - **Per-hop blinded shared secrets** — one ephemeral key is blinded at each
//!   hop (`α_{i+1} = b_i · α_i`), so the header stays small and unlinkable.
//! - **The filler trick** — deterministic padding keeps the header a constant
//!   size as each hop shifts it, without breaking the per-hop MACs.
//! - **Per-layer MAC** (`γ`) over the header (`β`) — tamper is rejected before
//!   any processing.
//! - **Onion-encrypted fixed payload** (`δ`) — each hop removes one layer.
//! - **Replay tags** — each hop remembers the per-packet secret and rejects
//!   duplicates.
//!
//! Each hop's routing key is the node's derived Ristretto key
//! ([`NodeIdentity::sphinx_public`](neo_core::NodeIdentity::sphinx_public)).
//! End-to-end confidentiality/integrity of the *carried* data is provided by the
//! neo session/slicing layers above this; Sphinx provides route privacy.

use std::collections::HashSet;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::Scalar;
use neo_core::{Error, NodeIdentity, Result};
use zeroize::Zeroize;

const ADDR_LEN: usize = 32;
const MAC_LEN: usize = 16;
const HOP_LEN: usize = ADDR_LEN + MAC_LEN; // one routing block: next addr + next MAC
/// Maximum path length a packet can carry.
pub const MAX_HOPS: usize = 5;
const BETA_LEN: usize = HOP_LEN * MAX_HOPS;
/// Fixed onion payload size (2-byte length prefix + data).
pub const PAYLOAD_LEN: usize = 2048;
const EXIT_ADDR: [u8; 32] = [0u8; 32];

/// A hop in a Sphinx path: its routing address and Ristretto routing key.
#[derive(Clone, Debug)]
pub struct SphinxHop {
    /// Routing address (the hop's `NodeId` bytes).
    pub id: [u8; 32],
    /// Compressed Ristretto routing public key (`NodeIdentity::sphinx_public`).
    pub public: [u8; 32],
}

/// A fixed-size Sphinx packet.
#[derive(Clone)]
pub struct SphinxPacket {
    alpha: [u8; 32],
    beta: [u8; BETA_LEN],
    gamma: [u8; MAC_LEN],
    delta: Vec<u8>, // always PAYLOAD_LEN
}

/// The total wire size of a packet (constant).
pub const PACKET_LEN: usize = 32 + BETA_LEN + MAC_LEN + PAYLOAD_LEN;

impl SphinxPacket {
    /// Serialize to the fixed wire form (`PACKET_LEN` bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PACKET_LEN);
        out.extend_from_slice(&self.alpha);
        out.extend_from_slice(&self.gamma);
        out.extend_from_slice(&self.beta);
        out.extend_from_slice(&self.delta);
        out
    }

    /// Parse from the fixed wire form.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PACKET_LEN {
            return Err(Error::Decode("wrong Sphinx packet length".into()));
        }
        let mut alpha = [0u8; 32];
        alpha.copy_from_slice(&bytes[..32]);
        let mut gamma = [0u8; MAC_LEN];
        gamma.copy_from_slice(&bytes[32..32 + MAC_LEN]);
        let mut beta = [0u8; BETA_LEN];
        beta.copy_from_slice(&bytes[32 + MAC_LEN..32 + MAC_LEN + BETA_LEN]);
        let delta = bytes[32 + MAC_LEN + BETA_LEN..].to_vec();
        Ok(Self {
            alpha,
            beta,
            gamma,
            delta,
        })
    }
}

/// The result of processing a packet at a hop.
pub enum Processed {
    /// Forward `packet` to the node addressed by `next`.
    Forward {
        /// Next hop's routing address.
        next: [u8; 32],
        /// The transformed packet (boxed — it is much larger than a delivered payload).
        packet: Box<SphinxPacket>,
    },
    /// This node is the exit; here is the delivered payload.
    Deliver {
        /// The recovered payload.
        payload: Vec<u8>,
    },
}

/// Per-node record of seen packets, for replay rejection.
#[derive(Default)]
pub struct ReplayCache {
    seen: HashSet<[u8; 32]>,
}

impl ReplayCache {
    /// A new, empty cache.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Build a Sphinx packet for `path` carrying `payload`.
pub fn create_packet(path: &[SphinxHop], payload: &[u8]) -> Result<SphinxPacket> {
    let n = path.len();
    if n == 0 || n > MAX_HOPS {
        return Err(Error::Config(format!("path length must be 1..={MAX_HOPS}")));
    }
    if payload.len() + 2 > PAYLOAD_LEN {
        return Err(Error::Config(
            "payload too large for a Sphinx packet".into(),
        ));
    }

    // 1. Ephemeral scalar.
    let mut wide = [0u8; 64];
    getrandom::getrandom(&mut wide).map_err(|e| Error::Rng(e.to_string()))?;
    let mut x = Scalar::from_bytes_mod_order_wide(&wide);
    wide.zeroize();

    // 2. Per-hop blinded ephemerals and shared secrets.
    let mut alphas: Vec<[u8; 32]> = Vec::with_capacity(n);
    let mut secrets: Vec<[u8; 32]> = Vec::with_capacity(n);
    {
        let mut a = x;
        for hop in path {
            let alpha_point = RISTRETTO_BASEPOINT_POINT * a;
            let y = CompressedRistretto::from_slice(&hop.public)
                .map_err(|_| Error::Decode("bad hop key length".into()))?
                .decompress()
                .ok_or_else(|| Error::Crypto("hop key not a valid point".into()))?;
            let alpha_c = alpha_point.compress().to_bytes();
            let s_c = (y * a).compress().to_bytes();
            let b = blinding(&alpha_c, &s_c);
            alphas.push(alpha_c);
            secrets.push(s_c);
            a *= b;
        }
        a.zeroize();
    }
    x.zeroize();

    let rho: Vec<[u8; 32]> = secrets
        .iter()
        .map(|s| subkey("neo-sphinx-rho-v1", s))
        .collect();
    let mu: Vec<[u8; 32]> = secrets
        .iter()
        .map(|s| subkey("neo-sphinx-mu-v1", s))
        .collect();
    let pi: Vec<[u8; 32]> = secrets
        .iter()
        .map(|s| subkey("neo-sphinx-pi-v1", s))
        .collect();

    // 3. Filler that keeps β constant-size across hops.
    let filler = generate_filler(&rho);

    // 4. Build β from the innermost hop outward.
    let mut beta = [0u8; BETA_LEN];
    let mut gamma = [0u8; MAC_LEN];
    let mut next_addr = EXIT_ADDR;
    for i in (0..n).rev() {
        let mut new_beta = [0u8; BETA_LEN];
        new_beta[..ADDR_LEN].copy_from_slice(&next_addr);
        new_beta[ADDR_LEN..HOP_LEN].copy_from_slice(&gamma);
        new_beta[HOP_LEN..].copy_from_slice(&beta[..BETA_LEN - HOP_LEN]);
        xor(&mut new_beta, &keystream(&rho[i], BETA_LEN));
        if i == n - 1 {
            let start = BETA_LEN - filler.len();
            new_beta[start..].copy_from_slice(&filler);
        }
        beta = new_beta;
        gamma = mac(&mu[i], &beta);
        next_addr = path[i].id;
    }

    // 5. Onion-encrypt the fixed payload (XOR streams — order-independent).
    let mut delta = vec![0u8; PAYLOAD_LEN];
    delta[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    delta[2..2 + payload.len()].copy_from_slice(payload);
    for key in &pi {
        xor(&mut delta, &keystream(key, PAYLOAD_LEN));
    }

    Ok(SphinxPacket {
        alpha: alphas[0],
        beta,
        gamma,
        delta,
    })
}

/// Process a packet at this node: verify, peel one layer, and either forward or
/// deliver. Rejects replays and tampered headers.
pub fn process(
    identity: &NodeIdentity,
    replay: &mut ReplayCache,
    packet: &SphinxPacket,
) -> Result<Processed> {
    let s = identity.sphinx_shared(packet.alpha)?;

    let tag = subkey("neo-sphinx-replay-v1", &s);
    if !replay.seen.insert(tag) {
        return Err(Error::Crypto("replayed Sphinx packet".into()));
    }

    let rho = subkey("neo-sphinx-rho-v1", &s);
    let mu = subkey("neo-sphinx-mu-v1", &s);
    let pi = subkey("neo-sphinx-pi-v1", &s);

    // Authenticate the header before touching it.
    if !ct_eq(&mac(&mu, &packet.beta), &packet.gamma) {
        return Err(Error::Crypto("Sphinx header MAC failed".into()));
    }

    // Decrypt the header: extend by a zero block, XOR the keystream, then shift.
    let mut ext = vec![0u8; BETA_LEN + HOP_LEN];
    ext[..BETA_LEN].copy_from_slice(&packet.beta);
    xor(&mut ext, &keystream(&rho, BETA_LEN + HOP_LEN));

    let mut next = [0u8; 32];
    next.copy_from_slice(&ext[..ADDR_LEN]);
    let mut next_gamma = [0u8; MAC_LEN];
    next_gamma.copy_from_slice(&ext[ADDR_LEN..HOP_LEN]);
    let mut new_beta = [0u8; BETA_LEN];
    new_beta.copy_from_slice(&ext[HOP_LEN..HOP_LEN + BETA_LEN]);

    // Peel one payload layer.
    let mut delta = packet.delta.clone();
    xor(&mut delta, &keystream(&pi, PAYLOAD_LEN));

    if next == EXIT_ADDR {
        if delta.len() < 2 {
            return Err(Error::Decode("payload too short".into()));
        }
        let len = u16::from_be_bytes([delta[0], delta[1]]) as usize;
        if 2 + len > PAYLOAD_LEN {
            return Err(Error::Decode("bad payload length".into()));
        }
        Ok(Processed::Deliver {
            payload: delta[2..2 + len].to_vec(),
        })
    } else {
        let b = blinding(&packet.alpha, &s);
        let alpha_point = CompressedRistretto::from_slice(&packet.alpha)
            .map_err(|_| Error::Decode("bad alpha length".into()))?
            .decompress()
            .ok_or_else(|| Error::Crypto("alpha not a valid point".into()))?;
        Ok(Processed::Forward {
            next,
            packet: Box::new(SphinxPacket {
                alpha: (alpha_point * b).compress().to_bytes(),
                beta: new_beta,
                gamma: next_gamma,
                delta,
            }),
        })
    }
}

// ---- helpers ---------------------------------------------------------------

/// Deterministic padding so β stays constant-size as hops shift it.
fn generate_filler(rho: &[[u8; 32]]) -> Vec<u8> {
    let n = rho.len();
    let mut filler = Vec::new();
    for key in rho.iter().take(n.saturating_sub(1)) {
        filler.resize(filler.len() + HOP_LEN, 0);
        let ks = keystream(key, BETA_LEN + HOP_LEN);
        let start = BETA_LEN + HOP_LEN - filler.len();
        xor(&mut filler, &ks[start..]);
    }
    filler
}

fn keystream(key: &[u8; 32], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    blake3::Hasher::new_keyed(key).finalize_xof().fill(&mut out);
    out
}

fn subkey(context: &str, secret: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(context, secret)
}

fn mac(key: &[u8; 32], data: &[u8]) -> [u8; MAC_LEN] {
    let full = blake3::keyed_hash(key, data);
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&full.as_bytes()[..MAC_LEN]);
    out
}

fn blinding(alpha: &[u8; 32], secret: &[u8; 32]) -> Scalar {
    let mut hasher = blake3::Hasher::new_derive_key("neo-sphinx-blinding-v1");
    hasher.update(alpha);
    hasher.update(secret);
    let mut wide = [0u8; 64];
    hasher.finalize_xof().fill(&mut wide);
    let scalar = Scalar::from_bytes_mod_order_wide(&wide);
    wide.zeroize();
    scalar
}

fn xor(buf: &mut [u8], keystream: &[u8]) {
    for (b, k) in buf.iter_mut().zip(keystream) {
        *b ^= k;
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop(identity: &NodeIdentity) -> SphinxHop {
        SphinxHop {
            id: *identity.id().as_bytes(),
            public: identity.sphinx_public(),
        }
    }

    fn route(nodes: &[&NodeIdentity], payload: &[u8]) -> Vec<u8> {
        let hops: Vec<SphinxHop> = nodes.iter().map(|n| hop(n)).collect();
        let mut packet = create_packet(&hops, payload).unwrap();
        // The wire size must be constant regardless of path length.
        assert_eq!(packet.to_bytes().len(), PACKET_LEN);

        for (i, node) in nodes.iter().enumerate() {
            let mut cache = ReplayCache::new();
            match process(node, &mut cache, &packet).unwrap() {
                Processed::Forward { next, packet: p } => {
                    assert!(i < nodes.len() - 1, "non-final hop should forward");
                    assert_eq!(&next, nodes[i + 1].id().as_bytes());
                    assert_eq!(p.to_bytes().len(), PACKET_LEN, "size stays constant");
                    packet = *p;
                }
                Processed::Deliver { payload: got } => {
                    assert_eq!(i, nodes.len() - 1, "only the last hop delivers");
                    return got;
                }
            }
        }
        unreachable!("path ended without delivery")
    }

    #[test]
    fn three_hop_packet_delivers_payload() {
        let a = NodeIdentity::generate().unwrap();
        let b = NodeIdentity::generate().unwrap();
        let c = NodeIdentity::generate().unwrap();
        assert_eq!(
            route(&[&a, &b, &c], b"sphinx carried this"),
            b"sphinx carried this"
        );
    }

    #[test]
    fn single_and_max_hop_paths_work() {
        let one = NodeIdentity::generate().unwrap();
        assert_eq!(route(&[&one], b"direct"), b"direct");

        let nodes: Vec<NodeIdentity> = (0..MAX_HOPS)
            .map(|_| NodeIdentity::generate().unwrap())
            .collect();
        let refs: Vec<&NodeIdentity> = nodes.iter().collect();
        assert_eq!(route(&refs, b"five hops"), b"five hops");
    }

    #[test]
    fn packets_are_the_same_size_regardless_of_path_length() {
        let nodes: Vec<NodeIdentity> = (0..MAX_HOPS)
            .map(|_| NodeIdentity::generate().unwrap())
            .collect();
        let one = create_packet(&[hop(&nodes[0])], b"x").unwrap();
        let five: Vec<SphinxHop> = nodes.iter().map(hop).collect();
        let five = create_packet(&five, b"x").unwrap();
        assert_eq!(one.to_bytes().len(), five.to_bytes().len());
    }

    #[test]
    fn wrong_node_cannot_process() {
        let a = NodeIdentity::generate().unwrap();
        let b = NodeIdentity::generate().unwrap();
        let wrong = NodeIdentity::generate().unwrap();
        let packet = create_packet(&[hop(&a), hop(&b)], b"secret").unwrap();
        // `wrong` is not the first hop: its MAC check must fail.
        let mut cache = ReplayCache::new();
        assert!(process(&wrong, &mut cache, &packet).is_err());
    }

    #[test]
    fn tampered_header_is_rejected() {
        let a = NodeIdentity::generate().unwrap();
        let b = NodeIdentity::generate().unwrap();
        let mut packet = create_packet(&[hop(&a), hop(&b)], b"secret").unwrap();
        packet.beta[0] ^= 0xff;
        let mut cache = ReplayCache::new();
        assert!(process(&a, &mut cache, &packet).is_err());
    }

    #[test]
    fn replay_is_rejected() {
        let a = NodeIdentity::generate().unwrap();
        let b = NodeIdentity::generate().unwrap();
        let packet = create_packet(&[hop(&a), hop(&b)], b"secret").unwrap();
        let mut cache = ReplayCache::new();
        assert!(process(&a, &mut cache, &packet).is_ok());
        assert!(
            process(&a, &mut cache, &packet).is_err(),
            "replay must be rejected"
        );
    }

    #[test]
    fn first_hop_does_not_see_the_payload() {
        let a = NodeIdentity::generate().unwrap();
        let b = NodeIdentity::generate().unwrap();
        let c = NodeIdentity::generate().unwrap();
        let packet = create_packet(&[hop(&a), hop(&b), hop(&c)], b"PAYLOAD-SECRET").unwrap();
        let mut cache = ReplayCache::new();
        let forwarded = match process(&a, &mut cache, &packet).unwrap() {
            Processed::Forward { packet, .. } => packet.to_bytes(),
            Processed::Deliver { .. } => panic!("first hop should forward"),
        };
        assert!(!forwarded.windows(14).any(|w| w == b"PAYLOAD-SECRET"));
    }

    #[test]
    fn from_bytes_survives_garbage() {
        let mut seed = 0x99u64;
        for _ in 0..3000 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let len = (seed >> 40) as usize % (PACKET_LEN + 16);
            let bytes: Vec<u8> = (0..len).map(|i| (seed >> (i % 8 * 8)) as u8).collect();
            let _ = SphinxPacket::from_bytes(&bytes);
        }
    }
}
