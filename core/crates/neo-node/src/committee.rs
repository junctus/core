//! Committee-exit circuits (M28): the subpoena-proof exit over a live circuit.
//!
//! The circuit's hops **are** a threshold committee holding DKG shares
//! ([`neo_mpc::dkg`]) of a joint key `Y` — no party holds the secret `s`. The
//! exit encrypts the destination's response to `Y`
//! ([`neo_mpc::threshold::encrypt`]) and each hop, on the return path,
//! contributes its partial decryption `D_i = y_i·R`. Only the client — holding
//! every hop's Sphinx-derived return secret — recovers the partials and combines
//! them, so **no committee member sees the response plaintext** (the egress that
//! terminates the destination's TLS is the honest exception, since it produced
//! the response before sealing it — that gap is the 2PC-TLS send path, M33).
//!
//! ## Why each partial is sealed to the client
//!
//! Partials accumulate as the response flows back toward the client. A naive
//! plaintext append would let the hop *nearest the client* observe every other
//! hop's partial — a full quorum — and decrypt the response itself, defeating the
//! whole property. To prevent that, each member `i` **seals** its partial under a
//! key derived from its own return secret `s_i` (which only the client re-derives,
//! from [`create_packet_keyed`](neo_crypto::create_packet_keyed)). A downstream
//! member relays the sealed blobs but cannot open them, so it never assembles a
//! quorum; only the client opens all of them.
//!
//! This module is the return-path crypto core (sealing + client recovery). Wiring
//! it onto the live persistent circuit (the M26 serving loop) and the
//! `neo run --committee` role build on top of it.

use std::collections::HashSet;
use std::sync::Mutex;

use neo_core::{Error, NodeId, NodeIdentity, Result};
use neo_crypto::{
    create_packet_keyed, process, Processed, ReplayCache, Session, SphinxHop, SphinxPacket,
};
use neo_mpc::threshold::{self, Ciphertext, Partial};
use neo_mpc::vss::{KeyCommitments, KeyShare};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::forward::{Hop, NextHop};
use crate::run::{connect_verified, read_frame, write_frame};

/// A serialized [`Partial`] is 97 bytes; sealing adds a keyed MAC.
const PARTIAL_LEN: usize = 97;
/// Integrity tag length on a sealed partial.
const SEAL_MAC_LEN: usize = 16;
/// Total sealed-partial length on the wire.
pub const SEALED_PARTIAL_LEN: usize = PARTIAL_LEN + SEAL_MAC_LEN;
/// Bound on sealed partials in one response (one per committee member).
const MAX_SEALED_PARTIALS: usize = neo_mpc::MAX_MEMBERS;

fn seal_key(return_secret: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("neo-committee-partial-seal-v1", return_secret)
}

/// XOR `data` with a keystream derived from `key` (one sealed partial, one key).
fn xor_mask(data: &mut [u8], key: &[u8; 32]) {
    let mut ks = vec![0u8; data.len()];
    blake3::Hasher::new_keyed(key).finalize_xof().fill(&mut ks);
    for (b, k) in data.iter_mut().zip(&ks) {
        *b ^= k;
    }
}

fn seal_mac(key: &[u8; 32], body: &[u8]) -> [u8; SEAL_MAC_LEN] {
    let mac_key = blake3::derive_key("neo-committee-partial-mac-v1", key);
    let full = blake3::keyed_hash(&mac_key, body);
    let mut out = [0u8; SEAL_MAC_LEN];
    out.copy_from_slice(&full.as_bytes()[..SEAL_MAC_LEN]);
    out
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A committee member computes and **seals** its partial decryption of `ct` for
/// the client. `return_secret` is the member's Sphinx-derived stream secret for
/// this circuit — only the client re-derives it, so a downstream hop relaying the
/// blob cannot open it (and thus cannot reach a decryption quorum).
pub fn seal_partial(
    return_secret: &[u8; 32],
    share: &KeyShare,
    ct: &Ciphertext,
) -> Result<Vec<u8>> {
    let partial = threshold::partial_decrypt(share, ct)?;
    let key = seal_key(return_secret);
    let mut body = partial.to_bytes().to_vec();
    xor_mask(&mut body, &key);
    let mac = seal_mac(&key, &body);
    body.extend_from_slice(&mac);
    Ok(body)
}

/// The client opens one sealed partial with a member's return secret. Fails if
/// the MAC does not match (wrong key / tampered), so a member can never open a
/// blob sealed to a different member.
pub fn open_partial(return_secret: &[u8; 32], sealed: &[u8]) -> Result<Partial> {
    if sealed.len() != SEALED_PARTIAL_LEN {
        return Err(Error::Decode("sealed partial has the wrong length".into()));
    }
    let key = seal_key(return_secret);
    let (body, mac) = sealed.split_at(PARTIAL_LEN);
    if !ct_eq(mac, &seal_mac(&key, body)) {
        return Err(Error::Crypto(
            "sealed partial failed its integrity check".into(),
        ));
    }
    let mut plain = body.to_vec();
    xor_mask(&mut plain, &key);
    Partial::from_bytes(&plain)
}

/// The response a committee circuit returns to the client: the exit's threshold
/// [`Ciphertext`] plus one sealed partial per committee member on the path.
#[derive(Clone, Debug)]
pub struct CommitteeResponse {
    /// The response encrypted to the committee's joint key (only a quorum decrypts).
    pub ciphertext: Ciphertext,
    /// Each member's partial, sealed to the client.
    pub sealed_partials: Vec<Vec<u8>>,
}

impl CommitteeResponse {
    /// Serialize as `ct_len (u32) || ct || count (u16) || count × sealed partials`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let ct = self.ciphertext.to_bytes();
        let mut out =
            Vec::with_capacity(6 + ct.len() + self.sealed_partials.len() * SEALED_PARTIAL_LEN);
        out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        out.extend_from_slice(&ct);
        out.extend_from_slice(&(self.sealed_partials.len() as u16).to_be_bytes());
        for sealed in &self.sealed_partials {
            out.extend_from_slice(sealed);
        }
        out
    }

    /// Parse [`to_bytes`](Self::to_bytes). Bounds-checked; never panics.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut cur = bytes;
        let ct_len = u32::from_be_bytes(take(&mut cur, 4)?.try_into().expect("4 bytes")) as usize;
        let ct = Ciphertext::from_bytes(take(&mut cur, ct_len)?)?;
        let count = u16::from_be_bytes(take(&mut cur, 2)?.try_into().expect("2 bytes")) as usize;
        if count > MAX_SEALED_PARTIALS {
            return Err(Error::Decode("too many sealed partials".into()));
        }
        let mut sealed_partials = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            sealed_partials.push(take(&mut cur, SEALED_PARTIAL_LEN)?.to_vec());
        }
        if !cur.is_empty() {
            return Err(Error::Decode(
                "trailing bytes after committee response".into(),
            ));
        }
        Ok(Self {
            ciphertext: ct,
            sealed_partials,
        })
    }
}

/// The client recovers the response plaintext: open each sealed partial with a
/// matching return secret (the MAC identifies the right one), de-duplicate by
/// member, and combine a threshold quorum. Returns an error — never garbage — if
/// fewer than `threshold_k` partials open and verify.
pub fn open_response(
    commitments: &KeyCommitments,
    threshold_k: usize,
    response: &CommitteeResponse,
    return_secrets: &[[u8; 32]],
) -> Result<Vec<u8>> {
    let mut partials = Vec::new();
    let mut seen = HashSet::new();
    for sealed in &response.sealed_partials {
        for secret in return_secrets {
            if let Ok(p) = open_partial(secret, sealed) {
                if seen.insert(p.member()) {
                    partials.push(p);
                }
                break;
            }
        }
    }
    threshold::combine(commitments, threshold_k, &response.ciphertext, &partials)
}

/// Split `n` bytes off the front of `cur`, erroring (not panicking) if short.
fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if cur.len() < n {
        return Err(Error::Decode("truncated committee response".into()));
    }
    let (head, tail) = cur.split_at(n);
    *cur = tail;
    Ok(head)
}

// ---- live circuit transport -----------------------------------------------

/// A committee circuit's exit handler: turn a request into a response (a real
/// exit performs the request; tests echo).
pub type ExitHandler = fn(&[u8]) -> Vec<u8>;

/// Client: send `request` through a committee `circuit` — each hop a committee
/// member holding a share of `commitments` — and recover the response the exit
/// encrypted to the committee's joint key, combining the members' sealed partials
/// gathered on the return path. Only this client ever sees the response
/// plaintext; no committee member does (bar the egress at the moment it fetches
/// the destination — the documented M33 send-path gap).
pub async fn committee_request_response(
    identity: &NodeIdentity,
    circuit: &[Hop],
    commitments: &KeyCommitments,
    threshold_k: usize,
    request: &[u8],
) -> Result<Vec<u8>> {
    if circuit.is_empty() {
        return Err(Error::Config(
            "a committee circuit needs at least one hop".into(),
        ));
    }
    let hops: Vec<SphinxHop> = circuit
        .iter()
        .map(|h| SphinxHop {
            id: *h.id.as_bytes(),
            public: h.sphinx,
        })
        .collect();
    // The exit must know the committee key to encrypt its response to; carry it
    // in the exit-only Sphinx payload, ahead of the request itself.
    let mut payload = Vec::with_capacity(2 + commitments.to_bytes().len() + request.len());
    let cbytes = commitments.to_bytes();
    payload.extend_from_slice(&(cbytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(&cbytes);
    payload.extend_from_slice(request);

    let (packet, secrets) = create_packet_keyed(&hops, &payload)?;
    let (mut stream, mut result) =
        connect_verified(&circuit[0].addr, identity, &circuit[0].id).await?;
    // Declare the committee-circuit mode, then hand over the onion.
    write_frame(
        &mut stream,
        &result.session.seal(&[crate::run::FRAME_COMMITTEE])?,
    )
    .await?;
    let framed = result.session.seal(&packet.to_bytes())?;
    write_frame(&mut stream, &framed).await?;

    let sealed = read_frame(&mut stream).await?;
    let bytes = result.session.open(&sealed)?;
    let response = CommitteeResponse::from_bytes(&bytes)?;
    open_response(commitments, threshold_k, &response, &secrets)
}

/// Relay/exit: handle one committee-circuit connection. Peels one Sphinx layer,
/// then either forwards to the next hop and, on the returning
/// [`CommitteeResponse`], appends **this** member's sealed partial; or, at the
/// exit, runs `exit`, encrypts the response to the committee key from the
/// payload, discards the plaintext, and seals its own partial. `share` is this
/// member's DKG share of the committee key.
pub async fn handle_committee_circuit<S, R>(
    identity: &NodeIdentity,
    share: &KeyShare,
    prev: &mut S,
    prev_session: &mut Session,
    resolver: &R,
    replay: &Mutex<ReplayCache>,
    exit: ExitHandler,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: NextHop,
{
    let sealed = read_frame(prev).await?;
    let packet_bytes = prev_session.open(&sealed)?;
    let packet = SphinxPacket::from_bytes(&packet_bytes)?;
    // This member's return secret — the client re-derives the same value (from
    // create_packet_keyed) and uses it to open this member's sealed partial.
    let secret = identity.sphinx_shared(packet.alpha())?;

    let processed = {
        let mut cache = replay.lock().expect("replay cache poisoned");
        process(identity, &mut cache, &packet)?
    };

    let response = match processed {
        Processed::Deliver { payload } => {
            // Exit: payload is [commitments || request]. Encrypt the response to
            // the committee key and discard the plaintext after sealing.
            let (commitments, request) = parse_exit_payload(&payload)?;
            let response_plaintext = exit(&request);
            let ciphertext = threshold::encrypt(&commitments, &response_plaintext)?;
            let sealed_partial = seal_partial(&secret, share, &ciphertext)?;
            CommitteeResponse {
                ciphertext,
                sealed_partials: vec![sealed_partial],
            }
        }
        Processed::Forward { next, packet } => {
            let next_id = NodeId::from_bytes(next);
            let addr = resolver
                .addr_of(&next_id)
                .ok_or_else(|| Error::Config(format!("no address for next hop {next_id}")))?;
            let (mut next_stream, mut next_result) =
                connect_verified(&addr, identity, &next_id).await?;
            // Propagate the committee mode to the next hop, then the peeled packet.
            write_frame(
                &mut next_stream,
                &next_result.session.seal(&[crate::run::FRAME_COMMITTEE])?,
            )
            .await?;
            let framed = next_result.session.seal(&packet.to_bytes())?;
            write_frame(&mut next_stream, &framed).await?;
            let sealed = read_frame(&mut next_stream).await?;
            let bytes = next_result.session.open(&sealed)?;
            let mut response = CommitteeResponse::from_bytes(&bytes)?;
            // Add this member's sealed partial for the exit's ciphertext.
            response
                .sealed_partials
                .push(seal_partial(&secret, share, &response.ciphertext)?);
            response
        }
    };

    let out = prev_session.seal(&response.to_bytes())?;
    write_frame(prev, &out).await?;
    Ok(())
}

/// Parse an exit payload `[commitments_len (u16) || commitments || request]`.
fn parse_exit_payload(payload: &[u8]) -> Result<(KeyCommitments, Vec<u8>)> {
    let mut cur = payload;
    let clen = u16::from_be_bytes(take(&mut cur, 2)?.try_into().expect("2 bytes")) as usize;
    let commitments = KeyCommitments::from_bytes(take(&mut cur, clen)?)?;
    Ok((commitments, cur.to_vec()))
}

// ---- networked distributed key generation ---------------------------------

/// Serialize a DKG exchange message: `[commitment_len (u16) || commitment ||
/// share (33)]` — this member's public Feldman commitment plus the private share
/// it deals to the peer. Sent over the authenticated, encrypted M1 session.
fn encode_dkg_msg(commitment: &KeyCommitments, share_for_peer: &KeyShare) -> Vec<u8> {
    let cbytes = commitment.to_bytes();
    let mut out = Vec::with_capacity(2 + cbytes.len() + 33);
    out.extend_from_slice(&(cbytes.len() as u16).to_be_bytes());
    out.extend_from_slice(&cbytes);
    out.extend_from_slice(&share_for_peer.to_bytes());
    out
}

fn decode_dkg_msg(bytes: &[u8]) -> Result<(KeyCommitments, KeyShare)> {
    let mut cur = bytes;
    let clen = u16::from_be_bytes(take(&mut cur, 2)?.try_into().expect("2 bytes")) as usize;
    let commitment = KeyCommitments::from_bytes(take(&mut cur, clen)?)?;
    let share = KeyShare::from_bytes(take(&mut cur, 33)?)?;
    Ok((commitment, share))
}

/// Run **networked Joint-Feldman DKG** among the committee `roster` from this
/// member's viewpoint (`identity`, 1-based `index`, its committee `listener`).
/// Returns this member's aggregate [`KeyShare`] and the agreed
/// [`CommitteeDescriptor`]. No party ever holds the joint secret `s`.
///
/// Coordination: for each pair `(a, b)` with `a < b`, the **higher** index dials
/// the lower; the lower accepts. Both sides send their commitment + the private
/// share dealt to the peer and read the peer's, over the authenticated session —
/// so shares stay confidential and are attributed to a verified sender. Each
/// received share is checked against its dealer's commitment (abort on a bad
/// share). Requires every member online; a complaint/disqualification round for
/// liveness under active faults is deferred (documented in [`neo_mpc::dkg`]).
pub async fn run_dkg(
    identity: &NodeIdentity,
    index: u8,
    roster: &[CommitteeMemberInfo],
    listener: &tokio::net::TcpListener,
    threshold: usize,
) -> Result<(KeyShare, CommitteeDescriptor)> {
    use neo_mpc::dkg;

    if !roster.iter().any(|m| m.index == index) {
        return Err(Error::Config(
            "this node is not in the committee roster".into(),
        ));
    }
    let cfg = neo_mpc::CommitteeConfig {
        members: roster.len(),
        threshold,
    };
    let contribution = dkg::Contribution::generate(index, &cfg)?;
    let my_commitment = contribution.commitment().clone();

    // Received from each peer: its commitment + the share it dealt to me.
    let mut received: std::collections::HashMap<u8, (KeyCommitments, KeyShare)> =
        std::collections::HashMap::new();

    // Accept from higher-indexed peers.
    let higher = roster.iter().filter(|m| m.index > index).count();
    for _ in 0..higher {
        let (mut stream, result) = crate::run::accept(listener, identity).await?;
        let peer = roster
            .iter()
            .find(|m| m.id == result.peer_id)
            .ok_or_else(|| Error::Crypto("DKG connection from a non-roster peer".into()))?;
        let mut session = result.session;
        // Read the peer's message, then reply with ours.
        let bytes = session.open(&read_frame(&mut stream).await?)?;
        let (peer_commitment, share_for_me) = decode_dkg_msg(&bytes)?;
        let msg = encode_dkg_msg(&my_commitment, &contribution.share_for(peer.index)?);
        write_frame(&mut stream, &session.seal(&msg)?).await?;
        received.insert(peer.index, (peer_commitment, share_for_me));
    }

    // Dial lower-indexed peers.
    for peer in roster.iter().filter(|m| m.index < index) {
        let (mut stream, mut result) = connect_verified(&peer.addr, identity, &peer.id).await?;
        let msg = encode_dkg_msg(&my_commitment, &contribution.share_for(peer.index)?);
        write_frame(&mut stream, &result.session.seal(&msg)?).await?;
        let bytes = result.session.open(&read_frame(&mut stream).await?)?;
        let (peer_commitment, share_for_me) = decode_dkg_msg(&bytes)?;
        received.insert(peer.index, (peer_commitment, share_for_me));
    }

    // Verify every dealt share against its dealer's commitment, then aggregate.
    let mut all_commitments = vec![my_commitment];
    let mut dealt_to_me = vec![contribution.share_for(index)?];
    for peer in roster.iter().filter(|m| m.index != index) {
        let (commitment, share) = received
            .get(&peer.index)
            .ok_or_else(|| Error::Crypto(format!("no DKG message from member {}", peer.index)))?;
        if !share.verify(commitment) {
            return Err(Error::Crypto(format!(
                "DKG share from member {} failed its commitment",
                peer.index
            )));
        }
        all_commitments.push(commitment.clone());
        dealt_to_me.push(share.clone());
    }

    let commitments = dkg::joint_commitments(&all_commitments)?;
    let my_share = dkg::aggregate_share(index, &dealt_to_me)?;
    let descriptor = CommitteeDescriptor {
        commitments,
        members: roster.to_vec(),
    };
    Ok((my_share, descriptor))
}

// ---- discovery: the committee descriptor ----------------------------------

/// A committee member's routing identity in a [`CommitteeDescriptor`]: its
/// committee index (matching its [`KeyShare`]'s `member`) plus how to reach and
/// onion-route to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitteeMemberInfo {
    /// 1-based committee index (equals this member's `KeyShare::member`).
    pub index: u8,
    /// The member's node id (authenticated at dial via `connect_verified`).
    pub id: NodeId,
    /// The member's Ristretto routing key, for the Sphinx layer to it.
    pub sphinx: [u8; 32],
    /// A dialable address for the member.
    pub addr: String,
}

/// The published identity of a committee: its joint key (and threshold, = the
/// commitment count), plus the member roster. A client fetches this — like a
/// relay snapshot, it is only trusted once its members and joint key are — and
/// routes a committee circuit through the roster to reach the exit. The exit is
/// the last member on the built circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitteeDescriptor {
    /// Joint key `commitments[0]` and threshold `= commitments.len()`.
    pub commitments: KeyCommitments,
    /// The committee members, in index order.
    pub members: Vec<CommitteeMemberInfo>,
}

impl CommitteeDescriptor {
    /// The reconstruction threshold `k` (the committed polynomial degree + 1).
    pub fn threshold(&self) -> usize {
        self.commitments.0.len()
    }

    /// Build a committee circuit routing through every member in index order
    /// (the last is the exit). Every hop contributes a partial, so the client
    /// gathers `members.len()` partials and needs [`threshold`](Self::threshold).
    pub fn circuit(&self) -> Result<Vec<Hop>> {
        if self.members.len() < self.threshold() {
            return Err(Error::Config(
                "committee has fewer members than its threshold".into(),
            ));
        }
        Ok(self
            .members
            .iter()
            .map(|m| Hop {
                id: m.id,
                sphinx: m.sphinx,
                addr: m.addr.clone(),
            })
            .collect())
    }

    /// Serialize for publication.
    pub fn to_bytes(&self) -> Vec<u8> {
        let cbytes = self.commitments.to_bytes();
        let mut out = Vec::new();
        out.extend_from_slice(&(cbytes.len() as u16).to_be_bytes());
        out.extend_from_slice(&cbytes);
        out.extend_from_slice(&(self.members.len() as u16).to_be_bytes());
        for m in &self.members {
            out.push(m.index);
            out.extend_from_slice(m.id.as_bytes());
            out.extend_from_slice(&m.sphinx);
            out.extend_from_slice(&(m.addr.len() as u16).to_be_bytes());
            out.extend_from_slice(m.addr.as_bytes());
        }
        out
    }

    /// Parse [`to_bytes`](Self::to_bytes). Bounds-checked; never panics.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut cur = bytes;
        let clen = u16::from_be_bytes(take(&mut cur, 2)?.try_into().expect("2 bytes")) as usize;
        let commitments = KeyCommitments::from_bytes(take(&mut cur, clen)?)?;
        let count = u16::from_be_bytes(take(&mut cur, 2)?.try_into().expect("2 bytes")) as usize;
        if count > neo_mpc::MAX_MEMBERS {
            return Err(Error::Decode("too many committee members".into()));
        }
        let mut members = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            let index = take(&mut cur, 1)?[0];
            let id = NodeId::from_bytes(take(&mut cur, 32)?.try_into().expect("32 bytes"));
            let sphinx: [u8; 32] = take(&mut cur, 32)?.try_into().expect("32 bytes");
            let alen = u16::from_be_bytes(take(&mut cur, 2)?.try_into().expect("2 bytes")) as usize;
            if alen > 256 {
                return Err(Error::Decode("committee member address too long".into()));
            }
            let addr = std::str::from_utf8(take(&mut cur, alen)?)
                .map_err(|_| Error::Decode("committee member address not UTF-8".into()))?
                .to_string();
            members.push(CommitteeMemberInfo {
                index,
                id,
                sphinx,
                addr,
            });
        }
        if !cur.is_empty() {
            return Err(Error::Decode(
                "trailing bytes after committee descriptor".into(),
            ));
        }
        Ok(Self {
            commitments,
            members,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neo_mpc::dkg;
    use neo_mpc::CommitteeConfig;
    use std::collections::HashMap;

    /// A DKG committee (no party holds `s`) plus a fresh return secret per hop.
    fn committee(members: usize, threshold: usize) -> (KeyCommitments, Vec<KeyShare>) {
        let cfg = CommitteeConfig { members, threshold };
        let contributions: Vec<dkg::Contribution> = (1..=members as u8)
            .map(|m| dkg::Contribution::generate(m, &cfg).unwrap())
            .collect();
        let mut shares = Vec::new();
        for recipient in 1..=members as u8 {
            let dealt: Vec<KeyShare> = contributions
                .iter()
                .map(|d| d.share_for(recipient).unwrap())
                .collect();
            shares.push(dkg::aggregate_share(recipient, &dealt).unwrap());
        }
        let commitments = dkg::joint_commitments(
            &contributions
                .iter()
                .map(|c| c.commitment().clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        (commitments, shares)
    }

    fn secret(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn only_the_client_recovers_the_response_never_a_relaying_member() {
        // A 3-hop committee circuit (threshold 3) over a 3-member committee.
        let (commitments, shares) = committee(3, 3);
        let secrets = [secret(11), secret(22), secret(33)];
        let response_plaintext = b"HTTP/1.1 200 OK\r\n\r\ntop secret body";

        // Exit encrypts the response to the joint key.
        let ct = threshold::encrypt(&commitments, response_plaintext).unwrap();
        // Each hop seals its partial under its own return secret.
        let sealed: Vec<Vec<u8>> = (0..3)
            .map(|i| seal_partial(&secrets[i], &shares[i], &ct).unwrap())
            .collect();
        let response = CommitteeResponse {
            ciphertext: ct,
            sealed_partials: sealed,
        };

        // The client, holding every return secret, recovers the plaintext.
        assert_eq!(
            open_response(&commitments, 3, &response, &secrets).unwrap(),
            response_plaintext
        );

        // A relaying member — it forwards all three sealed blobs but knows only
        // its OWN return secret — opens just one partial, below threshold, so it
        // cannot decrypt. This is the property that makes on-circuit fan-in safe.
        let just_mine = [secrets[0]];
        assert!(
            open_response(&commitments, 3, &response, &just_mine).is_err(),
            "a hop relaying every sealed partial must still be unable to decrypt"
        );
    }

    #[test]
    fn a_sealed_partial_opens_only_with_its_own_secret() {
        let (_c, shares) = committee(3, 3);
        let ct = threshold::encrypt(&_c, b"x").unwrap();
        let sealed = seal_partial(&secret(7), &shares[0], &ct).unwrap();
        assert_eq!(sealed.len(), SEALED_PARTIAL_LEN);
        assert!(open_partial(&secret(7), &sealed).is_ok());
        assert!(
            open_partial(&secret(8), &sealed).is_err(),
            "the wrong return secret must fail the MAC, not yield a forged partial"
        );
    }

    #[test]
    fn committee_response_roundtrips_on_the_wire() {
        let (commitments, shares) = committee(4, 3);
        let ct = threshold::encrypt(&commitments, b"a response").unwrap();
        let secrets: Vec<[u8; 32]> = (0..4).map(|i| secret(i as u8 + 1)).collect();
        let sealed: Vec<Vec<u8>> = (0..4)
            .map(|i| seal_partial(&secrets[i], &shares[i], &ct).unwrap())
            .collect();
        let response = CommitteeResponse {
            ciphertext: ct,
            sealed_partials: sealed,
        };
        let parsed = CommitteeResponse::from_bytes(&response.to_bytes()).unwrap();
        assert_eq!(
            open_response(&commitments, 3, &parsed, &secrets).unwrap(),
            b"a response"
        );
        // A truncated buffer is rejected, not panicked.
        assert!(CommitteeResponse::from_bytes(&response.to_bytes()[..5]).is_err());
    }

    #[tokio::test]
    async fn networked_dkg_establishes_a_shared_key_no_party_holds() {
        // Three members run Joint-Feldman DKG over real sockets; each ends with a
        // share of a joint key nobody dealt, and they agree on the descriptor.
        let ids: Vec<NodeIdentity> = (0..3).map(|_| NodeIdentity::generate().unwrap()).collect();

        // Bind each member's listener first so the roster addresses are known.
        let mut listeners = Vec::new();
        let mut roster = Vec::new();
        for (i, id) in ids.iter().enumerate() {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap().to_string();
            roster.push(CommitteeMemberInfo {
                index: (i + 1) as u8,
                id: id.id(),
                sphinx: id.public().sphinx,
                addr,
            });
            listeners.push(l);
        }

        // Run DKG concurrently for all members.
        let mut tasks = Vec::new();
        for (id, listener) in ids.iter().zip(listeners) {
            let idb = id.to_bytes();
            let roster_c = roster.clone();
            let index = roster.iter().find(|m| m.id == id.id()).unwrap().index;
            tasks.push(tokio::spawn(async move {
                let identity = NodeIdentity::from_bytes(&idb).unwrap();
                run_dkg(&identity, index, &roster_c, &listener, 2).await
            }));
        }
        let mut results = Vec::new();
        for t in tasks {
            results.push(t.await.unwrap().unwrap());
        }

        // Every member agrees on the joint key, and each share verifies against it.
        let commitments = results[0].1.commitments.clone();
        for (share, desc) in &results {
            assert_eq!(
                desc.commitments, commitments,
                "members agree on the joint key"
            );
            assert!(share.verify(&commitments), "each aggregate share verifies");
        }

        // The shares actually threshold-decrypt — proving a usable key that no
        // single party holds (a quorum of 2 recovers; the run had no dealer).
        let ct = threshold::encrypt(&commitments, b"secret").unwrap();
        let partials: Vec<_> = results[..2]
            .iter()
            .map(|(s, _)| threshold::partial_decrypt(s, &ct).unwrap())
            .collect();
        assert_eq!(
            threshold::combine(&commitments, 2, &ct, &partials).unwrap(),
            b"secret"
        );
    }

    #[test]
    fn committee_descriptor_roundtrips_and_builds_a_circuit() {
        let (commitments, _shares) = committee(3, 2);
        let members: Vec<CommitteeMemberInfo> = (1..=3u8)
            .map(|i| {
                let id = NodeIdentity::generate().unwrap();
                CommitteeMemberInfo {
                    index: i,
                    id: id.id(),
                    sphinx: id.public().sphinx,
                    addr: format!("10.0.0.{i}:9000"),
                }
            })
            .collect();
        let desc = CommitteeDescriptor {
            commitments,
            members,
        };
        assert_eq!(desc.threshold(), 2);
        let parsed = CommitteeDescriptor::from_bytes(&desc.to_bytes()).unwrap();
        assert_eq!(parsed, desc);
        assert_eq!(parsed.circuit().unwrap().len(), 3);
    }

    fn echo(request: &[u8]) -> Vec<u8> {
        request.to_vec()
    }

    fn hop_of(identity: &NodeIdentity, addr: &str) -> Hop {
        let p = identity.public();
        Hop {
            id: p.id,
            sphinx: p.sphinx,
            addr: addr.to_string(),
        }
    }

    async fn spawn_committee_hop(
        identity_bytes: Vec<u8>,
        share: KeyShare,
        resolver: HashMap<NodeId, String>,
    ) -> (String, tokio::task::JoinHandle<Result<()>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = tokio::spawn(async move {
            let identity = NodeIdentity::from_bytes(&identity_bytes).unwrap();
            let (stream, result) = crate::run::accept(&listener, &identity).await.unwrap();
            let replay = Mutex::new(ReplayCache::new());
            // Route through the real serve dispatcher so the FRAME_COMMITTEE mode
            // byte is exercised end to end, exactly as a live relay does.
            crate::serve::serve_connection(
                &identity,
                stream,
                result.session,
                &resolver,
                &replay,
                crate::circuit::ExitPolicy::default(),
                Some(crate::serve::CommitteeServing {
                    share: &share,
                    exit: echo,
                }),
            )
            .await
            .map(|_| ())
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn committee_circuit_returns_a_response_only_the_client_can_read() {
        // A live 3-hop circuit whose hops are a 3-member DKG committee (threshold
        // 2). The exit encrypts the echoed response to the joint key; each hop
        // seals its partial with its live Sphinx return secret; the client
        // combines them. No single hop can decrypt (proven in the unit tests);
        // here the full round trip runs over real sockets.
        let (commitments, shares) = committee(3, 2);
        let m: Vec<NodeIdentity> = (0..3).map(|_| NodeIdentity::generate().unwrap()).collect();
        let client = NodeIdentity::generate().unwrap();

        // Spawn exit → middle → entry, wiring each relay's resolver to its next hop.
        let (exit_addr, exit_task) =
            spawn_committee_hop(m[2].to_bytes(), shares[2].clone(), HashMap::new()).await;
        let mut r1 = HashMap::new();
        r1.insert(m[2].id(), exit_addr.clone());
        let (mid_addr, mid_task) =
            spawn_committee_hop(m[1].to_bytes(), shares[1].clone(), r1).await;
        let mut r0 = HashMap::new();
        r0.insert(m[1].id(), mid_addr.clone());
        let (entry_addr, entry_task) =
            spawn_committee_hop(m[0].to_bytes(), shares[0].clone(), r0).await;

        let circuit = vec![
            hop_of(&m[0], &entry_addr),
            hop_of(&m[1], &mid_addr),
            hop_of(&m[2], &exit_addr),
        ];
        let request = b"GET /secret HTTP/1.1";
        let response = committee_request_response(&client, &circuit, &commitments, 2, request)
            .await
            .unwrap();
        assert_eq!(response, request, "the client recovers the echoed response");

        entry_task.await.unwrap().unwrap();
        mid_task.await.unwrap().unwrap();
        exit_task.await.unwrap().unwrap();
    }
}
