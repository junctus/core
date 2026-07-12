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

/// The plaintext the exit encrypts per chunk — bounded so each threshold
/// ciphertext stays under [`neo_mpc::threshold::MAX_CIPHERTEXT`] (the AEAD tag
/// adds 16 bytes), so a large response is split across many chunks.
const CHUNK_PLAINTEXT: usize = neo_mpc::threshold::MAX_CIPHERTEXT - 16;
/// Bound on chunks in one response (a parse-time memory bound).
const MAX_CHUNKS: usize = 4096;

/// One chunk of a committee response: a slice of the plaintext (≤ [`CHUNK_PLAINTEXT`])
/// encrypted to the joint key, plus each committee member's partial for it, sealed
/// to the client.
#[derive(Clone, Debug)]
pub struct CommitteeChunk {
    /// This chunk's plaintext, encrypted to the committee's joint key.
    pub ciphertext: Ciphertext,
    /// Each member's partial for this chunk, sealed to the client.
    pub sealed_partials: Vec<Vec<u8>>,
}

impl CommitteeChunk {
    fn encode(&self, out: &mut Vec<u8>) {
        let ct = self.ciphertext.to_bytes();
        out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        out.extend_from_slice(&ct);
        out.extend_from_slice(&(self.sealed_partials.len() as u16).to_be_bytes());
        for sealed in &self.sealed_partials {
            out.extend_from_slice(sealed);
        }
    }

    fn decode(cur: &mut &[u8]) -> Result<Self> {
        let ct_len = u32::from_be_bytes(take(cur, 4)?.try_into().expect("4 bytes")) as usize;
        let ciphertext = Ciphertext::from_bytes(take(cur, ct_len)?)?;
        let count = u16::from_be_bytes(take(cur, 2)?.try_into().expect("2 bytes")) as usize;
        if count > MAX_SEALED_PARTIALS {
            return Err(Error::Decode("too many sealed partials in a chunk".into()));
        }
        let mut sealed_partials = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            sealed_partials.push(take(cur, SEALED_PARTIAL_LEN)?.to_vec());
        }
        Ok(Self {
            ciphertext,
            sealed_partials,
        })
    }

    fn add_partial(&mut self, return_secret: &[u8; 32], share: &KeyShare) -> Result<()> {
        self.sealed_partials
            .push(seal_partial(return_secret, share, &self.ciphertext)?);
        Ok(())
    }
}

/// The response a committee circuit returns to the client: the exit's response
/// split into chunks (each ≤ [`CHUNK_PLAINTEXT`]), each threshold-encrypted with
/// the members' sealed partials. The client decrypts each chunk and concatenates.
#[derive(Clone, Debug)]
pub struct CommitteeResponse {
    /// The response chunks, in order.
    pub chunks: Vec<CommitteeChunk>,
}

impl CommitteeResponse {
    /// The **exit** builds the initial response: encrypt `response` in chunks to
    /// the committee key and seal the exit's own partial for each — the plaintext
    /// is not retained past this. An empty response still yields one empty chunk.
    pub fn seal_at_exit(
        commitments: &KeyCommitments,
        response: &[u8],
        return_secret: &[u8; 32],
        share: &KeyShare,
    ) -> Result<Self> {
        let mut chunks = Vec::new();
        for piece in response.chunks(CHUNK_PLAINTEXT.max(1)) {
            let mut chunk = CommitteeChunk {
                ciphertext: threshold::encrypt(commitments, piece)?,
                sealed_partials: Vec::new(),
            };
            chunk.add_partial(return_secret, share)?;
            chunks.push(chunk);
        }
        if chunks.is_empty() {
            let mut chunk = CommitteeChunk {
                ciphertext: threshold::encrypt(commitments, &[])?,
                sealed_partials: Vec::new(),
            };
            chunk.add_partial(return_secret, share)?;
            chunks.push(chunk);
        }
        Ok(Self { chunks })
    }

    /// A **forwarding** member adds its sealed partial to every chunk.
    pub fn add_member(&mut self, return_secret: &[u8; 32], share: &KeyShare) -> Result<()> {
        for chunk in &mut self.chunks {
            chunk.add_partial(return_secret, share)?;
        }
        Ok(())
    }

    /// Serialize as `chunk_count (u16) || chunks`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.chunks.len() as u16).to_be_bytes());
        for chunk in &self.chunks {
            chunk.encode(&mut out);
        }
        out
    }

    /// Parse [`to_bytes`](Self::to_bytes). Bounds-checked; never panics.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut cur = bytes;
        let count = u16::from_be_bytes(take(&mut cur, 2)?.try_into().expect("2 bytes")) as usize;
        if count > MAX_CHUNKS {
            return Err(Error::Decode("too many committee response chunks".into()));
        }
        let mut chunks = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            chunks.push(CommitteeChunk::decode(&mut cur)?);
        }
        if !cur.is_empty() {
            return Err(Error::Decode(
                "trailing bytes after committee response".into(),
            ));
        }
        Ok(Self { chunks })
    }
}

/// The client recovers the full response: for each chunk, open the members'
/// sealed partials with the return secrets (the MAC picks the right one),
/// de-duplicate by member, combine a threshold quorum, then concatenate. Errors
/// — never garbage — if any chunk lacks a quorum.
pub fn open_response(
    commitments: &KeyCommitments,
    threshold_k: usize,
    response: &CommitteeResponse,
    return_secrets: &[[u8; 32]],
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for chunk in &response.chunks {
        let mut partials = Vec::new();
        let mut seen = HashSet::new();
        for sealed in &chunk.sealed_partials {
            for secret in return_secrets {
                if let Ok(p) = open_partial(secret, sealed) {
                    if seen.insert(p.member()) {
                        partials.push(p);
                    }
                    break;
                }
            }
        }
        out.extend_from_slice(&threshold::combine(
            commitments,
            threshold_k,
            &chunk.ciphertext,
            &partials,
        )?);
    }
    Ok(out)
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

/// How a committee exit turns a request into a response.
#[derive(Clone, Copy, Debug)]
pub enum ExitBehavior {
    /// Echo the request back — for demos and tests (no destination dialed).
    Echo,
    /// Fetch a real clearnet destination over TCP: connect, send the request,
    /// read the (bounded) response. SSRF-guarded via
    /// [`neo_core::net::is_safe_dial_target`]; `allow_loopback` relaxes that for
    /// local dev/test only.
    Clearnet {
        /// Permit loopback/private destinations (dev/test). Production: `false`.
        allow_loopback: bool,
    },
}

/// Max bytes an exit reads from a destination before stopping.
const EXIT_MAX_RESPONSE: usize = 4 * 1024 * 1024;
/// How long an exit waits on a destination fetch.
const EXIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Fetch `request` from a clearnet `destination` (`host:port`) over TCP: connect,
/// write the request, half-close, and read the response to EOF — bounded by
/// [`EXIT_MAX_RESPONSE`] and [`EXIT_TIMEOUT`], SSRF-guarded. A simple
/// send-then-read exit; a protocol-aware (keep-alive HTTP) exit is a refinement,
/// and hiding the request from the egress member is the M33 send path.
async fn fetch_clearnet(
    destination: &str,
    request: &[u8],
    allow_loopback: bool,
) -> Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    if !neo_core::net::is_safe_dial_target(destination, allow_loopback) {
        return Err(Error::Config(format!(
            "committee exit refuses unsafe destination {destination}"
        )));
    }
    let fetch = async {
        let mut stream = tokio::net::TcpStream::connect(destination)
            .await
            .map_err(|e| Error::Config(format!("exit connect {destination}: {e}")))?;
        stream
            .write_all(request)
            .await
            .map_err(|e| Error::Config(format!("exit write: {e}")))?;
        let _ = stream.shutdown().await; // half-close: signal end of request
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(|e| Error::Config(format!("exit read: {e}")))?;
            if n == 0 || buf.len() >= EXIT_MAX_RESPONSE {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        Ok::<_, Error>(buf)
    };
    tokio::time::timeout(EXIT_TIMEOUT, fetch)
        .await
        .map_err(|_| Error::Config("committee exit fetch timed out".into()))?
}

/// Client: send `request` to `destination` through a committee `circuit` — each
/// hop a committee member holding a share of `commitments` — and recover the
/// response the exit encrypted to the joint key, combining the members' sealed
/// partials from the return path. Only this client sees the response plaintext;
/// no committee member does (bar the egress at fetch time — the M33 send-path gap).
pub async fn committee_request_response(
    identity: &NodeIdentity,
    circuit: &[Hop],
    commitments: &KeyCommitments,
    threshold_k: usize,
    destination: &str,
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
    // Exit-only Sphinx payload: the committee key (to encrypt to) + destination
    // (to fetch) + request.
    let payload = encode_exit_payload(commitments, destination, request);

    let (packet, secrets) = create_packet_keyed(&hops, &payload)?;
    let (mut stream, mut result) =
        connect_verified(&circuit[0].addr, identity, &circuit[0].id).await?;
    write_frame(
        &mut stream,
        &result.session.seal(&[crate::run::FRAME_COMMITTEE])?,
    )
    .await?;
    write_frame(&mut stream, &result.session.seal(&packet.to_bytes())?).await?;

    let bytes = result.session.open(&read_frame(&mut stream).await?)?;
    let response = CommitteeResponse::from_bytes(&bytes)?;
    open_response(commitments, threshold_k, &response, &secrets)
}

/// Fisher–Yates shuffle of `v` using the system RNG.
fn shuffle(v: &mut [usize]) -> Result<()> {
    for i in (1..v.len()).rev() {
        let mut b = [0u8; 8];
        getrandom::getrandom(&mut b).map_err(|e| Error::Rng(e.to_string()))?;
        v.swap(i, (u64::from_le_bytes(b) % (i as u64 + 1)) as usize);
    }
    Ok(())
}

/// Up to `max` distinct size-`k` combinations of `0..n`, in lexicographic order.
fn some_k_subsets(n: usize, k: usize, max: usize) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    if k == 0 || k > n || max == 0 {
        return out;
    }
    let mut idx: Vec<usize> = (0..k).collect();
    loop {
        out.push(idx.clone());
        if out.len() >= max {
            return out;
        }
        let mut i = k;
        loop {
            if i == 0 {
                return out;
            }
            i -= 1;
            if idx[i] != i + n - k {
                break;
            }
        }
        idx[i] += 1;
        for j in i + 1..k {
            idx[j] = idx[j - 1] + 1;
        }
    }
}

/// Route a request through a committee **with liveness**: because on-circuit
/// fan-in needs every hop up, this picks a `k`-member subset (a fresh circuit),
/// bounds each attempt by `per_attempt`, and retries a *different* subset if a
/// hop is offline or slow — so a committee that over-provisions `n > k` tolerates
/// up to `n - k` unavailable members. Members are tried in a randomized order so
/// load spreads; up to `max_attempts` distinct subsets are tried.
pub async fn committee_request(
    identity: &NodeIdentity,
    descriptor: &CommitteeDescriptor,
    destination: &str,
    request: &[u8],
    per_attempt: std::time::Duration,
    max_attempts: usize,
) -> Result<Vec<u8>> {
    let k = descriptor.threshold();
    let n = descriptor.members.len();
    if n < k {
        return Err(Error::Config(
            "committee is smaller than its threshold".into(),
        ));
    }
    let mut order: Vec<usize> = (0..n).collect();
    shuffle(&mut order)?;

    let mut last = Error::Config("no committee attempt was made".into());
    for combo in some_k_subsets(n, k, max_attempts) {
        let circuit: Vec<Hop> = combo
            .iter()
            .map(|&pos| {
                let m = &descriptor.members[order[pos]];
                Hop {
                    id: m.id,
                    sphinx: m.sphinx,
                    addr: m.addr.clone(),
                }
            })
            .collect();
        match tokio::time::timeout(
            per_attempt,
            committee_request_response(
                identity,
                &circuit,
                &descriptor.commitments,
                k,
                destination,
                request,
            ),
        )
        .await
        {
            Ok(Ok(response)) => return Ok(response),
            Ok(Err(e)) => last = e,
            Err(_) => last = Error::Config("committee circuit attempt timed out".into()),
        }
    }
    Err(last)
}

/// Relay/exit: handle one committee-circuit connection. Peels one Sphinx layer,
/// then either forwards to the next hop and adds **this** member's sealed partial
/// to every chunk of the returning [`CommitteeResponse`]; or, at the exit, runs
/// `exit` on the request (fetching the destination), splits the response into
/// chunks encrypted to the committee key, discards the plaintext, and seals its
/// own partial per chunk. `share` is this member's DKG share.
pub async fn handle_committee_circuit<S, R>(
    identity: &NodeIdentity,
    share: &KeyShare,
    prev: &mut S,
    prev_session: &mut Session,
    resolver: &R,
    replay: &Mutex<ReplayCache>,
    exit: ExitBehavior,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: NextHop,
{
    let sealed = read_frame(prev).await?;
    let packet_bytes = prev_session.open(&sealed)?;
    let packet = SphinxPacket::from_bytes(&packet_bytes)?;
    let secret = identity.sphinx_shared(packet.alpha())?;

    let processed = {
        let mut cache = replay.lock().expect("replay cache poisoned");
        process(identity, &mut cache, &packet)?
    };

    let response = match processed {
        Processed::Deliver { payload } => {
            let (commitments, destination, request) = decode_exit_payload(&payload)?;
            let response_plaintext = match exit {
                ExitBehavior::Echo => request,
                ExitBehavior::Clearnet { allow_loopback } => {
                    fetch_clearnet(&destination, &request, allow_loopback).await?
                }
            };
            // Chunk + encrypt to the joint key; the plaintext is not retained past
            // this point (the exit saw it — the documented M33 boundary).
            CommitteeResponse::seal_at_exit(&commitments, &response_plaintext, &secret, share)?
        }
        Processed::Forward { next, packet } => {
            let next_id = NodeId::from_bytes(next);
            let addr = resolver
                .addr_of(&next_id)
                .ok_or_else(|| Error::Config(format!("no address for next hop {next_id}")))?;
            let (mut next_stream, mut next_result) =
                connect_verified(&addr, identity, &next_id).await?;
            write_frame(
                &mut next_stream,
                &next_result.session.seal(&[crate::run::FRAME_COMMITTEE])?,
            )
            .await?;
            write_frame(
                &mut next_stream,
                &next_result.session.seal(&packet.to_bytes())?,
            )
            .await?;
            let bytes = next_result
                .session
                .open(&read_frame(&mut next_stream).await?)?;
            let mut response = CommitteeResponse::from_bytes(&bytes)?;
            response.add_member(&secret, share)?;
            response
        }
    };

    write_frame(prev, &prev_session.seal(&response.to_bytes())?).await?;
    Ok(())
}

/// Encode an exit payload `[commitments_len (u16) || commitments || dest_len (u16)
/// || destination || request]`.
fn encode_exit_payload(commitments: &KeyCommitments, destination: &str, request: &[u8]) -> Vec<u8> {
    let cbytes = commitments.to_bytes();
    let mut out = Vec::with_capacity(4 + cbytes.len() + destination.len() + request.len());
    out.extend_from_slice(&(cbytes.len() as u16).to_be_bytes());
    out.extend_from_slice(&cbytes);
    out.extend_from_slice(&(destination.len() as u16).to_be_bytes());
    out.extend_from_slice(destination.as_bytes());
    out.extend_from_slice(request);
    out
}

/// Parse [`encode_exit_payload`] into `(commitments, destination, request)`.
fn decode_exit_payload(payload: &[u8]) -> Result<(KeyCommitments, String, Vec<u8>)> {
    let mut cur = payload;
    let clen = u16::from_be_bytes(take(&mut cur, 2)?.try_into().expect("2 bytes")) as usize;
    let commitments = KeyCommitments::from_bytes(take(&mut cur, clen)?)?;
    let dlen = u16::from_be_bytes(take(&mut cur, 2)?.try_into().expect("2 bytes")) as usize;
    let destination = std::str::from_utf8(take(&mut cur, dlen)?)
        .map_err(|_| Error::Decode("exit destination not UTF-8".into()))?
        .to_string();
    Ok((commitments, destination, cur.to_vec()))
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

/// Encode a set of member indices: `[count (u8) || indices...]`.
fn encode_index_set(set: &std::collections::BTreeSet<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + set.len());
    out.push(set.len().min(255) as u8);
    out.extend(set.iter().copied().take(255));
    out
}

fn decode_index_set(bytes: &[u8]) -> Result<std::collections::BTreeSet<u8>> {
    let mut cur = bytes;
    let count = take(&mut cur, 1)?[0] as usize;
    Ok(take(&mut cur, count)?.iter().copied().collect())
}

/// A timeout-bounded pairwise exchange among the `roster`: this member sends
/// `msg_for(peer)` to every reachable peer and collects each peer's reply,
/// returning `peer index -> reply bytes`. The higher index dials the lower; both
/// send and read on the one connection (dialer writes then reads; accepter reads
/// then writes). A peer unreachable by `deadline` (offline / slow) is simply
/// absent from the result, so a crash-faulty member cannot stall the run.
async fn pairwise_exchange(
    identity: &NodeIdentity,
    index: u8,
    roster: &[CommitteeMemberInfo],
    listener: &tokio::net::TcpListener,
    msg_for: &(dyn Fn(u8) -> Result<Vec<u8>> + Send + Sync),
    deadline: std::time::Instant,
) -> std::collections::HashMap<u8, Vec<u8>> {
    let collected = std::sync::Mutex::new(std::collections::HashMap::<u8, Vec<u8>>::new());
    let higher = roster.iter().filter(|m| m.index > index).count();

    let accept = async {
        let mut got = 0;
        while got < higher {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let Ok(Ok((mut stream, result))) =
                tokio::time::timeout(remaining, crate::run::accept(listener, identity)).await
            else {
                break;
            };
            let Some(peer) = roster.iter().find(|m| m.id == result.peer_id) else {
                continue;
            };
            let mut session = result.session;
            let their = match read_frame(&mut stream).await.and_then(|f| session.open(&f)) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let Ok(mine) = msg_for(peer.index) else {
                continue;
            };
            let Ok(sealed) = session.seal(&mine) else {
                continue;
            };
            if write_frame(&mut stream, &sealed).await.is_err() {
                continue;
            }
            collected.lock().expect("dkg map").insert(peer.index, their);
            got += 1;
        }
    };

    let dial = async {
        for peer in roster.iter().filter(|m| m.index < index) {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let Ok(mine) = msg_for(peer.index) else {
                continue;
            };
            let Ok(Ok((mut stream, mut result))) =
                tokio::time::timeout(remaining, connect_verified(&peer.addr, identity, &peer.id))
                    .await
            else {
                continue;
            };
            let Ok(sealed) = result.session.seal(&mine) else {
                continue;
            };
            if write_frame(&mut stream, &sealed).await.is_err() {
                continue;
            }
            let their = match read_frame(&mut stream)
                .await
                .and_then(|f| result.session.open(&f))
            {
                Ok(b) => b,
                Err(_) => continue,
            };
            collected.lock().expect("dkg map").insert(peer.index, their);
        }
    };

    tokio::join!(accept, dial);
    collected.into_inner().expect("dkg map")
}

/// Run **networked Joint-Feldman DKG** among the committee `roster` from this
/// member's viewpoint (`identity`, 1-based `index`, its committee `listener`),
/// tolerating **crash faults**: the run completes over a *qualified set* even if
/// some members are offline, as long as at least `threshold` remain. Returns this
/// member's aggregate [`KeyShare`] and the agreed [`CommitteeDescriptor`] (whose
/// roster is the qualified set). No party ever holds the joint secret.
///
/// Two timeout-bounded rounds (each up to `round_timeout`): (1) every reachable
/// pair exchanges its Feldman commitment + the private share dealt to the peer,
/// over the authenticated session, and each verifies the share against the
/// dealer's commitment; (2) members exchange their *accept sets* and take the
/// **intersection** as the qualified set `QUAL`, so all honest, mutually-reachable
/// members derive the same joint key. The key is formed over `QUAL` only.
///
/// **Honest boundary.** This tolerates *crash* faults under synchrony with full
/// connectivity among honest members. It does **not** yet tolerate a *Byzantine*
/// member that reports inconsistent accept sets to different peers (which could
/// split honest members onto different keys — a safe failure, circuits just fail,
/// but a liveness regression): full asynchronous Byzantine-robust DKG (a
/// broadcast/agreement primitive over `QUAL`) is the deferred hardening.
pub async fn run_dkg(
    identity: &NodeIdentity,
    index: u8,
    roster: &[CommitteeMemberInfo],
    listener: &tokio::net::TcpListener,
    threshold: usize,
    round_timeout: std::time::Duration,
) -> Result<(KeyShare, CommitteeDescriptor)> {
    use neo_mpc::dkg;
    use std::collections::BTreeSet;

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

    // Round 1: exchange commitments + shares with every reachable peer.
    let share_msg = |peer: u8| -> Result<Vec<u8>> {
        Ok(encode_dkg_msg(
            &my_commitment,
            &contribution.share_for(peer)?,
        ))
    };
    let deadline1 = std::time::Instant::now() + round_timeout;
    let raw = pairwise_exchange(identity, index, roster, listener, &share_msg, deadline1).await;

    // Keep only peers whose share is well-formed and verifies against its
    // dealer's commitment. Our accept set is those peers plus ourselves.
    let mut received: std::collections::HashMap<u8, (KeyCommitments, KeyShare)> =
        std::collections::HashMap::new();
    let mut accepted: BTreeSet<u8> = BTreeSet::from([index]);
    for (peer, bytes) in &raw {
        if let Ok((commitment, share)) = decode_dkg_msg(bytes) {
            if share.member == index && share.verify(&commitment) {
                accepted.insert(*peer);
                received.insert(*peer, (commitment, share));
            }
        }
    }

    // Round 2: agree on the qualified set. Everyone sends its accept set; QUAL is
    // the intersection over the peers we accepted — the members every honest,
    // reachable participant accepted — so all derive the same joint key.
    let accepted_bytes = encode_index_set(&accepted);
    let set_msg = |_peer: u8| -> Result<Vec<u8>> { Ok(accepted_bytes.clone()) };
    let deadline2 = std::time::Instant::now() + round_timeout;
    let views = pairwise_exchange(identity, index, roster, listener, &set_msg, deadline2).await;

    let mut qual = accepted.clone();
    for (peer, bytes) in &views {
        if !accepted.contains(peer) {
            continue; // only accepted members' views count
        }
        if let Ok(their_set) = decode_index_set(bytes) {
            qual = qual.intersection(&their_set).copied().collect();
        }
    }
    // We can only aggregate members we actually hold a verified share from.
    qual.retain(|j| *j == index || received.contains_key(j));
    if !qual.contains(&index) || qual.len() < threshold {
        return Err(Error::Crypto(format!(
            "DKG qualified set too small ({} members, need >= {threshold}); too many offline or faulty",
            qual.len()
        )));
    }

    // Aggregate over QUAL only — the key is defined by the qualified dealers.
    let mut all_commitments = Vec::with_capacity(qual.len());
    let mut dealt_to_me = Vec::with_capacity(qual.len());
    for &j in &qual {
        if j == index {
            all_commitments.push(my_commitment.clone());
            dealt_to_me.push(contribution.share_for(index)?);
        } else {
            let (commitment, share) = received
                .get(&j)
                .ok_or_else(|| Error::Crypto(format!("missing share from qualified member {j}")))?;
            all_commitments.push(commitment.clone());
            dealt_to_me.push(share.clone());
        }
    }
    let commitments = dkg::joint_commitments(&all_commitments)?;
    let my_share = dkg::aggregate_share(index, &dealt_to_me)?;
    let members: Vec<CommitteeMemberInfo> = roster
        .iter()
        .filter(|m| qual.contains(&m.index))
        .cloned()
        .collect();
    Ok((
        my_share,
        CommitteeDescriptor {
            commitments,
            members,
        },
    ))
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

        // Exit (member 0) chunks + encrypts the response and seals its partial;
        // members 1 and 2 add theirs on the return path.
        let mut response = CommitteeResponse::seal_at_exit(
            &commitments,
            response_plaintext,
            &secrets[0],
            &shares[0],
        )
        .unwrap();
        response.add_member(&secrets[1], &shares[1]).unwrap();
        response.add_member(&secrets[2], &shares[2]).unwrap();

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
        let secrets: Vec<[u8; 32]> = (0..4).map(|i| secret(i as u8 + 1)).collect();
        let mut response =
            CommitteeResponse::seal_at_exit(&commitments, b"a response", &secrets[0], &shares[0])
                .unwrap();
        for i in 1..4 {
            response.add_member(&secrets[i], &shares[i]).unwrap();
        }
        let parsed = CommitteeResponse::from_bytes(&response.to_bytes()).unwrap();
        assert_eq!(
            open_response(&commitments, 3, &parsed, &secrets).unwrap(),
            b"a response"
        );
        // A truncated buffer is rejected, not panicked.
        assert!(CommitteeResponse::from_bytes(&response.to_bytes()[..3]).is_err());
    }

    #[test]
    fn a_large_response_is_chunked_and_reassembled() {
        // A response bigger than one threshold ciphertext is split into chunks,
        // each with its members' partials; the client reassembles the whole.
        let (commitments, shares) = committee(3, 2);
        let secrets = [secret(1), secret(2), secret(3)];
        let big = vec![0xABu8; CHUNK_PLAINTEXT + 12_345]; // > one chunk
        let mut response =
            CommitteeResponse::seal_at_exit(&commitments, &big, &secrets[0], &shares[0]).unwrap();
        response.add_member(&secrets[1], &shares[1]).unwrap();
        assert!(response.chunks.len() >= 2, "a large response spans chunks");
        assert_eq!(
            open_response(&commitments, 2, &response, &secrets).unwrap(),
            big
        );
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
                run_dkg(
                    &identity,
                    index,
                    &roster_c,
                    &listener,
                    2,
                    std::time::Duration::from_secs(5),
                )
                .await
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

    #[tokio::test]
    async fn dkg_completes_over_a_qualified_set_when_a_member_is_offline() {
        // 4-member roster, threshold 2, but member 4 never comes up. The three
        // online members still establish a joint key over the qualified set.
        let ids: Vec<NodeIdentity> = (0..4).map(|_| NodeIdentity::generate().unwrap()).collect();
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

        // Run DKG only for members 1..3; member 4's listener stays idle (offline).
        let mut tasks = Vec::new();
        for _ in 0..3 {
            let listener = listeners.remove(0);
            let id = &ids[tasks.len()];
            let idb = id.to_bytes();
            let roster_c = roster.clone();
            let index = roster.iter().find(|m| m.id == id.id()).unwrap().index;
            tasks.push(tokio::spawn(async move {
                let identity = NodeIdentity::from_bytes(&idb).unwrap();
                run_dkg(
                    &identity,
                    index,
                    &roster_c,
                    &listener,
                    2,
                    std::time::Duration::from_secs(3),
                )
                .await
            }));
        }
        let _member4_listener = listeners; // keep member 4's port bound but idle

        let mut results = Vec::new();
        for t in tasks {
            results.push(t.await.unwrap().unwrap());
        }

        let commitments = results[0].1.commitments.clone();
        for (share, desc) in &results {
            assert_eq!(
                desc.commitments, commitments,
                "online members agree on the key"
            );
            assert!(share.verify(&commitments), "each aggregate share verifies");
            assert_eq!(
                desc.members.len(),
                3,
                "qualified set excludes the offline member"
            );
            assert!(
                desc.members.iter().all(|m| m.index != 4),
                "member 4 not in QUAL"
            );
        }
        // A quorum of the qualified members still threshold-decrypts.
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

    fn hop_of(identity: &NodeIdentity, addr: &str) -> Hop {
        let p = identity.public();
        Hop {
            id: p.id,
            sphinx: p.sphinx,
            addr: addr.to_string(),
        }
    }

    async fn spawn_committee_hop(
        identity_bytes: impl AsRef<[u8]> + Send + 'static,
        share: KeyShare,
        resolver: HashMap<NodeId, String>,
    ) -> (String, tokio::task::JoinHandle<Result<()>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = tokio::spawn(async move {
            let identity = NodeIdentity::from_bytes(identity_bytes.as_ref()).unwrap();
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
                    exit: ExitBehavior::Echo,
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
        // Echo exit: the destination is ignored, so any placeholder works.
        let response =
            committee_request_response(&client, &circuit, &commitments, 2, "ignored:0", request)
                .await
                .unwrap();
        assert_eq!(response, request, "the client recovers the echoed response");

        entry_task.await.unwrap().unwrap();
        mid_task.await.unwrap().unwrap();
        exit_task.await.unwrap().unwrap();
    }

    /// Serve committee circuits in a loop until the runtime shuts down (test only).
    fn serve_committee_loop(
        listener: tokio::net::TcpListener,
        identity_bytes: impl AsRef<[u8]> + Send + 'static,
        share: KeyShare,
        resolver: HashMap<NodeId, String>,
    ) {
        tokio::spawn(async move {
            let identity = NodeIdentity::from_bytes(identity_bytes.as_ref()).unwrap();
            let replay = Mutex::new(ReplayCache::new());
            while let Ok((stream, _)) = listener.accept().await {
                let (stream, result) =
                    match crate::run::responder_handshake(stream, &identity).await {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                let _ = crate::serve::serve_connection(
                    &identity,
                    stream,
                    result.session,
                    &resolver,
                    &replay,
                    crate::circuit::ExitPolicy::default(),
                    Some(crate::serve::CommitteeServing {
                        share: &share,
                        exit: ExitBehavior::Echo,
                    }),
                )
                .await;
            }
        });
    }

    #[tokio::test]
    async fn committee_request_retries_around_an_offline_member() {
        // 3-member committee, threshold 2; member 3's port is closed (offline).
        // The client's k-subset retry finds the working pair and succeeds.
        let (commitments, shares) = committee(3, 2);
        let m: Vec<NodeIdentity> = (0..3).map(|_| NodeIdentity::generate().unwrap()).collect();
        let client = NodeIdentity::generate().unwrap();

        let l0 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a0 = l0.local_addr().unwrap().to_string();
        let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a1 = l1.local_addr().unwrap().to_string();
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a2 = dead.local_addr().unwrap().to_string();
        drop(dead); // member 3's port now refuses connections

        let members = vec![
            CommitteeMemberInfo {
                index: 1,
                id: m[0].id(),
                sphinx: m[0].public().sphinx,
                addr: a0.clone(),
            },
            CommitteeMemberInfo {
                index: 2,
                id: m[1].id(),
                sphinx: m[1].public().sphinx,
                addr: a1.clone(),
            },
            CommitteeMemberInfo {
                index: 3,
                id: m[2].id(),
                sphinx: m[2].public().sphinx,
                addr: a2.clone(),
            },
        ];
        let descriptor = CommitteeDescriptor {
            commitments: commitments.clone(),
            members,
        };

        // Full resolver so either online member can be entry and forward to the other.
        let mut resolver = HashMap::new();
        resolver.insert(m[0].id(), a0.clone());
        resolver.insert(m[1].id(), a1.clone());
        resolver.insert(m[2].id(), a2.clone());

        serve_committee_loop(l0, m[0].to_bytes(), shares[0].clone(), resolver.clone());
        serve_committee_loop(l1, m[1].to_bytes(), shares[1].clone(), resolver.clone());

        let request = b"GET / HTTP/1.0";
        let response = committee_request(
            &client,
            &descriptor,
            "ignored:0",
            request,
            std::time::Duration::from_secs(3),
            6,
        )
        .await
        .unwrap();
        assert_eq!(
            response, request,
            "the client routes around the offline member"
        );
    }
}
