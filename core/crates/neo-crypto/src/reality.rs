//! REALITY-style authenticated camouflage — active-probe resistance (M23).
//!
//! A censor that actively probes a neo bridge must not be able to tell it from an
//! ordinary TLS server. The defense, following [REALITY], is an **authenticator**
//! a legitimate client embeds in its first flight that:
//! - is **indistinguishable from random** to anyone without the server's key, so a
//!   probe cannot fingerprint it; and
//! - a server can verify **only** with its private key, deciding *silently* whether
//!   to speak neo (authenticated) or to fall through to a **decoy** (a real
//!   upstream TLS site). A prober therefore always sees plausible, innocuous
//!   behaviour and learns nothing.
//!
//! The crucial twist versus plain TLS: the server's public key here is a
//! **capability** shared with legitimate clients out of band — it is *not*
//! published in a certificate. A censor lacking it cannot compute the shared
//! secret, so cannot forge an authenticator, and cannot distinguish an
//! authenticated client's flight from random bytes.
//!
//! This module is the **auth core**: key agreement, the uniform authenticator,
//! epoch binding against capture-replay, and the silent authenticate/decoy
//! decision. Test coverage proves a prober cannot reach the authenticated branch.
//!
//! **Honest boundary.** Wire-level REALITY also needs the server to *actually*
//! reverse-proxy an un-authenticated probe to a genuine upstream site (so the
//! decoy is a real TLS session with a real cert), and the neo flight must be
//! embedded inside a true TLS ClientHello. Those are integration steps on top of
//! this core; the authenticator, its indistinguishability, and the silent
//! decision are implemented and tested here.
//!
//! [REALITY]: https://github.com/XTLS/REALITY

use std::collections::HashSet;
use std::sync::Mutex;

use neo_core::{Error, Result};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Authenticator length (a BLAKE3 output).
const TAG_LEN: usize = 32;
/// Ephemeral public key length.
const EPH_LEN: usize = 32;
/// The fixed prefix of a hello: ephemeral key + authenticator.
const HELLO_PREFIX: usize = EPH_LEN + TAG_LEN;
/// Minimum random tail so a hello sits in a realistic ClientHello size class.
const MIN_PAD: usize = 32;
/// The pad length is randomized over `MIN_PAD..=MIN_PAD+PAD_JITTER` so the flight
/// is not a fixed size on the wire.
const PAD_JITTER: usize = 64;
/// Seen-ephemeral cache size per epoch generation (bounds memory).
const REPLAY_CAP: usize = 1 << 16;

/// A bounded, two-generation cache of ephemerals seen within the replay window, so
/// a captured hello cannot be replayed. Memory is capped at `~2 * REPLAY_CAP`.
struct ReplayCache {
    epoch: u64,
    current: HashSet<[u8; 32]>,
    previous: HashSet<[u8; 32]>,
}

impl ReplayCache {
    fn new() -> Self {
        Self {
            epoch: 0,
            current: HashSet::new(),
            previous: HashSet::new(),
        }
    }

    /// Returns `true` if `eph` was already seen within the replay window; records
    /// it otherwise. Rotates generations as the epoch advances (keeping the
    /// previous generation for the one-epoch skew window).
    fn is_replay(&mut self, epoch: u64, eph: [u8; 32]) -> bool {
        if epoch != self.epoch {
            if epoch == self.epoch.wrapping_add(1) {
                self.previous = std::mem::take(&mut self.current);
            } else {
                self.current.clear();
                self.previous.clear();
            }
            self.epoch = epoch;
        }
        if self.current.contains(&eph) || self.previous.contains(&eph) {
            return true;
        }
        if self.current.len() >= REPLAY_CAP {
            self.previous = std::mem::take(&mut self.current);
        }
        self.current.insert(eph);
        false
    }
}

/// The server's long-term REALITY secret. Its [`public`](RealitySecret::public)
/// half is a capability distributed to legitimate clients out of band.
pub struct RealitySecret {
    secret: StaticSecret,
    seen: Mutex<ReplayCache>,
}

/// The server's REALITY public key: the pre-shared capability a client needs to
/// author a valid, uniform-looking authenticator. Not published like a TLS cert.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RealityKey([u8; 32]);

/// The server's silent decision about an incoming hello.
#[derive(Clone, Debug)]
pub enum Verdict {
    /// A legitimate neo client: proceed, seeding the session from `session_seed`.
    Authenticated {
        /// A shared 32-byte seed for the ensuing neo session (both sides derive it).
        session_seed: [u8; 32],
    },
    /// Not authenticated — behave exactly as for any non-neo peer (decoy/upstream).
    Decoy,
}

impl RealitySecret {
    /// Generate a fresh server secret.
    pub fn generate() -> Result<Self> {
        let mut sk = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(sk.as_mut_slice()).map_err(|e| Error::Rng(e.to_string()))?;
        Ok(Self {
            secret: StaticSecret::from(*sk),
            seen: Mutex::new(ReplayCache::new()),
        })
    }

    /// The public capability clients need.
    pub fn public(&self) -> RealityKey {
        RealityKey(PublicKey::from(&self.secret).to_bytes())
    }

    /// Silently classify an incoming `hello` at the server's current `epoch`.
    ///
    /// Accepts the current and previous epoch (a small clock-skew window). A
    /// captured hello cannot be replayed: an authenticated ephemeral already seen
    /// within the window is refused as [`Verdict::Decoy`]. Any malformed, random,
    /// or wrong-key input also classifies as [`Verdict::Decoy`] — never an error and
    /// never a distinguishable reaction.
    pub fn classify(&self, hello: &[u8], epoch: u64) -> Verdict {
        if hello.len() < HELLO_PREFIX {
            return Verdict::Decoy;
        }
        let eph: [u8; 32] = hello[..EPH_LEN].try_into().expect("checked len");
        let got = &hello[EPH_LEN..HELLO_PREFIX];
        let shared_secret = self.secret.diffie_hellman(&PublicKey::from(eph));
        // Reject low-order / non-contributory ephemerals. A low-order point (e.g.
        // the identity) yields a shared secret an attacker can also predict —
        // letting a prober forge an authenticator WITHOUT the capability key. Take
        // the silent Decoy path (never an error) so the rejection is
        // indistinguishable from any other non-authenticated peer.
        if !shared_secret.was_contributory() {
            return Verdict::Decoy;
        }
        let shared = shared_secret.to_bytes();
        // Accept this epoch and the previous one (skew tolerance).
        for ep in [epoch, epoch.wrapping_sub(1)] {
            if ct_eq(&auth_tag(&shared, ep, &eph), got) {
                // Reject a replayed hello (a captured, re-sent flight within the
                // window) — silently, as a Decoy.
                if self
                    .seen
                    .lock()
                    .expect("reality replay cache poisoned")
                    .is_replay(epoch, eph)
                {
                    return Verdict::Decoy;
                }
                return Verdict::Authenticated {
                    session_seed: session_seed(&shared, &eph),
                };
            }
        }
        Verdict::Decoy
    }
}

impl RealityKey {
    /// The raw 32 bytes (for out-of-band distribution / pinning).
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Reconstruct from raw bytes (a pinned capability).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Author a client hello for `epoch`: an ephemeral key, a uniform
    /// authenticator, and a random tail. Returns the wire bytes and the
    /// `session_seed` the server will independently derive on acceptance.
    pub fn client_hello(&self, epoch: u64) -> Result<(Vec<u8>, [u8; 32])> {
        let mut esk = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(esk.as_mut_slice()).map_err(|e| Error::Rng(e.to_string()))?;
        let ephemeral = StaticSecret::from(*esk);
        let eph_pub = PublicKey::from(&ephemeral).to_bytes();
        let shared_secret = ephemeral.diffie_hellman(&PublicKey::from(self.0));
        // A low-order capability key would give a predictable shared secret;
        // refuse it rather than emit a forgeable hello.
        if !shared_secret.was_contributory() {
            return Err(Error::Crypto("REALITY capability key is low-order".into()));
        }
        let shared = shared_secret.to_bytes();

        let tag = auth_tag(&shared, epoch, &eph_pub);
        let seed = session_seed(&shared, &eph_pub);

        // Randomize the pad length so the flight is not a fixed size on the wire.
        // (Full wire indistinguishability — embedding inside a real TLS ClientHello
        // — is M27; this only removes the constant-length tell.)
        let mut jitter = [0u8; 1];
        getrandom::getrandom(&mut jitter).map_err(|e| Error::Rng(e.to_string()))?;
        let pad_len = MIN_PAD + (jitter[0] as usize % (PAD_JITTER + 1));
        let mut pad = vec![0u8; pad_len];
        getrandom::getrandom(&mut pad).map_err(|e| Error::Rng(e.to_string()))?;

        let mut hello = Vec::with_capacity(HELLO_PREFIX + pad.len());
        hello.extend_from_slice(&eph_pub);
        hello.extend_from_slice(&tag);
        hello.extend_from_slice(&pad);
        Ok((hello, seed))
    }

    /// Author just the fixed **64-byte authenticator prefix** for `epoch`:
    /// `ephemeral_pubkey ‖ tag`, plus the `session_seed` the server derives on
    /// acceptance. Unlike [`client_hello`](Self::client_hello) there is no random
    /// pad — the caller embeds these 64 bytes inside a real TLS ClientHello (M27),
    /// where the surrounding handshake, not a pad, provides realistic size. The
    /// ephemeral is a genuine X25519 public key (→ the TLS `key_share`) and the tag
    /// is uniform (→ the 32-byte `legacy_session_id`); [`classify`](RealitySecret::classify)
    /// reads exactly this `eph ‖ tag` layout.
    pub fn client_hello_prefix(&self, epoch: u64) -> Result<([u8; HELLO_PREFIX], [u8; 32])> {
        let mut esk = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(esk.as_mut_slice()).map_err(|e| Error::Rng(e.to_string()))?;
        let ephemeral = StaticSecret::from(*esk);
        let eph_pub = PublicKey::from(&ephemeral).to_bytes();
        let shared_secret = ephemeral.diffie_hellman(&PublicKey::from(self.0));
        if !shared_secret.was_contributory() {
            return Err(Error::Crypto("REALITY capability key is low-order".into()));
        }
        let shared = shared_secret.to_bytes();
        let tag = auth_tag(&shared, epoch, &eph_pub);
        let seed = session_seed(&shared, &eph_pub);

        let mut prefix = [0u8; HELLO_PREFIX];
        prefix[..EPH_LEN].copy_from_slice(&eph_pub);
        prefix[EPH_LEN..].copy_from_slice(&tag);
        Ok((prefix, seed))
    }

    /// The ephemeral public key and tag positions within the 64-byte prefix, for a
    /// caller placing them into distinct TLS fields: `(eph_pub, tag)`.
    pub fn split_prefix(prefix: &[u8; HELLO_PREFIX]) -> ([u8; EPH_LEN], [u8; TAG_LEN]) {
        let mut eph = [0u8; EPH_LEN];
        let mut tag = [0u8; TAG_LEN];
        eph.copy_from_slice(&prefix[..EPH_LEN]);
        tag.copy_from_slice(&prefix[EPH_LEN..]);
        (eph, tag)
    }
}

/// The fixed authenticator-prefix length: `ephemeral_pubkey(32) ‖ tag(32)`.
pub const REALITY_PREFIX_LEN: usize = HELLO_PREFIX;

/// The authenticator: a PRF over the DH secret, epoch, and ephemeral key. Uniform
/// to anyone without the DH secret; recomputable only with the server's key.
fn auth_tag(shared: &[u8; 32], epoch: u64, eph_pub: &[u8; 32]) -> [u8; TAG_LEN] {
    let mut h = blake3::Hasher::new_derive_key("neo-reality-auth-v1");
    h.update(shared);
    h.update(&epoch.to_be_bytes());
    h.update(eph_pub);
    *h.finalize().as_bytes()
}

/// A shared session seed for the ensuing neo session (both sides derive it).
fn session_seed(shared: &[u8; 32], eph_pub: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("neo-reality-session-v1");
    h.update(shared);
    h.update(eph_pub);
    *h.finalize().as_bytes()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honest_client_authenticates_and_shares_a_seed() {
        let server = RealitySecret::generate().unwrap();
        let key = server.public();
        let epoch = 1_000;

        let (hello, client_seed) = key.client_hello(epoch).unwrap();
        match server.classify(&hello, epoch) {
            Verdict::Authenticated { session_seed } => {
                assert_eq!(session_seed, client_seed, "both sides derive the same seed")
            }
            Verdict::Decoy => panic!("an honest client must authenticate"),
        }
    }

    #[test]
    fn a_prober_without_the_capability_only_ever_sees_decoy() {
        let server = RealitySecret::generate().unwrap();
        let epoch = 42;

        // Pure random bytes (an active probe): decoy.
        let mut junk = vec![0u8; 96];
        getrandom::getrandom(&mut junk).unwrap();
        assert!(matches!(server.classify(&junk, epoch), Verdict::Decoy));

        // A hello authored against the WRONG key (a prober guessing): decoy.
        let wrong = RealitySecret::generate().unwrap().public();
        let (hello, _) = wrong.client_hello(epoch).unwrap();
        assert!(matches!(server.classify(&hello, epoch), Verdict::Decoy));

        // A short/truncated flight: decoy, never an error.
        assert!(matches!(server.classify(&[0u8; 10], epoch), Verdict::Decoy));
    }

    #[test]
    fn a_low_order_ephemeral_cannot_forge_authentication() {
        // The forgery: an attacker without the capability sends the identity point
        // as its ephemeral. The DH result is the all-zero (non-contributory)
        // secret, which the attacker can also compute — so it forges the tag from
        // it. The was_contributory() guard must reject this as Decoy; otherwise the
        // server would recompute the same zero secret and authenticate the forgery.
        let server = RealitySecret::generate().unwrap();
        let epoch = 77;
        let eph = [0u8; 32]; // identity point
        let shared = [0u8; 32]; // DH(server_secret, identity) = all-zero encoding
        let tag = auth_tag(&shared, epoch, &eph);
        let mut hello = Vec::new();
        hello.extend_from_slice(&eph);
        hello.extend_from_slice(&tag);
        hello.extend_from_slice(&[0u8; MIN_PAD]);
        assert!(
            matches!(server.classify(&hello, epoch), Verdict::Decoy),
            "a low-order ephemeral must never authenticate"
        );
    }

    #[test]
    fn authenticators_are_unlinkable_across_connections() {
        let server = RealitySecret::generate().unwrap();
        let key = server.public();
        let (h1, _) = key.client_hello(7).unwrap();
        let (h2, _) = key.client_hello(7).unwrap();
        // Fresh ephemeral each time → different ephemeral key and different tag.
        assert_ne!(h1[..HELLO_PREFIX], h2[..HELLO_PREFIX]);
        // The tag is not a fixed/all-zero constant a censor could match on.
        assert_ne!(&h1[EPH_LEN..HELLO_PREFIX], &[0u8; TAG_LEN][..]);
    }

    #[test]
    fn a_replayed_hello_is_rejected() {
        // A captured hello authenticates once; re-sending it must be a silent Decoy.
        let server = RealitySecret::generate().unwrap();
        let key = server.public();
        let epoch = 500;
        let (hello, _) = key.client_hello(epoch).unwrap();

        assert!(matches!(
            server.classify(&hello, epoch),
            Verdict::Authenticated { .. }
        ));
        assert!(
            matches!(server.classify(&hello, epoch), Verdict::Decoy),
            "a captured hello must not re-authenticate"
        );
    }

    #[test]
    fn a_hello_outside_the_epoch_window_is_decoy() {
        // A fresh (never-seen) hello for `epoch`, classified two epochs later, is
        // outside the skew window → Decoy, independent of the replay cache.
        let server = RealitySecret::generate().unwrap();
        let key = server.public();
        let epoch = 500;
        let (stale, _) = key.client_hello(epoch).unwrap();
        assert!(matches!(server.classify(&stale, epoch + 2), Verdict::Decoy));
        // A fresh hello within the window (next epoch) still authenticates.
        let (fresh, _) = key.client_hello(epoch).unwrap();
        assert!(matches!(
            server.classify(&fresh, epoch + 1),
            Verdict::Authenticated { .. }
        ));
    }

    #[test]
    fn flight_length_varies_across_connections() {
        // The pad is jittered so the first flight is not a fixed size on the wire.
        let key = RealitySecret::generate().unwrap().public();
        let lens: std::collections::HashSet<usize> = (0..32)
            .map(|_| key.client_hello(1).unwrap().0.len())
            .collect();
        assert!(lens.len() > 1, "flight length must vary");
    }
}
