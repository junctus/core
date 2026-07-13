//! **Split-scalar P-256 ECDHE** for a live TLS 1.3 handshake (`secp256r1` / group 0x0017).
//!
//! The two client parties each draw an ephemeral scalar `x1`, `x2`; the `key_share` they
//! put in the ClientHello is the *sum* point `X = (x1 + x2)·G`, so **neither party knows
//! the ephemeral secret** and neither can complete the DH alone. When the server answers
//! with `Y = s·G`, party A computes `P1 = x1·Y` and party B `P2 = x2·Y` — **local**
//! scalar mults, no 2PC — which are additive shares of the shared point
//! `P1 + P2 = (x1+x2)·s·G = s·X`. The only 2PC step is turning those point shares into
//! shares of the secret's x-coordinate:
//!
//! ```text
//!   (P1, P2)  --ectf-->  additive shares of x(P)  --a2b-->  XOR-shares of x(P)
//! ```
//!
//! and `x(P)` big-endian is exactly the TLS 1.3 `secp256r1` (EC)DHE shared secret
//! (RFC 8446 §7.4.2 / RFC 8446 → the 32-byte field element). Neither party ever holds it.
//!
//! The scalar mults use the vetted `p256` crate; the conversion uses the crate's built
//! [`ectf`](super::super::ectf::ectf) (constant-time `F_p`, KOS OT) and
//! [`a2b_shared`](super::super::convert::a2b_shared). The end-to-end result is validated
//! against `p256`'s own scalar-mult DH in the tests, and against a live rustls server in
//! [`super::handshake`].

use neo_core::{Error, Result};
use p256::elliptic_curve::ff::{Field, PrimeField};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{ProjectivePoint, PublicKey, Scalar};

use super::super::convert::a2b_shared;
use super::super::ectf::ectf;

/// P-256 base-field prime `p`, big-endian (the modulus ECtF/A2B work over).
pub const P256_PRIME_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// XOR-shares of the 32-byte big-endian ECDHE shared secret (`secret_a ⊕ secret_b`).
pub struct SharedSecret {
    pub secret_a: [u8; 32],
    pub secret_b: [u8; 32],
}

/// Both client parties' ephemeral state plus the combined public `key_share`.
///
/// (In-process model, like the rest of [`mpc_tls`](super::super): a deployment holds
/// `x1` on party A and `x2` on party B and never co-locates them.)
pub struct ClientKeyShare {
    x1: Scalar,
    x2: Scalar,
    /// SEC1 uncompressed `0x04 ‖ X ‖ Y` (65 bytes) — the `key_share` for the ClientHello.
    pub key_share: [u8; 65],
}

/// A uniform non-zero P-256 scalar (reject-sampling the field bytes).
fn random_scalar() -> Result<Scalar> {
    loop {
        let mut b = [0u8; 32];
        getrandom::getrandom(&mut b).map_err(|e| Error::Rng(e.to_string()))?;
        // `from_repr` accepts only canonical (< order) encodings; reject others + zero.
        if let Some(s) = Option::<Scalar>::from(Scalar::from_repr(b.into())) {
            if !bool::from(Field::is_zero(&s)) {
                return Ok(s);
            }
        }
    }
}

fn affine_coords(pt: &ProjectivePoint) -> ([u8; 32], [u8; 32]) {
    let enc = pt.to_affine().to_encoded_point(false);
    let x = <[u8; 32]>::try_from(enc.x().expect("affine x").as_slice()).expect("32");
    let y = <[u8; 32]>::try_from(enc.y().expect("affine y").as_slice()).expect("32");
    (x, y)
}

fn reverse32(x: &[u8; 32]) -> [u8; 32] {
    let mut o = *x;
    o.reverse();
    o
}

impl ClientKeyShare {
    /// Draw the two ephemeral scalars and form the combined `key_share` `X = (x1+x2)·G`.
    pub fn generate() -> Result<Self> {
        let x1 = random_scalar()?;
        let x2 = random_scalar()?;
        let cap_x = ProjectivePoint::GENERATOR * (x1 + x2);
        let enc = cap_x.to_affine().to_encoded_point(false);
        let key_share = <[u8; 65]>::try_from(enc.as_bytes())
            .map_err(|_| Error::Crypto("ecdhe: unexpected key_share encoding".into()))?;
        Ok(ClientKeyShare { x1, x2, key_share })
    }

    /// Given the server's SEC1 `key_share` `Y`, derive XOR-shares of the ECDHE shared
    /// secret (the shared point's x-coordinate, big-endian) — the only 2PC step.
    pub fn derive_shared(&self, server_key_share: &[u8]) -> Result<SharedSecret> {
        let y = PublicKey::from_sec1_bytes(server_key_share)
            .map_err(|_| Error::Crypto("ecdhe: invalid server key_share (not on P-256)".into()))?
            .to_projective();

        // Local per-party point shares P1 = x1·Y, P2 = x2·Y (additive: P1 + P2 = s·X).
        let (x1b, y1b) = affine_coords(&(y * self.x1));
        let (x2b, y2b) = affine_coords(&(y * self.x2));

        // ECtF → additive shares of x(P) mod p (big-endian); A2B → XOR bit-shares.
        let (s1_be, s2_be) = ectf((&x1b, &y1b), (&x2b, &y2b), &P256_PRIME_BE)?;
        let (a_le, b_le) = a2b_shared(
            &reverse32(&s1_be),
            &reverse32(&s2_be),
            &reverse32(&P256_PRIME_BE),
        )?;
        // a_le ⊕ b_le = x(P) little-endian; reverse each share → big-endian XOR shares.
        Ok(SharedSecret {
            secret_a: reverse32(&a_le),
            secret_b: reverse32(&b_le),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    #[test]
    fn split_scalar_ecdhe_matches_p256_dh() {
        // Play the server with a known scalar s; the 2PC client's shared secret must
        // equal the plain P-256 DH x-coordinate x(s·X), computed independently by p256.
        for _ in 0..3 {
            let cks = ClientKeyShare::generate().unwrap();
            let s = random_scalar().unwrap();
            let server_pub = (ProjectivePoint::GENERATOR * s)
                .to_affine()
                .to_encoded_point(false);

            // Client side (2PC).
            let shared = cks.derive_shared(server_pub.as_bytes()).unwrap();
            let got: [u8; 32] = core::array::from_fn(|i| shared.secret_a[i] ^ shared.secret_b[i]);

            // Independent oracle: x( s · X ), X the combined client key_share.
            let cap_x = PublicKey::from_sec1_bytes(&cks.key_share)
                .unwrap()
                .to_projective();
            let (want_x, _) = affine_coords(&(cap_x * s));

            assert_eq!(got, want_x, "2PC split-scalar ECDHE x-coord vs p256 DH");
            // Sanity: neither share alone is the secret.
            assert_ne!(shared.secret_a, want_x);
            assert_ne!(shared.secret_b, want_x);
            let _ = BigUint::from_bytes_be(&got); // valid field element
        }
    }
}
