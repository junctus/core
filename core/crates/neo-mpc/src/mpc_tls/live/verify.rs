//! Pluggable **server-certificate verification** for the live 2PC-TLS handshake.
//!
//! The handshake authenticates the server two ways: the `Finished` MAC (bound to the
//! ECDHE secret, stops a passive/key-substituting MITM) and the `CertificateVerify`
//! signature over the transcript. *Who* to trust for the latter is policy — so it is a
//! [`ServerCertVerifier`] the caller supplies:
//!
//! - [`LeafKeyVerifier`] (default, dep-light): verifies the CertificateVerify signature
//!   against the **leaf key** (`ecdsa_secp256r1_sha256`), but does **not** build a chain to
//!   a trust anchor. Correct when the leaf is pinned out of band.
//! - [`WebpkiVerifier`] (feature `live-tls-webpki`): full X.509 **chain-building** to trust
//!   anchors via the vetted `rustls-webpki` `EndEntityCert` — issuer-signature path
//!   validation, subject-name match, and the CertificateVerify signature against the
//!   validated leaf key. This is what a real TLS client uses.

use neo_core::{Error, Result};

/// Verifies the server's certificate `chain` (leaf first) for `server_name`, and the
/// `CertificateVerify`: `sig` over `signed` under TLS `SignatureScheme` `scheme`.
pub trait ServerCertVerifier {
    fn verify(
        &self,
        chain: &[Vec<u8>],
        server_name: &str,
        scheme: u16,
        signed: &[u8],
        sig: &[u8],
    ) -> Result<()>;
}

/// The built-in verifier: authenticates the **leaf key** + the CertificateVerify signature
/// (`ecdsa_secp256r1_sha256`), without chain-building to a trust anchor. Pin the leaf out of
/// band, or use [`WebpkiVerifier`] for full path validation.
pub struct LeafKeyVerifier;

impl ServerCertVerifier for LeafKeyVerifier {
    fn verify(
        &self,
        chain: &[Vec<u8>],
        _server_name: &str,
        scheme: u16,
        signed: &[u8],
        sig: &[u8],
    ) -> Result<()> {
        let leaf = chain
            .first()
            .ok_or_else(|| Error::Crypto("certverify: empty certificate chain".into()))?;
        super::handshake::verify_leaf_signature_p256(leaf, scheme, signed, sig)
    }
}

#[cfg(feature = "live-tls-webpki")]
pub use webpki_verifier::WebpkiVerifier;

#[cfg(feature = "live-tls-webpki")]
mod webpki_verifier {
    use super::*;
    use rustls_pki_types::{CertificateDer, ServerName, SignatureVerificationAlgorithm, UnixTime};
    use webpki::ring as alg;
    use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage};

    /// Chain-building `SignatureVerificationAlgorithm`s accepted for issuer signatures.
    const CHAIN_ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
        alg::ECDSA_P256_SHA256,
        alg::ECDSA_P384_SHA384,
        alg::RSA_PKCS1_2048_8192_SHA256,
        alg::RSA_PKCS1_2048_8192_SHA384,
        alg::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        alg::ED25519,
    ];

    /// Full X.509 chain-building verifier (`rustls-webpki`): validates the server chain to
    /// the configured DER trust anchors, checks the subject name, and verifies the
    /// CertificateVerify signature — all via vetted `webpki`, not hand-rolled.
    pub struct WebpkiVerifier {
        roots: Vec<Vec<u8>>,
    }

    impl WebpkiVerifier {
        /// Trust the given DER root certificates (the platform store / `webpki-roots`; for a
        /// self-signed server, the server cert itself). Validates they parse as anchors.
        pub fn with_roots(root_ders: &[Vec<u8>]) -> Result<Self> {
            for r in root_ders {
                let der = CertificateDer::from(r.as_slice());
                anchor_from_trusted_cert(&der)
                    .map_err(|e| Error::Crypto(format!("webpki: bad root cert: {e}")))?;
            }
            Ok(WebpkiVerifier {
                roots: root_ders.to_vec(),
            })
        }
    }

    fn scheme_alg(scheme: u16) -> Option<&'static dyn SignatureVerificationAlgorithm> {
        Some(match scheme {
            0x0403 => alg::ECDSA_P256_SHA256,
            0x0503 => alg::ECDSA_P384_SHA384,
            0x0804 => alg::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
            0x0807 => alg::ED25519,
            _ => return None,
        })
    }

    impl ServerCertVerifier for WebpkiVerifier {
        fn verify(
            &self,
            chain: &[Vec<u8>],
            server_name: &str,
            scheme: u16,
            signed: &[u8],
            sig: &[u8],
        ) -> Result<()> {
            let leaf_der = CertificateDer::from(
                chain
                    .first()
                    .ok_or_else(|| Error::Crypto("certverify: empty chain".into()))?
                    .as_slice(),
            );
            let ee = EndEntityCert::try_from(&leaf_der)
                .map_err(|e| Error::Crypto(format!("certverify: bad leaf cert: {e}")))?;

            let root_ders: Vec<CertificateDer> = self
                .roots
                .iter()
                .map(|r| CertificateDer::from(r.as_slice()))
                .collect();
            let anchors: Vec<_> = root_ders
                .iter()
                .map(|c| anchor_from_trusted_cert(c))
                .collect::<std::result::Result<_, _>>()
                .map_err(|e| Error::Crypto(format!("certverify: bad anchor: {e}")))?;
            let intermediates: Vec<CertificateDer> = chain[1..]
                .iter()
                .map(|c| CertificateDer::from(c.as_slice()))
                .collect();

            // 1. Chain-building to the trust anchors + subject-name match.
            ee.verify_for_usage(
                CHAIN_ALGS,
                &anchors,
                &intermediates,
                UnixTime::now(),
                KeyUsage::server_auth(),
                None,
                None,
            )
            .map_err(|e| Error::Crypto(format!("certverify: chain validation failed: {e}")))?;
            let sn = ServerName::try_from(server_name)
                .map_err(|_| Error::Crypto("certverify: bad server name".into()))?;
            ee.verify_is_valid_for_subject_name(&sn)
                .map_err(|e| Error::Crypto(format!("certverify: name mismatch: {e}")))?;

            // 2. The CertificateVerify signature against the (now-validated) leaf key.
            let sig_alg = scheme_alg(scheme)
                .ok_or_else(|| Error::Crypto(format!("certverify: scheme 0x{scheme:04x}")))?;
            ee.verify_signature(sig_alg, signed, sig)
                .map_err(|e| Error::Crypto(format!("certverify: signature invalid: {e}")))?;
            Ok(())
        }
    }
}
