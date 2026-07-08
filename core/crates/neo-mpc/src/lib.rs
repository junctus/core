//! `neo-mpc` — committee / MPC-TLS exit (frontier flagship).
//!
//! A k-of-n committee jointly performs a clearnet request via MPC-TLS, so no
//! single member knows destination + content or is the sole originator. This
//! turns "no responsible exit" from a *statistical* property into a
//! *cryptographic* one. Heavy — an opt-in mode for sensitive, low-bandwidth
//! requests, not bulk traffic. Foundation: the `mpz` MPC framework (TLSNotary
//! lineage), which targets prove-not-proxy, so committee *proxying* is new work.
//!
//! Status: stub — implemented in milestone M12.
