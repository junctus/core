//! `neo-mix` — timing defense (the novel core, part 2).
//!
//! Cover traffic plus per-hop **Poisson timing mixing** (Loopix/Nym style) to
//! decorrelate a flow's input and output timing and resist a global passive
//! observer. Built here from scratch — there is no off-the-shelf Rust crate for
//! it. Scaled by the [`PrivacyLevel`](neo_core::PrivacyLevel) dial.
//!
//! Status: stub — implemented in milestone M5.
