//! `neo-slicing` — information slicing (the novel core, part 1).
//!
//! Splits an **encrypted** flow into `n` shares such that any `k` reconstruct it
//! and fewer than `k` reveal nothing (encrypt-then-slice). Shares travel disjoint
//! paths, so no single relay ever holds a complete, meaningful flow.
//!
//! Status: stub — implemented in milestone M3. See `docs/PROTOCOL.md`.
