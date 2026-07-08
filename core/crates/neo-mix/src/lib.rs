//! `neo-mix` — timing defense (the novel core, part 2).
//!
//! Two Loopix-style defenses against a global passive observer, both scaled by
//! the [`PrivacyLevel`](neo_core::PrivacyLevel) dial:
//! - **Per-packet timing mixing** — each packet is held for an independent,
//!   exponentially-distributed delay, so a mix node's output timing is
//!   decorrelated from its input (the sum of Poisson streams is Poisson).
//! - **Cover traffic** — decoy packets are emitted at Poisson intervals so the
//!   real traffic rate and pattern are hidden.
//!
//! [`Mixer`] applies both to a stream of packets. There is no off-the-shelf Rust
//! crate for this; it is built here from the OS CSPRNG and tokio timers.

#![forbid(unsafe_code)]

use std::time::Duration;

use neo_core::PrivacyLevel;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

/// Nominal size of a cover packet (bytes), for the caller to pad to.
pub const COVER_SIZE: usize = 1024;

/// Mixing parameters derived from the privacy dial.
#[derive(Clone, Copy, Debug)]
pub struct MixParams {
    /// Mean per-packet mixing delay. `ZERO` disables mixing.
    pub mean_delay: Duration,
    /// Mean gap between cover packets. `None` disables cover traffic.
    pub cover_interval: Option<Duration>,
    /// Suggested circuit hop count for this level.
    pub hops: usize,
    /// Suggested slicing redundancy `(data, parity)` for this level.
    pub redundancy: (usize, usize),
}

impl MixParams {
    /// Parameters for a privacy level. Mobile shells may scale these down further
    /// on battery or metered links.
    pub fn for_level(level: PrivacyLevel) -> Self {
        match level {
            PrivacyLevel::Off => Self {
                mean_delay: Duration::ZERO,
                cover_interval: None,
                hops: 1,
                redundancy: (1, 1),
            },
            PrivacyLevel::Balanced => Self {
                mean_delay: Duration::from_millis(50),
                cover_interval: Some(Duration::from_millis(250)),
                hops: 3,
                redundancy: (3, 2),
            },
            PrivacyLevel::Paranoid => Self {
                mean_delay: Duration::from_millis(200),
                cover_interval: Some(Duration::from_millis(80)),
                hops: 5,
                redundancy: (3, 4),
            },
        }
    }
}

/// An item leaving the mixer: a real (delayed) packet or an injected decoy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MixOut {
    /// A real packet, released after its mixing delay.
    Real(Vec<u8>),
    /// A cover (decoy) packet of the given size.
    Cover(usize),
}

/// Applies timing mixing and cover traffic to a packet stream.
pub struct Mixer {
    params: MixParams,
}

impl Mixer {
    /// Create a mixer with the given parameters.
    pub fn new(params: MixParams) -> Self {
        Self { params }
    }

    /// Read packets from `input`, delay each independently, interleave cover
    /// traffic, and emit to `output`. Returns when `input` is closed and every
    /// in-flight packet has been released.
    pub async fn run(self, mut input: mpsc::Receiver<Vec<u8>>, output: mpsc::Sender<MixOut>) {
        let cover = spawn_cover(self.params.cover_interval, output.clone());

        let mut inflight = JoinSet::new();
        while let Some(packet) = input.recv().await {
            let out = output.clone();
            let delay = sample_exponential(self.params.mean_delay);
            inflight.spawn(async move {
                tokio::time::sleep(delay).await;
                let _ = out.send(MixOut::Real(packet)).await;
            });
        }
        while inflight.join_next().await.is_some() {}
        cover.abort();
    }
}

fn spawn_cover(
    interval: Option<Duration>,
    output: mpsc::Sender<MixOut>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let Some(mean) = interval else { return };
        loop {
            tokio::time::sleep(sample_exponential(mean)).await;
            if output.send(MixOut::Cover(COVER_SIZE)).await.is_err() {
                break;
            }
        }
    })
}

/// Sample an exponentially-distributed delay with the given mean, from OS randomness.
pub fn sample_exponential(mean: Duration) -> Duration {
    if mean.is_zero() {
        return Duration::ZERO;
    }
    // X = -mean * ln(U), U uniform in (0, 1].
    let secs = -mean.as_secs_f64() * uniform_open_unit().ln();
    Duration::from_secs_f64(secs.max(0.0))
}

/// A uniform float in `(0, 1]` from the OS CSPRNG.
fn uniform_open_unit() -> f64 {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes).expect("OS RNG unavailable");
    // 53-bit mantissa, shifted into (0, 1].
    let x = u64::from_le_bytes(bytes) >> 11;
    (x as f64 + 1.0) / (1u64 << 53) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_track_the_privacy_dial() {
        assert!(MixParams::for_level(PrivacyLevel::Off).mean_delay.is_zero());
        assert!(MixParams::for_level(PrivacyLevel::Off)
            .cover_interval
            .is_none());
        let paranoid = MixParams::for_level(PrivacyLevel::Paranoid);
        assert!(paranoid.cover_interval.is_some());
        assert!(paranoid.mean_delay > MixParams::for_level(PrivacyLevel::Balanced).mean_delay);
        assert!(paranoid.hops >= 5);
    }

    #[test]
    fn exponential_delay_has_the_expected_mean() {
        let mean = Duration::from_millis(100);
        let n = 5000;
        let total: f64 = (0..n).map(|_| sample_exponential(mean).as_secs_f64()).sum();
        let avg = total / n as f64;
        assert!((avg - 0.1).abs() < 0.02, "avg was {avg}s, expected ~0.1s");
    }

    #[test]
    fn zero_mean_delay_is_instant() {
        assert!(sample_exponential(Duration::ZERO).is_zero());
    }

    #[tokio::test]
    async fn mixer_delivers_every_real_packet() {
        let (in_tx, in_rx) = mpsc::channel(16);
        let (out_tx, mut out_rx) = mpsc::channel(64);
        let mixer = Mixer::new(MixParams {
            mean_delay: Duration::from_millis(5),
            cover_interval: Some(Duration::from_millis(2)),
            hops: 3,
            redundancy: (2, 1),
        });
        let handle = tokio::spawn(mixer.run(in_rx, out_tx));

        for i in 0..5u8 {
            in_tx.send(vec![i]).await.unwrap();
        }
        drop(in_tx);
        handle.await.unwrap();

        let (mut reals, mut covers) = (0u32, 0u32);
        while let Some(item) = out_rx.recv().await {
            match item {
                MixOut::Real(_) => reals += 1,
                MixOut::Cover(_) => covers += 1,
            }
        }
        assert_eq!(reals, 5, "all real packets must be delivered");
        let _ = covers; // cover count is timing-dependent
    }

    /// Global-passive-observer simulation: an observer sees packets enter the mix
    /// in order `0..n` and watches the order they leave. Without mixing the output
    /// order matches the input (fully linkable); with mixing it is scrambled, so
    /// the observer cannot link an output position back to an input position.
    #[tokio::test]
    async fn mixing_decorrelates_output_order_from_input() {
        async fn output_order(params: MixParams, n: usize) -> Vec<u8> {
            let (in_tx, in_rx) = mpsc::channel(n + 1);
            let (out_tx, mut out_rx) = mpsc::channel(2 * n + 1);
            let handle = tokio::spawn(Mixer::new(params).run(in_rx, out_tx));
            for i in 0..n as u8 {
                in_tx.send(vec![i]).await.unwrap();
            }
            drop(in_tx);
            handle.await.unwrap();
            let mut order = Vec::new();
            while let Some(item) = out_rx.recv().await {
                if let MixOut::Real(packet) = item {
                    order.push(packet[0]);
                }
            }
            order
        }

        // Count inversions: how far the output order is from the input order.
        fn inversions(seq: &[u8]) -> usize {
            let mut count = 0;
            for i in 0..seq.len() {
                for j in i + 1..seq.len() {
                    if seq[i] > seq[j] {
                        count += 1;
                    }
                }
            }
            count
        }

        let n = 40;
        let clear = output_order(MixParams::for_level(PrivacyLevel::Off), n).await;
        assert_eq!(clear.len(), n, "all packets delivered");
        let clear_inv = inversions(&clear);

        let mixed = output_order(MixParams::for_level(PrivacyLevel::Paranoid), n).await;
        assert_eq!(mixed.len(), n, "all packets delivered");
        let mixed_inv = inversions(&mixed);

        // No mixing barely reorders; heavy mixing scrambles substantially.
        assert!(
            clear_inv < n,
            "without mixing, order is preserved ({clear_inv})"
        );
        assert!(
            mixed_inv > 3 * n,
            "mixing must decorrelate output order (inversions: {mixed_inv})"
        );
    }
}
