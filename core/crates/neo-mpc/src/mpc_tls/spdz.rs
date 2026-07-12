//! **SPDZ-style authenticated arithmetic over `F_p`** — malicious-secure multiplication
//! for the ECtF / EC-conversion path (the *field* analog of [`wrk17`](super::wrk17)'s
//! boolean authenticated shares). [`ectf`](super::ectf)'s Gilboa [`mta_fp`] is
//! semi-honest at the MtA layer; this module adds the standard MASCOT/SPDZ machinery
//! that makes field multiplication **malicious-detecting**: information-theoretic MACs
//! under a global key `α`, MAC-checked opens, Beaver multiplication, and the **triple
//! sacrifice** check.
//!
//! # Authenticated share `[x]`
//!
//! A global MAC key `α = α_A + α_B` (each party holds its additive share). An
//! authenticated value [`Auth`] `[x]` is an additive share of `x` **and** of `α·x`:
//! party `i` holds `xᵢ` and `mᵢ` with `Σxᵢ = x`, `Σmᵢ = α·x`. Because neither party
//! knows the full `α`, neither can present a valid MAC for a *different* value — the
//! SPDZ analog of the IT-MAC unforgeability.
//!
//! - **Add / sub / mul-by-public-constant / add-public-constant** are local.
//! - **Open** ([`Auth::open`]) reveals `x` and checks `Σ(mᵢ − αᵢ·x) = 0` — the abort
//!   gate. A value-tampered share needs a MAC consistent under the *other* party's `α`
//!   share, i.e. a guess at `α_B` (resp. `α_A`).
//! - **Beaver multiply** ([`beaver_mul`]) computes `[x·y]` from a triple `[a],[b],[ab]`
//!   with MAC-checked opens of `x−a`, `y−b`.
//! - **Sacrifice** ([`sacrifice`]) verifies a triple `(a,b,ab)` against a second triple
//!   sharing `b` — `open(a−â)=ρ`, then `open(c − ĉ − ρ·b) = 0` — catching a maliciously
//!   wrong triple.
//!
//! # Honest boundary
//!
//! - **Follows MASCOT/SPDZ** (Keller–Orsini–Scholl 2016; the sacrifice is the standard
//!   SPDZ triple check). **Correctness and the abort mechanism are what the tests
//!   establish** (Beaver products are correct; a tampered share or a corrupted triple
//!   aborts). The *formal* malicious guarantee is the SPDZ proof + the **external
//!   audit** — not established by these correctness tests.
//! - The (semi-honest) triples come from [`ectf::mta_fp`](super::ectf); wiring ECtF's
//!   `mul_shared` onto this authenticated Beaver online is the remaining integration.
//! - Both parties are modelled **in-process**; `F_p` is `crypto-bigint`'s constant-time
//!   Montgomery arithmetic (as in [`ectf`](super::ectf)); the real SPDZ open uses a
//!   commit-then-open MAC check (here computed directly in-process).

use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::{Encoding, U256};
use neo_core::{Error, Result};

/// A field element of `F_p` (constant-time Montgomery residue).
type F = DynResidue<{ U256::LIMBS }>;

/// The prime field `F_p` (odd, 256-bit).
#[derive(Clone, Copy)]
struct Field {
    params: DynResidueParams<{ U256::LIMBS }>,
    modulus: U256,
}

impl Field {
    fn new(prime_be: &[u8; 32]) -> Self {
        let modulus = U256::from_be_bytes(*prime_be);
        Field {
            params: DynResidueParams::new(&modulus),
            modulus,
        }
    }
    #[cfg(test)]
    fn elem(&self, v: u64) -> F {
        DynResidue::new(&U256::from(v), self.params)
    }
    fn rand(&self) -> Result<F> {
        loop {
            let mut b = [0u8; 32];
            getrandom::getrandom(&mut b).map_err(|e| Error::Rng(e.to_string()))?;
            let u = U256::from_be_bytes(b);
            if u < self.modulus {
                return Ok(DynResidue::new(&u, self.params));
            }
        }
    }
}

fn is_zero(x: &F) -> bool {
    x.retrieve() == U256::ZERO
}

/// The SPDZ global MAC key `α = α_A + α_B` (each party's share) plus the field.
#[derive(Clone, Copy)]
pub struct Keys {
    alpha_a: F,
    alpha_b: F,
    field: Field,
}

impl Keys {
    pub fn random(prime_be: &[u8; 32]) -> Result<Self> {
        let field = Field::new(prime_be);
        Ok(Keys {
            alpha_a: field.rand()?,
            alpha_b: field.rand()?,
            field,
        })
    }

    fn alpha(&self) -> F {
        self.alpha_a + self.alpha_b
    }
}

/// A SPDZ authenticated arithmetic share `[x]`: additive shares of `x` and of `α·x`.
#[derive(Clone, Copy)]
pub struct Auth {
    xa: F,
    xb: F,
    ma: F,
    mb: F,
}

impl Auth {
    /// The cleartext value `x = xa + xb` (for tests/asserts).
    pub fn value(&self) -> F {
        self.xa + self.xb
    }

    /// Deal a fresh valid `[x]` for a known `x` (dealer model / tests; a real sharing
    /// authenticates a random value and derandomises).
    pub fn deal(x: F, keys: &Keys) -> Result<Auth> {
        let xa = keys.field.rand()?;
        let xb = x - xa;
        let ma = keys.field.rand()?;
        let mb = keys.alpha() * x - ma; // ma + mb = α·x
        Ok(Auth { xa, xb, ma, mb })
    }

    /// `[x] + [y]`, local.
    pub fn add(&self, o: &Auth) -> Auth {
        Auth {
            xa: self.xa + o.xa,
            xb: self.xb + o.xb,
            ma: self.ma + o.ma,
            mb: self.mb + o.mb,
        }
    }

    /// `[x] − [y]`, local.
    pub fn sub(&self, o: &Auth) -> Auth {
        Auth {
            xa: self.xa - o.xa,
            xb: self.xb - o.xb,
            ma: self.ma - o.ma,
            mb: self.mb - o.mb,
        }
    }

    /// `c · [x]` for a public field element `c`, local (scale the value and MAC shares).
    pub fn mul_const(&self, c: F) -> Auth {
        Auth {
            xa: self.xa * c,
            xb: self.xb * c,
            ma: self.ma * c,
            mb: self.mb * c,
        }
    }

    /// `[x] + c` for a public field element `c`: one party adds `c` to its value share,
    /// each party adds `αᵢ·c` to its MAC share (so `Σm = α·x + α·c = α·(x+c)`).
    pub fn add_const(&self, c: F, keys: &Keys) -> Auth {
        Auth {
            xa: self.xa + c,
            xb: self.xb,
            ma: self.ma + keys.alpha_a * c,
            mb: self.mb + keys.alpha_b * c,
        }
    }

    /// Open `[x]`, MAC-checked — the abort gate. Reveals `x = xa+xb` and verifies
    /// `Σ(mᵢ − αᵢ·x) = 0`; a tamper (value inconsistent with the MAC under the unknown
    /// full `α`) aborts.
    pub fn open(&self, keys: &Keys) -> Result<F> {
        let x = self.xa + self.xb;
        let sigma_a = self.ma - keys.alpha_a * x;
        let sigma_b = self.mb - keys.alpha_b * x;
        if !is_zero(&(sigma_a + sigma_b)) {
            return Err(Error::Crypto(
                "SPDZ: MAC check failed on open (tampered share — abort)".into(),
            ));
        }
        Ok(x)
    }
}

/// An authenticated arithmetic triple `[a],[b],[ab]` with `ab = a·b`.
#[derive(Clone, Copy)]
pub struct Triple(pub Auth, pub Auth, pub Auth);

/// Beaver multiply `[x]·[y]` using triple `t = [a],[b],[ab]`:
/// `[xy] = [ab] + d·[b] + e·[a] + d·e`, `d = open(x−a)`, `e = open(y−b)` (MAC-checked).
pub fn beaver_mul(x: &Auth, y: &Auth, t: &Triple, keys: &Keys) -> Result<Auth> {
    let d = x.sub(&t.0).open(keys)?; // x − a
    let e = y.sub(&t.1).open(keys)?; // y − b
    let z =
        t.2.add(&t.1.mul_const(d)) // + d·[b]
            .add(&t.0.mul_const(e)) // + e·[a]
            .add_const(d * e, keys); // + d·e
    Ok(z)
}

/// **SPDZ triple sacrifice**: verify triple `t = (a,b,c)` by sacrificing a second triple
/// `aux = (â,b,ĉ)` that **shares the same `b`**: open `ρ = a − â`, then check
/// `open(c − ĉ − ρ·b) = 0`. A maliciously wrong `c` (or `ĉ`) is caught.
pub fn sacrifice(t: &Triple, aux: &Triple, keys: &Keys) -> Result<()> {
    let rho = t.0.sub(&aux.0).open(keys)?; // ρ = a − â
                                           // c − ĉ − ρ·b  should open to 0.
    let check = t.2.sub(&aux.2).sub(&t.1.mul_const(rho));
    if !is_zero(&check.open(keys)?) {
        return Err(Error::Crypto(
            "SPDZ: triple failed the sacrifice check (abort)".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const P256_PRIME_BE: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];

    fn keys() -> Keys {
        Keys::random(&P256_PRIME_BE).unwrap()
    }

    // Deal an honest triple ([a],[b],[a·b]).
    fn deal_triple(a: F, b: F, k: &Keys) -> Triple {
        Triple(
            Auth::deal(a, k).unwrap(),
            Auth::deal(b, k).unwrap(),
            Auth::deal(a * b, k).unwrap(),
        )
    }

    #[test]
    fn authenticated_open_and_local_ops() {
        let k = keys();
        let f = k.field;
        let x = f.elem(12345);
        let y = f.elem(67890);
        let sx = Auth::deal(x, &k).unwrap();
        let sy = Auth::deal(y, &k).unwrap();
        assert_eq!(
            sx.open(&k).unwrap().retrieve(),
            x.retrieve(),
            "open [x] = x"
        );
        assert_eq!(
            sx.add(&sy).open(&k).unwrap().retrieve(),
            (x + y).retrieve(),
            "[x]+[y] = x+y"
        );
        let c = f.elem(7);
        assert_eq!(
            sx.mul_const(c).open(&k).unwrap().retrieve(),
            (x * c).retrieve(),
            "c·[x] = c·x"
        );
        assert_eq!(
            sx.add_const(c, &k).open(&k).unwrap().retrieve(),
            (x + c).retrieve(),
            "[x]+c = x+c"
        );
    }

    #[test]
    fn a_tampered_share_aborts_on_open() {
        let k = keys();
        let f = k.field;
        // Flip the value share without a matching MAC (needs the other party's α) → abort.
        let mut s = Auth::deal(f.elem(42), &k).unwrap();
        s.xa += f.elem(1);
        assert!(s.open(&k).is_err(), "value tamper without MAC aborts");
        // Even a value+own-MAC-consistent flip is caught (adversary lacks full α).
        let mut s2 = Auth::deal(f.elem(42), &k).unwrap();
        let delta = f.elem(5);
        s2.xa += delta;
        s2.ma += k.alpha_a * delta; // consistent under α_a only
        assert!(
            s2.open(&k).is_err(),
            "flip consistent under only α_a aborts"
        );
    }

    #[test]
    fn beaver_multiplication_is_correct() {
        let k = keys();
        let f = k.field;
        for (xv, yv) in [(3u64, 5u64), (0, 999), (123456, 654321)] {
            let x = f.elem(xv);
            let y = f.elem(yv);
            let a = f.rand().unwrap();
            let b = f.rand().unwrap();
            let t = deal_triple(a, b, &k);
            let z = beaver_mul(
                &Auth::deal(x, &k).unwrap(),
                &Auth::deal(y, &k).unwrap(),
                &t,
                &k,
            )
            .unwrap();
            assert_eq!(
                z.open(&k).unwrap().retrieve(),
                (x * y).retrieve(),
                "Beaver [x·y] = x·y for {xv}·{yv}"
            );
        }
    }

    #[test]
    fn sacrifice_passes_honest_and_catches_a_corrupted_triple() {
        let k = keys();
        let f = k.field;
        let b = f.rand().unwrap();
        let a = f.rand().unwrap();
        let a_hat = f.rand().unwrap();
        // Two honest triples that SHARE the same [b] (required by the sacrifice).
        let bshare = Auth::deal(b, &k).unwrap();
        let good = Triple(
            Auth::deal(a, &k).unwrap(),
            bshare,
            Auth::deal(a * b, &k).unwrap(),
        );
        let aux = Triple(
            Auth::deal(a_hat, &k).unwrap(),
            bshare,
            Auth::deal(a_hat * b, &k).unwrap(),
        );
        sacrifice(&good, &aux, &k).unwrap();
        // Corrupt c of `good` (c := a·b + 1) → sacrifice must abort.
        let bad = Triple(good.0, good.1, Auth::deal(a * b + f.elem(1), &k).unwrap());
        assert!(
            sacrifice(&bad, &aux, &k).is_err(),
            "a corrupted triple must fail the sacrifice check"
        );
    }
}
