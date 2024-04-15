//! Pseudorandom functions and permutations.
//!
//! # PRFs
//!
//! Let `f` be a [`Func`] and let `adv` be a [`Distinguisher`](crate::Distinguisher). Define the
//! advantage of `adv` in distinguishing `f` from a random function as
//!
//! ```text
//! Pr[adv.play(Real::with(f)), Ok(true)] - Pr[adv.play(RandFunc::default()), Ok(true)]
//! ```
//!
//! Informally, we call `f` a pseudorandom function, or PRF, if every efficient attacker's
//! advantage is small.
//!
//! # PRPs
//!
//! Let `f` be a [`Perm`] and let `adv` be a [`Distinguisher`](crate::Distinguisher). Define the
//! advantage of `adv` in distinguishing `f` from a random function as
//!
//! ```text
//! Pr[adv.play(Real::with(f)), Ok(true)] - Pr[adv.play(RandPerm::default()), Ok(true)]
//! ```
//!
//! Informally, we call `f` a pseudorandom permutation, or PRP, if every efficient attacker's
//! advantage is small.

use std::collections::{HashMap, HashSet};

use rand::{distributions::Standard, prelude::*};

/// A keyed function (e.g., a MAC).
pub trait Func {
    type Key;
    type Domain: std::hash::Hash + Eq + PartialEq + ?Sized;
    type Range: Clone + std::hash::Hash + Eq + PartialEq;

    fn eval(&self, k: &Self::Key, x: &Self::Domain) -> Self::Range;
}

/// A keyed permutation (e.g., a blockcipher).
pub trait Perm: Func {
    fn eval_inv(&self, k: &Self::Key, y: &Self::Range) -> Self::Domain;
}

/// Interface for an attacker playing the [`Real`], [`RandFunc`], or [`RandPerm`] game.
pub trait Game<F: Func> {
    fn eval(&mut self, x: &F::Domain) -> F::Range;
}

/// A [`Func`] with a randomly generated key.
pub struct Real<F: Func> {
    f: F,
    k: F::Key,
}

impl<F: Func> Real<F>
where
    Standard: Distribution<F::Key>,
{
    pub fn with(f: F) -> Self {
        Self {
            f,
            k: thread_rng().gen(),
        }
    }
}

impl<F: Func> Game<F> for Real<F> {
    fn eval(&mut self, x: &F::Domain) -> F::Range {
        self.f.eval(&self.k, x)
    }
}

/// A lazy-sampled random function.
#[derive(Default)]
pub struct RandFunc<F: Func>
where
    F::Domain: Sized,
{
    table: HashMap<F::Domain, F::Range>,
}

impl<F: Func> Game<F> for RandFunc<F>
where
    Standard: Distribution<F::Range>,
    F::Domain: Clone,
{
    fn eval(&mut self, x: &F::Domain) -> F::Range {
        self.table
            .entry(x.clone())
            .or_insert(thread_rng().gen())
            .clone()
    }
}

/// A lazy-sampled random permutation.
#[derive(Default)]
pub struct RandPerm<F: Func>
where
    F::Domain: Sized,
{
    table: HashMap<F::Domain, F::Range>,
    range: HashSet<F::Range>,
}

impl<F: Func> Game<F> for RandPerm<F>
where
    Standard: Distribution<F::Range>,
    F::Domain: Clone,
{
    fn eval(&mut self, x: &F::Domain) -> F::Range {
        let mut rng = thread_rng();
        self.table
            .entry(x.clone())
            .or_insert(loop {
                let y = rng.gen();
                if !self.range.contains(&y) {
                    self.range.insert(y.clone());
                    break y;
                }
            })
            .clone()
    }
}

/// The AES-128 blockcipher.
#[derive(Default)]
pub struct Aes128;

impl Func for Aes128 {
    type Key = [u8; 16];
    type Domain = [u8; 16];
    type Range = [u8; 16];

    fn eval(&self, k: &[u8; 16], x: &[u8; 16]) -> [u8; 16] {
        use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
        let cipher = aes::Aes128::new(&GenericArray::from(*k));
        let mut block = GenericArray::from(*x);
        cipher.encrypt_block(&mut block);
        block.into()
    }
}

impl Perm for Aes128 {
    fn eval_inv(&self, k: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
        use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
        let cipher = aes::Aes128::new(&GenericArray::from(*k));
        let mut block = GenericArray::from(*y);
        cipher.decrypt_block(&mut block);
        block.into()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Distinguisher, Error};

    /// Test some basic properties we expect `F` to have.
    struct Tester<F>(F);

    impl<G: Game<Aes128>> Distinguisher<G> for Tester<Aes128> {
        fn play(&self, mut game: G) -> Result<bool, Error> {
            let x0 = [0; 16];
            let x1 = [1; 16];
            let y0 = game.eval(&x0);
            let y1 = game.eval(&x1);
            if y0 == y1 {
                return Ok(false);
            }
            if y0 != game.eval(&x0) {
                return Ok(false);
            }
            if y1 != game.eval(&x1) {
                return Ok(false);
            }
            Ok(true)
        }
    }

    #[test]
    fn aes_real() {
        let adv = Tester(Aes128);
        assert_eq!(adv.play(Real::with(Aes128)), Ok(true));
    }

    #[test]
    fn aes_rand_func() {
        let adv = Tester(Aes128);
        assert_eq!(adv.play(RandFunc::default()), Ok(true));
    }

    #[test]
    fn aes_rand_perm() {
        let adv = Tester(Aes128);
        assert_eq!(adv.play(RandPerm::default()), Ok(true));
    }

    #[test]
    fn aes_perm() {
        let k = thread_rng().gen();
        for x in [[0; 16], [1; 16], [2; 16]] {
            assert_eq!(Aes128.eval_inv(&k, &Aes128.eval(&k, &x)), x);
        }
    }
}

pub mod lemma_prp_to_prf {

    //! PRP/PRF switching [[BR06]]: If `f` is a PRP, then `f` is a PRF (up to birthday attacks).
    //!
    //! Formally, for every PRF attacker `a`, there exists a PRP attacker `b` such that
    //!
    //! ```text
    //! AdvPRF(a, f) <= AdvPRP(b, f) + q(q-1)/(2*|F::Range|)
    //! ```
    //!
    //! where `a` queries its oracle at most `q` times and `b` has the same runtime as `a`.
    //!
    //! [BR06]: https://eprint.iacr.org/2004/331

    use super::*;

    /// Game `G0`: exactly the [`Real`] game with `f`. Let
    ///
    /// ```text
    /// p0 = Pr[a.play(G0::with(f)) = Ok(true)]
    /// ```
    pub type G0<F> = Real<F>;

    /// Game `G1`: exactly the [`RandPerm`] game with `f`. Let
    ///
    /// ```text
    /// p1 = Pr[a.play(G1::default()) = Ok(true)]
    /// ```
    ///
    /// REDUCTION `b`: Run `a`.
    ///
    /// Then `p0 - p1` is exactly `b`'s [PRP](crate::prf) distinguishing advantage against `f`.
    pub type G1<F> = RandPerm<F>;

    /// Game `G2`: derived from `G1` by rewriting the rejection sampling loop.
    ///
    /// Let
    ///
    /// ```text
    /// p2 = Pr[a.play(G2::default()) = Ok(true)]
    /// ```
    ///
    /// `G1` and `G2` are EQUIVALENT, thus `p1 - p2 == 0`.
    #[derive(Default)]
    pub struct G2<F: Func>
    where
        F::Domain: Sized,
    {
        table: HashMap<F::Domain, F::Range>,
        #[cfg(feature = "identical-until")]
        range: HashSet<F::Range>,
    }

    impl<F: Func> Game<F> for G2<F>
    where
        Standard: Distribution<F::Range>,
        F::Domain: Clone,
    {
        #[allow(clippy::never_loop)]
        fn eval(&mut self, x: &F::Domain) -> F::Range {
            let mut rng = thread_rng();
            self.table
                .entry(x.clone())
                .or_insert(loop {
                    let y = rng.gen();
                    // TODO(cjpatton) Figure out a nice way to express the "identical-until" code
                    // path as an attribute. The goal would be to signal the hax backend to
                    // conditionally compile the code covered by the attribute.
                    #[cfg(feature = "identical-until")]
                    if self.range.contains(&y) {
                        self.range.insert(y.clone());
                        continue;
                    }
                    break y;
                })
                .clone()
        }
    }

    /// Game `G3`: derived from `G2` by removing the rejection sampling logic.
    ///
    /// Let
    ///
    /// ```text
    /// p3 = Pr[a.play(G3::default()) = Ok(true)]
    /// ```
    ///
    /// `G3` and `G2` are IDENTICAL UNTIL the game samples a point in the range of `f` twice.
    /// Afeter `q` queries, this probability is `q(q-1)/(2*|F::Range|)`, thus `p2 - p3 <=
    /// q(q-1)/(2*|F::Range|)`.
    ///
    ///
    /// `G3` is EQUIVALENT to the [`RandFunc`] game with `f`.
    pub type G3<F> = RandFunc<F>;
}
