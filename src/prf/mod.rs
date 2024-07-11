//! Pseudorandom functions and permutations.
//!
//! # PRFs
//!
//! Let `f` be a [`Func`] and let `adv` be a [`Distinguisher`](crate::Distinguisher). Define the
//! advantage of `adv` in distinguishing `f` from a random function as
//!
//! ```text
//! Pr[adv.play(Real::with(f)), true] - Pr[adv.play(RandFunc::default()), true]
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
//! Pr[adv.play(Real::with(f)), true] - Pr[adv.play(RandPerm::default()), true]
//! ```
//!
//! Informally, we call `f` a pseudorandom permutation, or PRP, if every efficient attacker's
//! advantage is small.

use std::collections::{HashMap, HashSet};

use rand::{distributions::Standard, prelude::*};

/// A keyed function (e.g., a MAC).
pub trait Func {
    type Key;
    type Domain: ?Sized;
    type Range;
    fn eval(&self, k: &Self::Key, x: &Self::Domain) -> Self::Range;
}

/// A keyed permutation (e.g., a blockcipher).
pub trait Perm: Func {
    fn eval_inv(&self, k: &Self::Key, y: &Self::Range) -> Self::Domain;
}

/// Oracle for evaluating a keyed function.
pub trait Eval<F: Func> {
    fn eval(&mut self, x: &F::Domain) -> F::Range;
}

/// Real game for defining PRP and PRF security.
pub struct Real<F: Func> {
    f: F,
    k: F::Key,
}
impl<F: Func> Real<F>
where
    Standard: Distribution<F::Key>,
{
    pub fn with(f: F) -> Self {
        let k = thread_rng().gen();
        Self { f, k }
    }
}
impl<F: Func> Eval<F> for Real<F> {
    fn eval(&mut self, x: &F::Domain) -> F::Range {
        self.f.eval(&self.k, x)
    }
}

/// Ideal game for defining PRF security.
#[derive(Default)]
pub struct RandFunc<F: Func>
where
    F::Domain: Sized,
{
    table: HashMap<F::Domain, F::Range>,
}
impl<F: Func> Eval<F> for RandFunc<F>
where
    Standard: Distribution<F::Range>,
    F::Domain: Clone + std::hash::Hash + Eq,
    F::Range: Clone + std::hash::Hash + Eq,
{
    fn eval(&mut self, x: &F::Domain) -> F::Range {
        self.table
            .entry(x.clone())
            .or_insert(thread_rng().gen())
            .clone()
    }
}

/// Ideal game for defining PRP security.
#[derive(Default)]
pub struct RandPerm<F: Func>
where
    F::Domain: Sized,
{
    table: HashMap<F::Domain, F::Range>,
    range: HashSet<F::Range>,
}
impl<F: Func> Eval<F> for RandPerm<F>
where
    Standard: Distribution<F::Range>,
    F::Domain: Clone + std::hash::Hash + Eq,
    F::Range: Clone + std::hash::Hash + Eq,
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
    use crate::Distinguisher;

    /// Test some basic properties we expect `F` to have.
    struct Tester<F>(F);

    impl<G: Eval<Aes128>> Distinguisher<G> for Tester<Aes128> {
        fn play_then_return(&self, mut game: G) -> (G, bool) {
            let x0 = [0; 16];
            let x1 = [1; 16];
            let y0 = game.eval(&x0);
            let y1 = game.eval(&x1);
            if y0 == y1 {
                return (game, false);
            }
            if y0 != game.eval(&x0) {
                return (game, false);
            }
            if y1 != game.eval(&x1) {
                return (game, false);
            }
            (game, true)
        }
    }

    #[test]
    fn aes_real() {
        let adv = Tester(Aes128);
        assert_eq!(adv.play(Real::with(Aes128)), true);
    }

    #[test]
    fn aes_rand_func() {
        let adv = Tester(Aes128);
        assert_eq!(adv.play(RandFunc::default()), true);
    }

    #[test]
    fn aes_rand_perm() {
        let adv = Tester(Aes128);
        assert_eq!(adv.play(RandPerm::default()), true);
    }

    #[test]
    fn aes_perm() {
        let k = thread_rng().gen();
        for x in [[0; 16], [1; 16], [2; 16]] {
            assert_eq!(Aes128.eval_inv(&k, &Aes128.eval(&k, &x)), x);
        }
    }
}

pub mod switching;
