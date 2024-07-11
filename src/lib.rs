use std::ops::AddAssign;

pub mod joy;
pub mod prf;
pub mod vdaf;

pub type Error = &'static str;

/// Add two vectors together.
pub fn vec_add<F: AddAssign>(mut u: Vec<F>, v: Vec<F>) -> Vec<F> {
    assert_eq!(u.len(), v.len());
    for (x, y) in u.iter_mut().zip(v.into_iter()) {
        *x += y;
    }
    u
}

/// A generic distinguishing attacker.
///
/// The attacker gets as input a "game" and outputs a bit. The output is used to define a
/// notion of advantage, e.g., for [PRFs](crate::prf).
pub trait Distinguisher<G> {
    fn play(&self, game: G) -> bool;
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;

    pub(crate) struct TrivialDistinguisher;
    impl<G> Distinguisher<G> for TrivialDistinguisher {
        fn play(&self, _game: G) -> bool {
            true
        }
    }
}
