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
pub trait Distinguisher<G> {
    fn play_then_return(&self, game: G) -> (G, bool);
    fn play(&self, game: G) -> bool {
        self.play_then_return(game).1
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;

    pub(crate) struct TrivialDistinguisher;
    impl<G> Distinguisher<G> for TrivialDistinguisher {
        fn play_then_return(&self, game: G) -> (G, bool) {
            // Don't modify the game
            (game, true)
        }
    }
}
