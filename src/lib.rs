//! "Better" as in "maintainable".

use std::ops::AddAssign;

use rand::prelude::*;

pub mod vdaf;

pub type Error = &'static str;

/// Generate a vector with `size` random bytes.
pub fn rand_bytes(size: usize) -> Vec<u8> {
    let mut bytes = vec![0; size];
    thread_rng().fill(&mut bytes[..]);
    bytes
}

/// Add two vectors together.
pub fn vec_add<F: AddAssign>(mut u: Vec<F>, v: Vec<F>) -> Vec<F> {
    assert_eq!(u.len(), v.len());
    for (x, y) in u.iter_mut().zip(v.into_iter()) {
        *x += y;
    }
    u
}

/// A generic distinguishing adversary.
pub trait Distinguisher<G> {
    /// Play the game and output a bit.
    fn play(&self, game: G) -> Result<bool, Error>;
}
