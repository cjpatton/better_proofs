//! "Better" as in "maintainable".

use std::ops::AddAssign;

use rand::prelude::*;

pub mod vdaf;

fn rand_bytes<const S: usize>() -> [u8; S] {
    let mut bytes = [0; S];
    thread_rng().fill(&mut bytes[..]);
    bytes
}

fn vec_add<F: AddAssign>(mut u: Vec<F>, v: Vec<F>) -> Vec<F> {
    assert_eq!(u.len(), v.len());
    for (x, y) in u.iter_mut().zip(v.into_iter()) {
        *x += y;
    }
    u
}
