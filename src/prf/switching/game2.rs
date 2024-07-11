use std::collections::{HashMap, HashSet};

use rand::{
    distributions::{Distribution, Standard},
    prelude::*,
};

use crate::prf::{Eval, Func};

/// Game 2: Equivalent to game 1 until collision in the range.
#[derive(Default)]
pub struct G2<F: Func>
where
    F::Domain: Sized,
{
    table: HashMap<F::Domain, F::Range>,
    range: HashSet<F::Range>,
    bad: bool,
}
impl<F: Func> Eval<F> for G2<F>
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
                if self.range.contains(&y) {
                    self.bad = true;
                    continue; // reject and try again
                }
                self.range.insert(y.clone());
                break y;
            })
            .clone()
    }
}
