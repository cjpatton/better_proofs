use std::collections::{HashMap, HashSet};

use rand::{
    distributions::{Distribution, Standard},
    prelude::*,
};

use crate::prf::{Eval, Func};

/// Game 1: Equivalent rewrite of the ideal PRF game.
#[derive(Default)]
pub struct G1<F: Func>
where
    F::Domain: Sized,
{
    table: HashMap<F::Domain, F::Range>,
    range: HashSet<F::Range>,
    bad: bool,
}
impl<F: Func> Eval<F> for G1<F>
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
                }
                self.range.insert(y.clone());
                break y;
            })
            .clone()
    }
}
