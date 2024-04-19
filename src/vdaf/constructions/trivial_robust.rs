//! Robust, but not private.

use prio::field::Field64;

use crate::{
    vdaf::{robust::ExtractableVdaf, AggregatorId, ReportShare, Vdaf},
    vec_add, Error,
};

/// Compute the sum of the measurements, each either `0_u64` or `1_u64`.
///
/// ```
/// use better_proofs::vdaf::{Vdaf, constructions::trivial_robust::TrivialRobust};
/// assert_eq!(TrivialRobust::agg_func(&(), &[1, 0, 1]), 2);
/// ```
///
/// Sharding sets each input share to the measurement, thus this scheme is trivially not private.
/// During preparation, the aggregators confirm that they both have the same input share and that
/// it falls in the desired range.

#[derive(Clone)]
pub struct TrivialRobust;

impl Vdaf for TrivialRobust {
    type VerifyKey = ();
    type Nonce = ();
    type Coins = ();

    type Measurement = u64;
    type Field = Field64;
    type PublicShare = ();
    type InputShare = u64;
    type PrepState = ();
    type PrepShare = u64;
    type AggParam = ();
    type AggResult = u64;

    fn shard(&self, measurement: &u64, _nonce: &(), _coins: &()) -> ((), [u64; 2]) {
        ((), [*measurement, *measurement])
    }

    fn prep_init(
        &self,
        _vk: &(),
        _agg_id: AggregatorId,
        _agg_param: &(),
        report_share: &ReportShare<Self>,
    ) -> ((), u64) {
        ((), report_share.input_share)
    }

    fn prep_finish(&self, _prep_state: (), prep_shares: &[u64; 2]) -> Result<Vec<Field64>, Error> {
        if prep_shares[0] != prep_shares[1] {
            return Err("measurement mismatch");
        }

        if prep_shares[0] > 1 {
            return Err("measurement out of range");
        }

        Ok(vec![Field64::from(prep_shares[0]) / Field64::from(2)])
    }

    fn unshard(
        &self,
        _agg_param: &(),
        agg_shares: [Vec<Field64>; 2],
        _num_measurements: usize,
    ) -> u64 {
        let [agg_share_0, agg_share_1] = agg_shares;
        vec_add(agg_share_0, agg_share_1)[0].into()
    }

    fn agg_func(_agg_param: &(), measurements: &[u64]) -> u64 {
        measurements.iter().copied().sum()
    }
}

impl ExtractableVdaf for TrivialRobust {
    type PartialMeasurement = u64;

    fn refine(&self, _agg_param: &(), part_measurement: &u64) -> Option<Vec<Self::Field>> {
        Some(vec![Field64::from(*part_measurement)])
    }
}

#[cfg(test)]
mod test {
    use crate::vdaf::run_vdaf;

    use super::*;

    #[test]
    fn run() {
        assert_eq!(
            4,
            run_vdaf(&TrivialRobust, &[1, 1, 1, 0, 0, 1], &()).unwrap()
        );
    }
}

pub mod theorem_robust {

    //! [`TrivialRobust`] is perfectly robust.
    //!
    //! Let `vdaf = TrivialRobust` and `ext = TrivialRobustExtractor`. Every attacker has `0`
    //! advantage in attacking the robustness of `vdaf` with respect to `ext`.

    use crate::vdaf::robust::{Extractor, Transcript};

    use super::*;

    /// [`Extractor`] for the theorem.
    pub struct TrivialRobustExtractor;

    impl Extractor<TrivialRobust> for TrivialRobustExtractor {
        fn extract(
            &self,
            _nonce: &(),
            _public_share: &(),
            input_shares: &[u64; 2],
        ) -> Result<Transcript<TrivialRobust, u64>, Error> {
            let out = if input_shares[0] != input_shares[1] || input_shares[0] > 1 {
                None
            } else {
                Some(input_shares[0])
            };

            Ok(Transcript {
                prep_shares: [input_shares[0], input_shares[1]],
                out,
            })
        }
    }

    #[cfg(test)]
    mod test {

        use crate::{
            vdaf::robust::{Game, Ideal, Real},
            Distinguisher,
        };

        use super::*;

        struct Tester<V> {
            vdaf: V,
        }

        impl<V> Tester<V> {
            pub fn with(vdaf: V) -> Self {
                Self { vdaf }
            }
        }

        impl<G: Game<TrivialRobust>> Distinguisher<G> for Tester<TrivialRobust> {
            fn play(&self, game: G) -> Result<bool, Error> {
                struct TestCase {
                    measurement: u64,
                    expected_out: Option<Vec<Field64>>,
                }

                for (i, t) in [
                    TestCase {
                        measurement: 0,
                        expected_out: Some(vec![Field64::from(0)]),
                    },
                    TestCase {
                        measurement: 1,
                        expected_out: Some(vec![Field64::from(1)]),
                    },
                    TestCase {
                        measurement: 1337,
                        expected_out: None,
                    },
                ]
                .iter()
                .enumerate()
                {
                    let (public_share, input_shares) = self.vdaf.shard(&t.measurement, &(), &());
                    let tx = game.prep(&(), &(), &public_share, &input_shares)?;
                    if tx.out != t.expected_out {
                        println!("test case {i}: got {:?}; want {:?}", tx.out, t.expected_out);
                        return Ok(false);
                    }
                }

                Ok(true)
            }
        }

        #[test]
        fn real() {
            let adv = Tester::with(TrivialRobust);
            let vdaf = TrivialRobust;
            assert_eq!(adv.play(Real::with(vdaf)), Ok(true));
        }

        #[test]
        fn ideal() {
            let adv = Tester::with(TrivialRobust);
            let ext = TrivialRobustExtractor;
            let vdaf = TrivialRobust;
            assert_eq!(adv.play(Ideal::with(vdaf, ext)), Ok(true));
        }
    }
}
