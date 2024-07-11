//! Private, but not robust.

use prio::{
    field::Field64,
    vdaf::xof::{IntoFieldVec, Xof, XofTurboShake128},
};

use crate::{
    prf::Func,
    vdaf::{AggregatorId, ReportShare, Vdaf},
    vec_add, Error,
};

/// Compute the sum of the measurements, each a [`u64`].
///
/// ```
/// use better_proofs::vdaf::{Vdaf, constructions::trivial_private::TrivialPrivate};
/// assert_eq!(TrivialPrivate::agg_func(&(), &[1, 2, 3]), 6);
/// ```
///
/// Each measurement `m` is encoded as an element of [`Field64`] and split into `m - r` and `r`,
/// where `r` is a pseudoandom element of [`Field64`]. No information is exchanged during
/// preparation, thus no measurement validation is performed and this scheme is trivially not
/// robust.
#[derive(Clone)]
pub struct TrivialPrivate;

/// A [PRF](crate::prf) instantiated from [`XofTurboShake128`].
pub struct CoinsToField;

impl Func for CoinsToField {
    type Key = [u8; 16];
    type Domain = [u8];
    type Range = Field64;

    fn eval(&self, k: &[u8; 16], x: &[u8]) -> Field64 {
        let mut xof = XofTurboShake128::init(k, b"coins_to_field");
        xof.update(x);
        xof.into_seed_stream().into_field_vec(1)[0]
    }
}

impl Vdaf for TrivialPrivate {
    type VerifyKey = ();
    type Nonce = ();
    type Coins = [u8; 16];

    type Measurement = u64;
    type Field = Field64;
    type PublicShare = ();
    type InputShare = Field64;
    type PrepState = Field64;
    type PrepShare = ();
    type AggParam = ();
    type AggResult = u64;

    fn shard(&self, measurement: &u64, _nonce: &(), coins: &[u8; 16]) -> ((), [Field64; 2]) {
        let r = CoinsToField.eval(coins, b"TrivialPrivate");
        ((), [Field64::from(*measurement) - r, r])
    }

    fn prep_init(
        &self,
        _vk: &(),
        _agg_id: AggregatorId,
        _agg_param: &(),
        report_share: &ReportShare<Self>,
    ) -> (Field64, ()) {
        (report_share.input_share, ())
    }

    fn prep_finish(
        &self,
        prep_state: Field64,
        _prep_shares: &[(); 2],
    ) -> Result<Vec<Field64>, Error> {
        Ok(vec![prep_state])
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

#[cfg(test)]
mod test {
    use crate::vdaf::run_vdaf;

    use super::*;

    #[test]
    fn run() {
        assert_eq!(6, run_vdaf(&TrivialPrivate, &[1, 2, 3], &()).unwrap());
    }
}

pub mod theorem_private {

    //! If [`CoinsToField`] is a [PRF](crate::prf), then [`TrivialPrivate`] is
    //! [`private`](crate::vdaf::private).
    //!
    //! Let `vdaf = TrivialPrivate` and `sim = TrivialPrivateSimulator::default()`. Then for every
    //! VDAF attacker `a` there exists a [PRF](crate::prf) attacker `b` such that `a`'s advantage
    //! with respect to `sim` is no greater than `b`'s advantage.

    use crate::vdaf::{
        constructions::trivial_private::TrivialPrivate,
        private::{ClientId, Simulator},
    };
    use prio::field::{random_vector, Field64};
    use std::collections::HashMap;

    use super::*;

    /// [`Simulator`] for the theorem.
    #[derive(Default)]
    pub struct TrivialPrivateSimulator {
        input_shares: HashMap<ClientId, Field64>,
    }

    impl Simulator<TrivialPrivate> for TrivialPrivateSimulator {
        fn sim_shard(
            &mut self,
            _hon_id: AggregatorId,
            cli_id: ClientId,
        ) -> Result<ReportShare<TrivialPrivate>, Error> {
            // TODO(cjpatton) Update `FieldElement` so that we can just call `thread_rng().gen()`
            // here. This will also be needed to instantiate the `RandFunc` game for
            // `CoinsToField`.
            let r = random_vector(1).map_err(|_| "random_vector() failed")?[0];
            self.input_shares.insert(cli_id, r);

            Ok(ReportShare {
                nonce: (),
                public_share: (),
                input_share: r,
            })
        }

        fn sim_prep_init(
            &mut self,
            _adv_vk: &(),
            _hon_id: AggregatorId,
            _cli_id: ClientId,
            _agg_param: &(),
        ) -> Result<(), Error> {
            Ok(())
        }

        fn sim_prep_finish(
            &mut self,
            _cli_id: ClientId,
            _agg_param: &(),
            _prep_shares: &[(); 2],
        ) -> Result<(), Error> {
            Ok(())
        }

        fn sim_agg(
            &mut self,
            cli_ids: &[usize],
            _agg_param: &(),
            agg_result: &u64,
        ) -> Result<Vec<Field64>, Error> {
            let mut agg_share = Field64::from(0);
            for cli_id in cli_ids {
                if let Some(input_share) = self.input_shares.get(cli_id) {
                    agg_share += *input_share;
                }
            }
            Ok(vec![Field64::from(*agg_result) - agg_share])
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;

        use crate::{
            vdaf::private::{test_utils, Ideal, Real},
            Distinguisher,
        };

        #[test]
        fn real() {
            let adv = test_utils::Tester::with(TrivialPrivate);
            let vdaf = TrivialPrivate;
            assert_eq!(adv.play(Real::with(vdaf)), true);
        }

        #[test]
        fn ideal() {
            let adv = test_utils::Tester::with(TrivialPrivate);
            let sim = TrivialPrivateSimulator::default();
            assert_eq!(adv.play(Ideal::with(sim)), true);
        }
    }
}
