//! Private, but not robust.

use prio::{
    codec::Decode,
    field::Field64,
    vdaf::xof::{IntoFieldVec, Seed, Xof, XofTurboShake128},
};

use crate::{
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
/// preparation, thus no measurement validation is performed.
#[derive(Clone)]
pub struct TrivialPrivate;

impl TrivialPrivate {
    /// PRG used to derive derive a field element from random coin flips.
    pub fn coins_to_field(coins: &[u8]) -> Result<Field64, Error> {
        Ok(XofTurboShake128::seed_stream(
            &Seed::get_decoded(coins).map_err(|_| "failed to read coins into XOF seed")?,
            b"coins_to_r",
            b"",
        )
        .into_field_vec(1)[0])
    }
}

impl Vdaf for TrivialPrivate {
    const VERIFY_KEY_SIZE: usize = 0;
    const NONCE_SIZE: usize = 0;
    const RAND_SIZE: usize = 16;

    type Measurement = u64;
    type Field = Field64;
    type PublicShare = ();
    type InputShare = Field64;
    type PrepState = Field64;
    type PrepShare = ();
    type AggParam = ();
    type AggResult = u64;

    fn shard(
        &self,
        measurement: &u64,
        _nonce: &[u8],
        coins: &[u8],
    ) -> Result<((), [Field64; 2]), Error> {
        let r = Self::coins_to_field(coins)?;
        Ok(((), [Field64::from(*measurement) - r, r]))
    }

    fn prep_init(
        &self,
        _vk: &[u8],
        _agg_id: AggregatorId,
        _agg_param: &(),
        report_share: &ReportShare<Self>,
    ) -> Result<(Field64, ()), Error> {
        Ok((report_share.input_share, ()))
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
    ) -> Result<u64, Error> {
        let [agg_share_0, agg_share_1] = agg_shares;
        Ok(vec_add(agg_share_0, agg_share_1)[0].into())
    }

    fn agg_func(_agg_param: &(), measurements: &[u64]) -> u64 {
        measurements.iter().copied().sum()
    }
}

pub mod theorem_private {

    //! If [`TrivialPrivate::coins_to_field`] is a PRG, then [`TrivialPrivate`] is [`private`](crate::vdaf::private).
    //!
    //! Let `vdaf == TrivialPrivate` and `sim == TrivialPrivateSimulator::default()`. Then for
    //! every VDAF attacker `a` there exists a PRG attacker `b` such that `a`'s advantage with
    //! respect to `sim` is no greater than `b`'s advantage.

    use std::collections::HashMap;

    use prio::field::Field64;

    use crate::{
        rand_bytes,
        vdaf::{
            constructions::trivial_private::TrivialPrivate,
            private::{ClientId, Simulator},
            Vdaf,
        },
    };

    use super::*;

    /// [`Simulator`] for the proof.
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
            let r = TrivialPrivate::coins_to_field(&rand_bytes(TrivialPrivate::RAND_SIZE))?;
            self.input_shares.insert(cli_id, r);

            Ok(ReportShare {
                nonce: rand_bytes(TrivialPrivate::NONCE_SIZE),
                public_share: (),
                input_share: r,
            })
        }

        fn sim_prep_init(
            &mut self,
            _adv_vk: &[u8],
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
                if let Some(input_share) = self.input_shares.get(&cli_id) {
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
            let adv = test_utils::HonestButCurious::with(TrivialPrivate);
            let vdaf = TrivialPrivate;
            assert_eq!(adv.play(Real::with(vdaf)), Ok(true));
        }

        #[test]
        fn ideal() {
            let adv = test_utils::HonestButCurious::with(TrivialPrivate);
            let sim = TrivialPrivateSimulator::default();
            assert_eq!(adv.play(Ideal::with(sim)), Ok(true));
        }
    }
}
