//! Games for defining privacy.

use super::{Error, ReportShare, Vdaf};

/// Interface for attacker playing the real or ideal game.
pub trait Game<V: Vdaf<KS>, const KS: usize> {
    /// Initialize the game with  verification key `vk` and corrupt Aggregator `id`.
    fn init(&mut self, vk: [u8; KS], id: u8) -> Result<(), Error>;

    /// Command Client `i` to generate a report for the given measurement, send the honest
    /// Aggregator its report share, and return the corrupt Aggregator's report share.
    fn shard(
        &mut self,
        i: usize,
        measurement: &V::Measurement,
    ) -> Result<ReportShare<V, KS>, Error>;

    /// Command the honest Aggregator to initialize preparation of report `i` with the given
    /// aggregation parameter and return its prep share.
    fn prep_init(&mut self, i: usize, agg_param: &V::AggParam) -> Result<V::PrepShare, Error>;

    /// Command the honest Aggregator to finish preparation of report `i` with the given
    /// aggregation parameter and store the output share. Return an indication of whether the
    /// Aggregator successfuly recovered an output share.
    fn prep_finish(
        &mut self,
        i: usize,
        agg_param: &V::AggParam,
        prep_shares: [V::PrepShare; 2],
    ) -> Result<bool, Error>;

    /// Command the honest Aggregator to computes the aggregate share for the given aggregation
    /// parameter.
    fn agg(&mut self, agg_param: &V::AggParam) -> Result<Vec<V::Field>, Error>;
}

/// Privacy Attacker.
pub trait Attacker<V: Vdaf<KS>, const KS: usize> {
    fn play(&self, game: &mut impl Game<V, KS>) -> bool;
}

/// Real privacy game.
pub struct Real<V: Vdaf<KS>, const KS: usize> {
    pub vdaf: V,
}

impl<V: Vdaf<KS>, const KS: usize> Game<V, KS> for Real<V, KS> {
    fn init(&mut self, _vk: [u8; KS], _id: u8) -> Result<(), Error> {
        todo!()
    }

    fn shard(
        &mut self,
        _i: usize,
        _measurement: &V::Measurement,
    ) -> Result<ReportShare<V, KS>, Error> {
        todo!()
    }

    fn prep_init(&mut self, _i: usize, _agg_param: &V::AggParam) -> Result<V::PrepShare, Error> {
        todo!()
    }

    fn prep_finish(
        &mut self,
        _i: usize,
        _agg_param: &V::AggParam,
        _prep_shares: [V::PrepShare; 2],
    ) -> Result<bool, Error> {
        todo!()
    }

    fn agg(&mut self, _agg_param: &V::AggParam) -> Result<Vec<V::Field>, Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::vdaf::Vdaf;

    use super::*;

    struct InsecureVdaf;

    impl Vdaf<16> for InsecureVdaf {
        type Measurement = ();
        type Result = ();
        type Field = i32; // Not a field
        type PublicShare = ();
        type InputShare = ();
        type PrepState = ();
        type PrepShare = ();
        type PrepMsg = ();
        type AggParam = ();

        fn shard(
            &self,
            _measurement: &Self::Measurement,
            _nonce: &[u8; 16],
            _coins: &[u8; 16],
        ) -> Result<(Self::PublicShare, [Self::InputShare; 2]), Error> {
            todo!()
        }

        fn prep_init(
            &self,
            _vk: &[u8; 16],
            _id: u8,
            _agg_param: &Self::AggParam,
            _report_share: &ReportShare<Self, 16>,
        ) -> Result<(Self::PrepState, Self::PrepShare), Error> {
            todo!()
        }

        fn prep_finish(
            &self,
            _prep_state: Self::PrepState,
            _prep_shares: &[Self::PrepShare; 2],
        ) -> Result<Vec<Self::Field>, Error> {
            todo!()
        }

        fn unshard(
            &self,
            _agg_param: &Self::AggParam,
            _agg_share_0: Vec<Self::Field>,
            _agg_share_1: Vec<Self::Field>,
            _num_measurements: usize,
        ) -> Result<Self::Result, Error> {
            todo!()
        }

        fn agg_len(&self) -> usize {
            todo!()
        }
    }

    /// This attacker just executes the protocol faifthully.
    struct BenignAttacker;

    impl Attacker<InsecureVdaf, 16> for BenignAttacker {
        fn play(&self, _game: &mut impl Game<InsecureVdaf, 16>) -> bool {
            todo!()
        }
    }

    #[test]
    fn benign_real() {
        let mut real = Real { vdaf: InsecureVdaf };
        assert_eq!(BenignAttacker {}.play(&mut real), true);
    }
}
