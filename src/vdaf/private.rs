//! Games for defining privacy.

use super::{Error, ReportShare, Vdaf};

/// Interface for attacker playing the real or ideal game.
pub trait Game<V: Vdaf> {
    /// Construct an instance of the game with the given VDAF.
    fn with(vdaf: V) -> Self;

    /// Initialize the game with  verification key `vk` and corrupt Aggregator `id`.
    fn init(&mut self, vk: &[u8], id: u8) -> Result<(), Error>;

    /// Command Client `i` to generate a report for the given measurement, send the honest
    /// Aggregator its report share, and return the corrupt Aggregator's report share.
    fn shard(&mut self, i: usize, measurement: &V::Measurement) -> Result<ReportShare<V>, Error>;

    /// Command the honest Aggregator to initialize preparation of report `i` with the given
    /// aggregation parameter and return its prep share.
    fn prep_init(&mut self, i: usize, agg_param: &V::AggParam) -> Result<V::PrepShare, Error>;

    /// Command the honest Aggregator to finish preparation of report `i` with the given
    /// aggregation parameter and store the output share. Return an indication of whether the
    /// Aggregator successfully recovered an output share.
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

/// Privacy attacker.
pub trait Attacker<V: Vdaf> {
    /// Run the game, then output `true` if we are played the [`Real`] game and `false` if we
    /// played the [`Ideal`] game.
    fn play(&self, game: &mut impl Game<V>) -> bool;
}

/// Real privacy game.
pub struct Real<V: Vdaf> {
    pub vdaf: V,
}

impl<V: Vdaf> Game<V> for Real<V> {
    fn with(_vdaf: V) -> Self {
        todo!()
    }

    fn init(&mut self, _vk: &[u8], _id: u8) -> Result<(), Error> {
        todo!()
    }

    fn shard(&mut self, _i: usize, _measurement: &V::Measurement) -> Result<ReportShare<V>, Error> {
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

/// Privacy simulator. Its job is to fool the adversary into believing it is playing the [`Real`]
/// game when in fact it is playing the [`Ideal`] game.
pub trait Simulator<V: Vdaf> {}

/// Ideal privacy game.
pub struct Ideal<V: Vdaf> {
    pub vdaf: V,
}

impl<V: Vdaf> Game<V> for Ideal<V> {
    fn with(_vdaf: V) -> Self {
        todo!()
    }

    fn init(&mut self, _vk: &[u8], _id: u8) -> Result<(), Error> {
        todo!()
    }

    fn shard(&mut self, _i: usize, _measurement: &V::Measurement) -> Result<ReportShare<V>, Error> {
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
mod test_insecure_vdaf {
    use crate::vdaf::Vdaf;

    use super::*;

    /// A VDAF that has a trivial privacy attack.
    struct InsecureVdaf;

    impl Vdaf for InsecureVdaf {
        const VERIFY_KEY_SIZE: usize = 0;
        const NONCE_SIZE: usize = 16;
        const RAND_SIZE: usize = 0;

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
            _nonce: &[u8],
            _coins: &[u8],
        ) -> Result<(Self::PublicShare, [Self::InputShare; 2]), Error> {
            todo!()
        }

        fn prep_init(
            &self,
            _vk: &[u8],
            _id: u8,
            _agg_param: &Self::AggParam,
            _report_share: &ReportShare<Self>,
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
            _agg_shares: [Vec<Self::Field>; 2],
            _num_measurements: usize,
        ) -> Result<Self::Result, Error> {
            todo!()
        }

        fn agg_len(&self) -> usize {
            todo!()
        }
    }

    struct InsecureVdafAttacker;

    impl Attacker<InsecureVdaf> for InsecureVdafAttacker {
        fn play(&self, _game: &mut impl Game<InsecureVdaf>) -> bool {
            todo!()
        }
    }

    #[test]
    fn insecure_vdaf() {
        assert_eq!(
            InsecureVdafAttacker.play(&mut Real::with(InsecureVdaf)),
            true
        );

        assert_eq!(
            InsecureVdafAttacker.play(&mut Ideal::with(InsecureVdaf)),
            true
        );
    }
}
