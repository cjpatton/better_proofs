//! Games for defining robustness.

use super::{Error, ReportShare, Vdaf};

/// Transcript of preparation for a given report.
pub struct Transcript<V: Vdaf> {
    /// The prep share sent by each Aggregator.
    pub prep_shares: [V::PrepShare; 2],

    /// The output share recovered by each Aggregator (`None` indicates no share was recovered).
    pub out_shares: [Option<Vec<V::Field>>; 2],
}

/// Interface for attacker playing the real or ideal game.
pub trait Game<V: Vdaf> {
    /// Construct an instance of the game with the given VDAF.
    fn with(vdaf: V) -> Self;

    /// Instruct the Aggregators to process the given report shares using the given aggregation
    /// parameter.
    fn prep(
        &mut self,
        report_shares: [ReportShare<V>; 2],
        agg_param: &V::AggParam,
    ) -> Result<Transcript<V>, Error>;
}

/// Real robustness game.
pub struct Real<V: Vdaf> {
    pub vdaf: V,
}

impl<V: Vdaf> Game<V> for Real<V> {
    fn with(_vdaf: V) -> Self {
        todo!()
    }

    fn prep(
        &mut self,
        _report_shares: [ReportShare<V>; 2],
        _agg_param: &V::AggParam,
    ) -> Result<Transcript<V>, Error> {
        todo!()
    }
}

/// Robustness simulator. Its job is to fool the adversary into believing it is playing the [`Real`]
/// game when in fact it is playing the [`Ideal`] game.
pub trait Simulator<V: Vdaf> {}

/// Ideal robustness game.
pub struct Ideal<V: Vdaf> {
    pub vdaf: V,
}

impl<V: Vdaf> Game<V> for Ideal<V> {
    fn with(_vdaf: V) -> Self {
        todo!()
    }

    fn prep(
        &mut self,
        _report_shares: [ReportShare<V>; 2],
        _agg_param: &V::AggParam,
    ) -> Result<Transcript<V>, Error> {
        todo!()
    }
}
