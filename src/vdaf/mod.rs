//! Security definitions for 1-round, 2-party VDAFs (draft-irtf-cfrg-vdaf).

use std::ops::AddAssign;

use crate::{rand_bytes, vec_add};

/// VDAF execution error.
pub struct Error();

/// VDAF report share sent by each Client to an Aggregator.
pub struct ReportShare<V, const NS: usize, const KS: usize>
where
    V: Vdaf<NS, KS>,
{
    pub nonce: [u8; NS],
    pub public_share: V::PublicShare,
    pub input_share: V::InputShare,
}

/// Syntax for a 1-round, 2-party VDAF.
pub trait Vdaf<const NS: usize, const KS: usize>: Sized {
    type Measurement;
    type Result;
    type Field: AddAssign;
    type PublicShare;
    type InputShare;
    type PrepState;
    type PrepShare;
    type PrepMsg;
    type AggParam;

    /// Client generates its report.
    fn shard(
        &self,
        measurement: &Self::Measurement,
        pk: &[u8; KS],
    ) -> Result<[ReportShare<Self, NS, KS>; 2], Error>;

    /// Aggregator begins preparation of a report.
    fn prep_init(
        &self,
        vk: &[u8; KS],
        agg_id: u8,
        agg_param: &Self::AggParam,
        report_share: &ReportShare<Self, NS, KS>,
    ) -> Result<(Self::PrepState, Self::PrepShare), Error>;

    /// Aggregator finishes preparation of a report and obtains its output share.
    fn prep_finish(
        &self,
        prep_state: Self::PrepState,
        prep_shares: &[Self::PrepShare; 2],
    ) -> Result<Vec<Self::Field>, Error>;

    /// Collector combines the aggregate shares (sums of the output share) into the aggregate
    /// result.
    fn unshard(
        &self,
        agg_param: &Self::AggParam,
        agg_share_0: Vec<Self::Field>,
        agg_share_1: Vec<Self::Field>,
        num_measurements: usize,
    ) -> Result<Self::Result, Error>;

    /// Length of the encoded aggregate.
    fn agg_len(&self) -> usize;

    /// Execute the VDAF on the measurements and return the aggregate result.
    fn run(
        &self,
        measurements: &[Self::Measurement],
        agg_param: &Self::AggParam,
    ) -> Result<Self::Result, Error> {
        debug_assert!(!measurements.is_empty());
        let vk = rand_bytes();
        let (agg_share_0, agg_share_1) = measurements
            .iter()
            .map(|measurement| {
                let [report_share_0, report_share_1] = self.shard(measurement, &rand_bytes())?;
                let (prep_state_0, prep_share_0) =
                    self.prep_init(&vk, 0, agg_param, &report_share_0)?;
                let (prep_state_1, prep_share_1) =
                    self.prep_init(&vk, 1, agg_param, &report_share_1)?;
                let prep_shares = [prep_share_0, prep_share_1];
                let out_share_0 = self.prep_finish(prep_state_0, &prep_shares)?;
                let out_share_1 = self.prep_finish(prep_state_1, &prep_shares)?;
                debug_assert_eq!(out_share_0.len(), self.agg_len());
                debug_assert_eq!(out_share_1.len(), self.agg_len());
                Ok((out_share_0, out_share_1))
            })
            .reduce(|agg, out| {
                let (agg_share_0, agg_share_1) = agg?;
                let (out_share_0, out_share_1) = out?;
                Ok((
                    vec_add(agg_share_0, out_share_0),
                    vec_add(agg_share_1, out_share_1),
                ))
            })
            .unwrap()?;
        self.unshard(agg_param, agg_share_0, agg_share_1, measurements.len())
    }
}
