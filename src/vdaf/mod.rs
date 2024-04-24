//! 1-round, 2-party VDAFs [[draft-irtf-cfrg-vdaf]].
//!
//! [draft-irtf-cfrg-vdaf]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/

use std::{hash::Hash, ops::AddAssign};

use rand::{
    distributions::{Distribution, Standard},
    prelude::*,
};

use crate::Error;

pub mod constructions;
pub mod private;

/// Aggregator ID.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AggregatorId {
    Leader = 0,
    Helper = 1,
}

impl AggregatorId {
    /// Return ID of this aggregator's co-aggregator.
    pub fn peer(&self) -> Self {
        match self {
            Self::Leader => Self::Helper,
            Self::Helper => Self::Leader,
        }
    }
}

/// VDAF report share sent from a client to an aggregator.
#[derive(Clone)]
pub struct ReportShare<V: Vdaf> {
    pub nonce: V::Nonce,
    pub public_share: V::PublicShare,
    pub input_share: V::InputShare,
}

/// Syntax for a 1-round, 2-party VDAF.
pub trait Vdaf: Clone {
    /// Key used during preparation of a report.
    type VerifyKey: Clone;

    /// Nonce included with each report.
    type Nonce: Clone;

    /// Coins consumed by [`Vdaf::shard`].
    type Coins: Clone;

    /// Measurement type for this VDAF.
    type Measurement: Clone;

    /// Field for aggregation.
    type Field: AddAssign;

    /// The report public share.
    type PublicShare: Clone;

    /// The input share sent to each aggregator in its report share.
    type InputShare;

    /// The state of an aggregator during preparation.
    type PrepState;

    /// The mesesage braodcast by each aggregator during preparation.
    type PrepShare;

    /// The aggregation parameter.
    type AggParam: Clone + Eq + Hash + PartialEq;

    /// Aggregate result for this VDAF.
    type AggResult: Eq + std::fmt::Debug;

    /// Client generates its report.
    fn shard(
        &self,
        measurement: &Self::Measurement,
        nonce: &Self::Nonce,
        coins: &Self::Coins,
    ) -> (Self::PublicShare, [Self::InputShare; 2]);

    /// Aggregator begins preparation of a report.
    fn prep_init(
        &self,
        vk: &Self::VerifyKey,
        agg_id: AggregatorId,
        agg_param: &Self::AggParam,
        report_share: &ReportShare<Self>,
    ) -> (Self::PrepState, Self::PrepShare);

    /// Aggregator finishes preparation of a report and obtains its output share.
    fn prep_finish(
        &self,
        prep_state: Self::PrepState,
        prep_shares: &[Self::PrepShare; 2],
    ) -> Result<Vec<Self::Field>, Error>;

    /// Collector combines the aggregate shares (sums of the output share) into the aggregate
    /// result.
    ///
    /// # Preconditions
    ///
    /// - The length of the aggregate shares must be the same.
    fn unshard(
        &self,
        agg_param: &Self::AggParam,
        agg_shares: [Vec<Self::Field>; 2],
        num_measurements: usize,
    ) -> Self::AggResult;

    /// The aggregation function computed by this VDAF.
    fn agg_func(agg_param: &Self::AggParam, measurements: &[Self::Measurement]) -> Self::AggResult;
}

/// Flip coins and split the measurement into report shares.
fn shard_into_report_shares<V: Vdaf>(vdaf: &V, measurement: &V::Measurement) -> [ReportShare<V>; 2]
where
    Standard: Distribution<V::Nonce> + Distribution<V::Coins>,
{
    let mut rng = thread_rng();
    let nonce = rng.gen();
    let coins = rng.gen();
    let (public_share, [input_share_0, input_share_1]) = vdaf.shard(measurement, &nonce, &coins);
    [
        ReportShare {
            public_share: public_share.clone(),
            input_share: input_share_0,
            nonce: nonce.clone(),
        },
        ReportShare {
            public_share,
            input_share: input_share_1,
            nonce,
        },
    ]
}

/// Execute the VDAF on the measurements and return the aggregate result.
#[cfg(test)]
fn run_vdaf<V: Vdaf>(
    vdaf: &V,
    measurements: &[V::Measurement],
    agg_param: &V::AggParam,
) -> Result<V::AggResult, Error>
where
    Standard: Distribution<V::VerifyKey> + Distribution<V::Nonce> + Distribution<V::Coins>,
{
    use crate::vec_add;

    debug_assert!(!measurements.is_empty());
    let vk = thread_rng().gen();
    let agg_shares = measurements
        .iter()
        .map(|measurement| {
            let [report_share_0, report_share_1] = shard_into_report_shares(vdaf, measurement);
            let (prep_state_0, prep_share_0) =
                vdaf.prep_init(&vk, AggregatorId::Leader, agg_param, &report_share_0);
            let (prep_state_1, prep_share_1) =
                vdaf.prep_init(&vk, AggregatorId::Helper, agg_param, &report_share_1);
            let prep_shares = [prep_share_0, prep_share_1];
            let out_share_0 = vdaf.prep_finish(prep_state_0, &prep_shares)?;
            let out_share_1 = vdaf.prep_finish(prep_state_1, &prep_shares)?;
            debug_assert_eq!(out_share_0.len(), out_share_1.len());
            Ok([out_share_0, out_share_1])
        })
        .reduce(|agg, out| {
            let [agg_share_0, agg_share_1] = agg?;
            let [out_share_0, out_share_1] = out?;
            Ok([
                vec_add(agg_share_0, out_share_0),
                vec_add(agg_share_1, out_share_1),
            ])
        })
        .unwrap()?;
    let agg_result = vdaf.unshard(agg_param, agg_shares, measurements.len());
    debug_assert_eq!(agg_result, V::agg_func(agg_param, measurements));
    Ok(agg_result)
}

/// Send one share to the honest aggregator and another to the malicious aggregator.
fn send<Z>(shares: [Z; 2], hon_id: AggregatorId) -> (Z, Z) {
    let [share_0, share_1] = shares;
    if hon_id == AggregatorId::Helper {
        (share_0, share_1)
    } else {
        (share_1, share_0)
    }
}
