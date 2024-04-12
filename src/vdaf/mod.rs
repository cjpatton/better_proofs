//! 1-round, 2-party VDAFs [[draft-irtf-cfrg-vdaf]].
//!
//! [draft-irtf-cfrg-vdaf]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/

use std::{hash::Hash, ops::AddAssign};

use crate::{rand_bytes, vec_add, Error};

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
    pub nonce: Vec<u8>,
    pub public_share: V::PublicShare,
    pub input_share: V::InputShare,
}

/// Syntax for a 1-round, 2-party VDAF.
pub trait Vdaf: Clone {
    const VERIFY_KEY_SIZE: usize;
    const RAND_SIZE: usize;
    const NONCE_SIZE: usize;

    type Measurement: Clone;
    type Field: AddAssign;
    type PublicShare: Clone;
    type InputShare;
    type PrepState;
    type PrepShare;
    type AggParam: Clone + Eq + Hash + PartialEq;
    type AggResult: Eq + std::fmt::Debug;

    /// Client generates its report.
    fn shard(
        &self,
        measurement: &Self::Measurement,
        nonce: &[u8],
        coins: &[u8],
    ) -> Result<(Self::PublicShare, [Self::InputShare; 2]), Error>;

    /// Aggregator begins preparation of a report.
    fn prep_init(
        &self,
        vk: &[u8],
        agg_id: AggregatorId,
        agg_param: &Self::AggParam,
        report_share: &ReportShare<Self>,
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
        agg_shares: [Vec<Self::Field>; 2],
        num_measurements: usize,
    ) -> Result<Self::AggResult, Error>;

    /// The aggregation function computed by this VDAF.
    fn agg_func(agg_param: &Self::AggParam, measurements: &[Self::Measurement]) -> Self::AggResult;

    /// Flip coins and split the measurement into report shares.
    fn shard_into_report_shares(
        &self,
        measurement: &Self::Measurement,
    ) -> Result<[ReportShare<Self>; 2], Error> {
        let nonce = rand_bytes(Self::NONCE_SIZE);
        let coins = rand_bytes(Self::RAND_SIZE);
        let (public_share, [input_share_0, input_share_1]) =
            self.shard(measurement, &nonce, &coins)?;
        Ok([
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
        ])
    }

    /// Execute the VDAF on the measurements and return the aggregate result.
    fn run(
        &self,
        measurements: &[Self::Measurement],
        agg_param: &Self::AggParam,
    ) -> Result<Self::AggResult, Error> {
        debug_assert!(!measurements.is_empty());
        let vk = rand_bytes(Self::VERIFY_KEY_SIZE);
        let agg_shares = measurements
            .iter()
            .map(|measurement| {
                let [report_share_0, report_share_1] =
                    self.shard_into_report_shares(measurement)?;
                let (prep_state_0, prep_share_0) =
                    self.prep_init(&vk, AggregatorId::Leader, agg_param, &report_share_0)?;
                let (prep_state_1, prep_share_1) =
                    self.prep_init(&vk, AggregatorId::Helper, agg_param, &report_share_1)?;
                let prep_shares = [prep_share_0, prep_share_1];
                let out_share_0 = self.prep_finish(prep_state_0, &prep_shares)?;
                let out_share_1 = self.prep_finish(prep_state_1, &prep_shares)?;
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
        let agg_result = self.unshard(agg_param, agg_shares, measurements.len())?;
        debug_assert_eq!(agg_result, Self::agg_func(agg_param, measurements));
        Ok(agg_result)
    }
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
