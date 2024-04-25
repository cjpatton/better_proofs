//! Definition of robustness.
//!
//! Intuitively, robustness captures the goal that honest aggregators can correctly distinguish
//! between reports for valid measurements and reports for invalid measurements. The adversary is a
//! [`Distinguisher`](crate::Distinguisher) interacting with a [`Game`]. There are two
//! implementations of this trait:
//!
//! - [`Real`] models execution of a [`Vdaf`] in the presence of malicious clients. Both
//! aggregators are presumed to be honest. The attacker is allowed to eavesdrop on their
//! communication but can't otherwise influence the execution beyond submitting malformed reports.
//!
//! - [`Ideal`] runs the same experiment except the computation is simulated by an [`Extractor`]
//! whose goal is to extract plaintext measurements from honestly generated reports.
//!
//! The game provides an oracle for preparing a single report and returning the refined measurement
//! (see [`ExtractableVdaf`]) and the transcript of messages exchanged by the aggregators. The
//! extractor's job is to decide whether the report encodes a valid measurement, and if so, return
//! measurement. It must do so without knowing the aggregation parameter selected by the attacker.
//!
//! Let `vdaf` be a [`Vdaf`], `adv` be a [`Distinguisher`](crate::Distinguisher), and `ext` be a
//! [`Extractor`]. We define the advantage of `adv` in breaking `vdaf`'s robustness with respect to
//! `ext` as
//!
//! ```text
//! Adv[adv, ext, vdaf] =
//!     Pr[adv.play(Real::with(vdaf)) == Ok(true)]
//!       - Pr[adv.play(Ideal::with(vdaf, ext)) == Ok(true)]
//! ```
//!
//! Informally, we say that `vdaf` is robust if for every efficient `adv` there is an efficient
//! `ext` such that `adv`'s advantage is small.

use crate::{vdaf::AggregatorId, vec_add, Error};

use super::{ReportShare, Vdaf};

use rand::{distributions::Standard, prelude::*};

/// Information revealed to the robustness attacker about VDAF execution.
pub struct Transcript<V: Vdaf, O> {
    /// Messages exchanged by the aggregators during preparation of a single report.
    pub prep_shares: [V::PrepShare; 2],
    /// Outcome of preparation, i.e., the refined measurement.
    pub out: Option<O>,
}

// Traits

/// Interface for an attacker playing the [`Real`] or [`Ideal`] game.
pub trait Game<V: Vdaf> {
    /// Run VDAF preparation for a single report.
    fn prep(
        &self,
        agg_param: &V::AggParam,
        nonce: &V::Nonce,
        public_share: &V::PublicShare,
        input_shares: &[V::InputShare; 2],
    ) -> Result<Transcript<V, Vec<V::Field>>, Error>;
}

/// An extractor in the [`Ideal`] game. If the report encodes a valid (partial) measurement, then
/// the extractor's job is to return it.
pub trait Extractor<V: ExtractableVdaf> {
    fn extract(
        &self,
        nonce: &V::Nonce,
        public_share: &V::PublicShare,
        input_shares: &[V::InputShare; 2],
    ) -> Result<Transcript<V, V::PartialMeasurement>, Error>;
}

/// Additional functionality for VDAFs used to define robustness.
pub trait ExtractableVdaf: Vdaf {
    /// Output of the [`Extractor`]. This type is a super set of [`Vdaf::Measurement`] that
    /// captures the fact that it a report may be valid for some aggregation parameters, but not
    /// all.
    type PartialMeasurement;

    /// Refine a partial measurement with the given aggregation parameter. This should equal the
    /// sum of the output shares for an honestly generated report.
    fn refine(
        &self,
        agg_param: &Self::AggParam,
        part_measurement: &Self::PartialMeasurement,
    ) -> Option<Vec<Self::Field>>;
}

// Games

/// Real robustness game.
pub struct Real<V: Vdaf> {
    vdaf: V,
    vk: V::VerifyKey,
}

impl<V: Vdaf> Real<V> {
    /// Construct an instance of the [`Real`] game with the given VDAF.
    pub fn with(vdaf: V) -> Self
    where
        Standard: Distribution<V::VerifyKey>,
    {
        Self {
            vdaf,
            vk: thread_rng().gen(),
        }
    }
}

impl<V: Vdaf> Game<V> for Real<V> {
    fn prep(
        &self,
        agg_param: &V::AggParam,
        nonce: &V::Nonce,
        public_share: &V::PublicShare,
        input_shares: &[V::InputShare; 2],
    ) -> Result<Transcript<V, Vec<V::Field>>, Error> {
        let (prep_state_0, prep_share_0) = self.vdaf.prep_init(
            &self.vk,
            AggregatorId::Leader,
            agg_param,
            &ReportShare {
                nonce: nonce.clone(),
                public_share: public_share.clone(),
                input_share: input_shares[0].clone(),
            },
        );
        let (prep_state_1, prep_share_1) = self.vdaf.prep_init(
            &self.vk,
            AggregatorId::Helper,
            agg_param,
            &ReportShare {
                nonce: nonce.clone(),
                public_share: public_share.clone(),
                input_share: input_shares[1].clone(),
            },
        );

        let prep_shares = [prep_share_0, prep_share_1];
        let res_0 = self.vdaf.prep_finish(prep_state_0, &prep_shares);
        let res_1 = self.vdaf.prep_finish(prep_state_1, &prep_shares);
        let out = match (res_0, res_1) {
            // Preparation succeeded: return the refined measurement.
            (Ok(out_share_0), Ok(out_share_1)) => Some(vec_add(out_share_0, out_share_1)),

            // Preparation failed: return nothing.
            (Err(e0), Err(e1)) if e0 == e1 => None,

            // The aggregators disagree on the outcome. We consider this a break of robustness, so
            // leak this result to the attacker.
            _ => return Err("aggregators disagree about report validity"),
        };

        Ok(Transcript { prep_shares, out })
    }
}

/// Ideal robustness game.
pub struct Ideal<V: ExtractableVdaf, E: Extractor<V>> {
    vdaf: V,
    ext: E,
}

impl<V: ExtractableVdaf, E: Extractor<V>> Ideal<V, E> {
    /// Construct an instance of the [`Ideal`] game with the given VDAF and extractor.
    pub fn with(vdaf: V, ext: E) -> Self {
        Self { vdaf, ext }
    }
}

impl<V: ExtractableVdaf, E: Extractor<V>> Game<V> for Ideal<V, E> {
    fn prep(
        &self,
        agg_param: &V::AggParam,
        nonce: &V::Nonce,
        public_share: &V::PublicShare,
        input_shares: &[V::InputShare; 2],
    ) -> Result<Transcript<V, Vec<V::Field>>, Error> {
        let Transcript { prep_shares, out } =
            self.ext.extract(nonce, public_share, input_shares)?;
        Ok(Transcript {
            prep_shares,
            out: out.and_then(|part_measurement| self.vdaf.refine(agg_param, &part_measurement)),
        })
    }
}
