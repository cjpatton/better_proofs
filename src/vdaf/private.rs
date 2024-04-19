//! Definition of privacy.
//!
//! The adversary is a [`Distinguisher`](crate::Distinguisher) interacting with a [`Game`]. There
//! are two implementations of this trait:
//!
//! - [`Real`] executes a [`Vdaf`] in the presence of an attacker with one honest aggregator.
//!
//! - [`Ideal`] runs the same experiment except the honest aggregator is replaced with a
//! [`Simulator`] that only has access to aggregate results.
//!
//! Each of these games is defined by instantiating [`Env`]'s generic parameters:
//!
//! ```test
//!                                            .
//!                                            .
//!   +-----------------------------------+    .    +----------------------------------+
//!   | Real                              |    .    | Ideal                            |
//!   | +-------------------------------+ |    .    | +------------------------------+ |
//!   | | Env                           | |    .    | | Env                          | |
//!   | | +---------------------------+ | |    .    | | +--------------------------+ | |
//!   | | | Vdaf w/ honest aggregator | | |    .    | | | Simulator w/ agg results | | |
//!   | | +---------------------------+ | |    .    | | +--------------------------+ | |
//!   | +-------------------------------+ |    .    | +------------------------------+ |
//!   +-----------------------------------+    .    +----------------------------------+
//!                    ^                       .                     ^
//!                    |                       .                     |
//!               Distinguisher                .                Distinguisher
//! ```
//!
//! Let `vdaf` be a [`Vdaf`], `adv` be a [`Distinguisher`](crate::Distinguisher), and `sim` be a
//! [`Simulator`]. We define the advantage of `adv` in breaking `vdaf`'s privacy with respect to
//! `sim` as
//!
//! ```text
//! Adv[adv, sim, vdaf] =
//!     Pr[adv.play(Real::with(vdaf)) == Ok(true)] - Pr[adv.play(Ideal::with(sim)) == Ok(true)]
//! ```
//!
//! Informally, we say that `vdaf` is private if for every efficient `adv` there is an efficient
//! `sim` such that `adv`'s advantage is small.

use std::collections::HashMap;

use rand::distributions::{Distribution, Standard};

use crate::vec_add;

use super::{send, shard_into_report_shares, AggregatorId, Error, ReportShare, Vdaf};

/// Client ID.
pub type ClientId = usize;

// Traits

/// Interface for an attacker playing the [`Real`] or [`Ideal`] game.
pub trait Game<V: Vdaf> {
    /// Initialize the game with the verification key and corrupt aggregator.
    fn init(&mut self, adv_vk: &V::VerifyKey, adv_id: AggregatorId) -> Result<(), Error>;

    /// Command a client to generate a report for the given measurement, send the honest aggregator
    /// its report share, and return the corrupt aggregator's report share.
    fn shard(
        &mut self,
        cli_id: ClientId,
        measurement: &V::Measurement,
    ) -> Result<ReportShare<V>, Error>;

    /// Command the honest aggregator to initialize preparation of a client's report with the given
    /// aggregation parameter and return its prep share.
    fn prep_init(
        &mut self,
        cli_id: ClientId,
        agg_param: &V::AggParam,
    ) -> Result<V::PrepShare, Error>;

    /// Command the honest aggregator to finish preparation of a clients report with the given
    /// aggregation parameter and store the output share.
    fn prep_finish(
        &mut self,
        cli_id: ClientId,
        agg_param: &V::AggParam,
        prep_shares: &[V::PrepShare; 2],
    ) -> Result<(), Error>;

    /// Command the honest aggregator to computes the aggregate share for the given aggregation
    /// parameter.
    fn agg(&mut self, agg_param: &V::AggParam) -> Result<Vec<V::Field>, Error>;
}

/// Simlulates the honest aggregator in the [`Ideal`] game given only the aggregate results.
pub trait Simulator<V: Vdaf> {
    fn sim_shard(
        &mut self,
        hon_id: AggregatorId,
        cli_id: ClientId,
    ) -> Result<ReportShare<V>, Error>;

    fn sim_prep_init(
        &mut self,
        adv_vk: &V::VerifyKey,
        hon_id: AggregatorId,
        cli_id: ClientId,
        agg_param: &V::AggParam,
    ) -> Result<V::PrepShare, Error>;

    fn sim_prep_finish(
        &mut self,
        cli_id: ClientId,
        agg_param: &V::AggParam,
        prep_shares: &[V::PrepShare; 2],
    ) -> Result<(), Error>;

    fn sim_agg(
        &mut self,
        cli_ids: &[ClientId],
        agg_param: &V::AggParam,
        agg_result: &V::AggResult,
    ) -> Result<Vec<V::Field>, Error>;
}

// Middleware

/// Middleware between [`Vdaf`] and [`Env`] in the [`Real`] game. (Likewise for [`Simulator`] in
/// the [`Ideal`] game.)
pub trait Handler<V: Vdaf, S, W, R> {
    fn handle_shard(
        &mut self,
        hon_id: AggregatorId,
        cli_id: ClientId,
        measurement: &V::Measurement,
    ) -> Result<(S, ReportShare<V>), Error>;

    fn handle_prep_init(
        &mut self,
        s: &S,
        adv_vk: &V::VerifyKey,
        hon_id: AggregatorId,
        cli_id: ClientId,
        agg_param: &V::AggParam,
    ) -> Result<(W, V::PrepShare), Error>;

    fn handle_prep_finish(
        &mut self,
        w: W,
        cli_id: ClientId,
        agg_param: &V::AggParam,
        prep_shares: &[V::PrepShare; 2],
    ) -> Result<R, Error>;

    fn handle_agg(
        &mut self,
        items: Vec<(ClientId, S, R)>,
        agg_param: &V::AggParam,
    ) -> Result<Vec<V::Field>, Error>;
}

impl<V: Vdaf> Handler<V, ReportShare<V>, V::PrepState, Vec<V::Field>> for V
where
    Standard: Distribution<V::Nonce> + Distribution<V::Coins>,
{
    fn handle_shard(
        &mut self,
        hon_id: AggregatorId,
        _cli_id: ClientId,
        measurement: &V::Measurement,
    ) -> Result<(ReportShare<V>, ReportShare<V>), Error> {
        let report_shares = shard_into_report_shares(self, measurement)?;
        Ok(send(report_shares, hon_id))
    }

    fn handle_prep_init(
        &mut self,
        report_share: &ReportShare<V>,
        adv_vk: &V::VerifyKey,
        hon_id: AggregatorId,
        _cli_id: ClientId,
        agg_param: &V::AggParam,
    ) -> Result<(V::PrepState, V::PrepShare), Error> {
        self.prep_init(adv_vk, hon_id, agg_param, report_share)
    }

    fn handle_prep_finish(
        &mut self,
        prep_state: V::PrepState,
        _cli_id: ClientId,
        _agg_param: &V::AggParam,
        prep_shares: &[V::PrepShare; 2],
    ) -> Result<Vec<V::Field>, Error> {
        self.prep_finish(prep_state, prep_shares)
    }

    fn handle_agg(
        &mut self,
        items: Vec<(ClientId, ReportShare<V>, Vec<V::Field>)>,
        _agg_param: &V::AggParam,
    ) -> Result<Vec<V::Field>, Error> {
        items
            .into_iter()
            .map(|(_cli_id, _report_share, out_share)| out_share)
            .reduce(vec_add)
            .ok_or("empty aggregate share")
    }
}

impl<V: Vdaf, S: Simulator<V>> Handler<V, V::Measurement, (), ()> for S {
    fn handle_shard(
        &mut self,
        hon_id: AggregatorId,
        cli_id: ClientId,
        measurement: &V::Measurement,
    ) -> Result<(V::Measurement, ReportShare<V>), Error> {
        // Command the simulator to simulate the report share sent to the attacker from the client.
        // Have the game store the measurement so we can aggregate directly later.
        Ok((measurement.clone(), self.sim_shard(hon_id, cli_id)?))
    }

    fn handle_prep_init(
        &mut self,
        _s: &V::Measurement,
        adv_vk: &V::VerifyKey,
        hon_id: AggregatorId,
        cli_id: ClientId,
        agg_param: &V::AggParam,
    ) -> Result<((), V::PrepShare), Error> {
        // Command the simulator to simulate the honest aggregator's prep share.
        Ok(((), self.sim_prep_init(adv_vk, hon_id, cli_id, agg_param)?))
    }

    fn handle_prep_finish(
        &mut self,
        _w: (),
        cli_id: ClientId,
        agg_param: &V::AggParam,
        prep_shares: &[V::PrepShare; 2],
    ) -> Result<(), Error> {
        // Command the simulator to simulate preparation finalization.
        self.sim_prep_finish(cli_id, agg_param, prep_shares)
    }

    fn handle_agg(
        &mut self,
        items: Vec<(ClientId, V::Measurement, ())>,
        agg_param: &<V as Vdaf>::AggParam,
    ) -> Result<Vec<<V as Vdaf>::Field>, Error> {
        // Give the simulator the aggregate result and command it to simulate the honest
        // aggregator's aggregate share.
        let (cli_ids, measurements): (Vec<ClientId>, Vec<V::Measurement>) = items
            .into_iter()
            .map(|(cli_id, measurement, _r)| (cli_id, measurement))
            .unzip();
        let agg_result = V::agg_func(agg_param, &measurements);
        self.sim_agg(&cli_ids, agg_param, &agg_result)
    }
}

// Execution environment

enum AggState<W, R> {
    Waiting(W),
    Ready(R),
    Aggregated,
}

type AggStatePerParam<A, W, R> = HashMap<A, AggState<W, R>>;

type EvalPerClient<S, A, W, R> = (S, AggStatePerParam<A, W, R>);

/// Execution environment used to instantiate [`Game`].
#[derive(Default)]
pub struct Env<V, H, S, W, R>
where
    V: Vdaf,
    H: Handler<V, S, W, R>,
{
    handler: H,
    init: Option<(V::VerifyKey, AggregatorId)>,
    eval: HashMap<ClientId, EvalPerClient<S, V::AggParam, W, R>>,
}

impl<V, H, S, W, R> Game<V> for Env<V, H, S, W, R>
where
    V: Vdaf,
    H: Handler<V, S, W, R>,
    S: Clone,
{
    fn init(&mut self, adv_vk: &V::VerifyKey, adv_id: AggregatorId) -> Result<(), Error> {
        if self.init.is_some() {
            return Err("already initialized");
        }

        self.init = Some((adv_vk.clone(), adv_id.peer()));
        Ok(())
    }

    fn shard(
        &mut self,
        cli_id: ClientId,
        measurement: &V::Measurement,
    ) -> Result<ReportShare<V>, Error> {
        let Some((_adv_vk, hon_id)) = &self.init else {
            return Err("game not initialized");
        };

        if self.eval.get(&cli_id).is_some() {
            return Err("report already uploaded");
        }

        let (s, adv_report_share) = self.handler.handle_shard(*hon_id, cli_id, measurement)?;
        self.eval.insert(cli_id, (s, HashMap::new()));
        Ok(adv_report_share)
    }

    fn prep_init(
        &mut self,
        cli_id: ClientId,
        agg_param: &V::AggParam,
    ) -> Result<V::PrepShare, Error> {
        let Some((adv_vk, hon_id)) = &self.init else {
            return Err("game not initialized");
        };

        let Some((s, agg_states)) = self.eval.get_mut(&cli_id) else {
            return Err("report not yet uploaded");
        };

        if agg_states.get(agg_param).is_some() {
            return Err("preparation already in progress");
        }

        let (w, hon_prep_share) = self
            .handler
            .handle_prep_init(s, adv_vk, *hon_id, cli_id, agg_param)?;

        agg_states.insert(agg_param.clone(), AggState::Waiting(w));
        Ok(hon_prep_share)
    }

    fn prep_finish(
        &mut self,
        cli_id: ClientId,
        agg_param: &V::AggParam,
        prep_shares: &[V::PrepShare; 2],
    ) -> Result<(), Error> {
        let Some((_report_share, agg_states)) = self.eval.get_mut(&cli_id) else {
            return Err("report not yet uploaded");
        };

        let Some(AggState::Waiting(w)) = agg_states.remove(agg_param) else {
            return Err("preparation complete or not yet started");
        };

        let r = self
            .handler
            .handle_prep_finish(w, cli_id, agg_param, prep_shares)?;
        agg_states.insert(agg_param.clone(), AggState::Ready(r));
        Ok(())
    }

    fn agg(&mut self, agg_param: &V::AggParam) -> Result<Vec<V::Field>, Error> {
        let mut items = Vec::new();
        for (cli_id, (s, agg_states)) in self.eval.iter_mut() {
            let Some(AggState::Ready(r)) = agg_states.remove(agg_param) else {
                continue;
            };

            items.push((*cli_id, s.clone(), r));
            agg_states.insert(agg_param.clone(), AggState::Aggregated);
        }

        let hon_agg_share = self.handler.handle_agg(items, agg_param)?;
        Ok(hon_agg_share)
    }
}

// Games

/// Real privacy game.
pub type Real<V> = Env<V, V, ReportShare<V>, <V as Vdaf>::PrepState, Vec<<V as Vdaf>::Field>>;

impl<V: Vdaf> Real<V>
where
    Standard: Distribution<V::Nonce> + Distribution<V::Coins>,
{
    /// Construct an instance of the [`Real`] game with the given VDAF.
    pub fn with(vdaf: V) -> Self {
        Self {
            handler: vdaf,
            init: None,
            eval: HashMap::new(),
        }
    }
}

/// Ideal privacy game.
pub type Ideal<V, S> = Env<V, S, <V as Vdaf>::Measurement, (), ()>;

impl<V: Vdaf, S: Simulator<V>> Ideal<V, S> {
    /// Construct an instance of the [`Ideal`] game with the given simulator.
    pub fn with(sim: S) -> Self {
        Self {
            handler: sim,
            init: None,
            eval: HashMap::new(),
        }
    }
}

#[cfg(test)]
pub mod test_utils {
    use prio::field::FieldElementWithInteger;
    use rand::prelude::*;

    use crate::{vdaf::Vdaf, vec_add, Distinguisher};

    use super::*;

    /// Test some basic correctness properties.
    pub struct Tester<V> {
        vdaf: V,
    }

    impl<V> Tester<V> {
        pub fn with(vdaf: V) -> Self {
            Self { vdaf }
        }
    }

    impl<G, V, F> Distinguisher<G> for Tester<V>
    where
        G: Game<V>,
        V: Vdaf<Measurement = u64, Field = F, AggParam = (), AggResult = u64>,
        F: FieldElementWithInteger<Integer = u64>,
        Standard: Distribution<V::VerifyKey>,
    {
        fn play(&self, mut game: G) -> Result<bool, Error> {
            let batch_size = 10;
            let test_measurement = 1;
            let vk = thread_rng().gen();

            // Corrupt the leader.
            game.init(&vk, AggregatorId::Leader)?;

            // Aggregate a few reports.
            let mut out_shares_0 = Vec::new();
            for i in 0..batch_size {
                // Sharding
                let report_share_0 = game.shard(i, &test_measurement)?;

                // Preparation
                let (prep_state, prep_share_0) =
                    self.vdaf
                        .prep_init(&vk, AggregatorId::Leader, &(), &report_share_0)?;
                let prep_share_1 = game.prep_init(i, &())?;
                let prep_shares = [prep_share_0, prep_share_1];
                game.prep_finish(i, &(), &prep_shares)?;

                out_shares_0.push(self.vdaf.prep_finish(prep_state, &prep_shares)?);
            }

            let agg_share_0 = out_shares_0
                .into_iter()
                .reduce(|agg, out| vec_add(agg, out))
                .unwrap();
            let agg_share_1 = game.agg(&())?;
            let agg_result = self
                .vdaf
                .unshard(&(), [agg_share_0, agg_share_1], batch_size)?;

            if agg_result != test_measurement * batch_size as u64 {
                // In the real world, the honest aggregator will compute a share of 0. If it does
                // not, then guess we're in the ideal world.
                return Ok(false);
            }

            // Always guess that we're in the real world.
            Ok(true)
        }
    }
}
