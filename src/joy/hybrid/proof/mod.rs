//! Claim 15.9: If [`PubEnc`] and [`SymEnc`] are CPA-secure, then so is [`Hybrid<PubEnc, SymEnc>`].

use rand::{
    distributions::{Distribution, Standard},
    prelude::*,
};

use super::{Cpa, GetPublicKey, LeftOrRight, PubCpa, PubEnc, SymEnc};

/// Reduction from a [`Hybrid`] attacker to a [`PubEnc`] attacker.
pub struct FromHybridToPubEnc<P, S>
where
    P: PubEnc,
{
    sym_enc: S,
    game: PubCpa<P>, // Instance of the game for `pub_enc`.
    sim_right: bool,
}
impl<P, S> FromHybridToPubEnc<P, S>
where
    P: PubEnc,
{
    pub fn init(game: PubCpa<P>, sym_enc: S, sim_right: bool) -> Self {
        Self {
            game,
            sym_enc,
            sim_right,
        }
    }
}
impl<P, S> GetPublicKey for FromHybridToPubEnc<P, S>
where
    P: PubEnc,
{
    type PublicKey = P::PublicKey;
    fn get_pk(&self) -> &P::PublicKey {
        self.game.get_pk()
    }
}
impl<P, S> LeftOrRight for FromHybridToPubEnc<P, S>
where
    P: PubEnc,
    S: SymEnc,
    P: PubEnc<Plaintext = S::Key>,
    Standard: Distribution<S::Key>,
{
    type Plaintext = S::Plaintext;
    type Ciphertext = (P::Ciphertext, S::Ciphertext);
    fn left_or_right(
        &self,
        m_left: &S::Plaintext,
        m_right: &S::Plaintext,
    ) -> (P::Ciphertext, S::Ciphertext) {
        let mut rng = thread_rng();
        let tk_left = rng.gen();
        let tk_right = rng.gen();
        // Simulation: If `self.left`, then transition from `G1` to `G2`;
        // otherwise, transition from `G3` to `G4`. If `game.left`, then
        // simulate the former; otherwise simulate the latter.
        let c_pub = self.game.left_or_right(&tk_left, &tk_right);
        let c_sym = if self.sim_right {
            self.sym_enc.encrypt(&tk_left, m_right)
        } else {
            self.sym_enc.encrypt(&tk_left, m_left)
        };
        (c_pub, c_sym)
    }
}

/// Reduction from a [`Hybrid`] attacker to a [`SymEnc`] attacker.
pub struct FromHybridToSymEnc<P, S>
where
    P: PubEnc,
    S: SymEnc,
{
    pub_enc: P,
    pk: P::PublicKey,
    game: Cpa<S>, // Instance of the game for `sym_enc`
}
impl<P, S> FromHybridToSymEnc<P, S>
where
    P: PubEnc,
    S: SymEnc,
{
    pub fn init(game: Cpa<S>, pub_enc: P) -> Self {
        let (pk, _sk) = pub_enc.key_gen();
        Self { pub_enc, pk, game }
    }
}
impl<P, S> GetPublicKey for FromHybridToSymEnc<P, S>
where
    P: PubEnc,
    S: SymEnc,
{
    type PublicKey = P::PublicKey;
    fn get_pk(&self) -> &P::PublicKey {
        &self.pk
    }
}
impl<P, S> LeftOrRight for FromHybridToSymEnc<P, S>
where
    P: PubEnc,
    S: SymEnc,
    P: PubEnc<Plaintext = S::Key>,
    Standard: Distribution<S::Key>,
{
    type Plaintext = S::Plaintext;
    type Ciphertext = (P::Ciphertext, S::Ciphertext);
    fn left_or_right(
        &self,
        m_left: &S::Plaintext,
        m_right: &S::Plaintext,
    ) -> (P::Ciphertext, S::Ciphertext) {
        let tk_right = thread_rng().gen();
        let c_pub = self.pub_enc.encrypt(&self.pk, &tk_right);
        // Simulation: if `game.left`, then this simulates `G2`; otherwise, this
        // simulates `G3`.
        let c_sym = self.game.left_or_right(m_left, m_right);
        (c_pub, c_sym)
    }
}

// Games

pub mod game1;
pub mod game2;
pub mod game3;
pub mod game4;
