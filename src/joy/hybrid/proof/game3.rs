use rand::{
    distributions::{Distribution, Standard},
    prelude::*,
};

use crate::joy::hybrid::{GetPublicKey, Hybrid, LeftOrRight, PubEnc, SymEnc};

/// Game 3: Encrypt the right plaintext.
///
/// CLAIM: For all [distinguishers](crate::Distinguisher) `adv`,
///
/// ```text
/// Pr[adv.play(G2::init(hybrid))] =
///     Pr[adv.play(FromHybridToSymEnc::init(Cpa::init(sym_nec, false), pub_enc))]
/// ```
/// and
/// ```text
/// Pr[adv.play(G3::init(hybrid))] =
///     Pr[adv.play(FromHybridToSymEnc::init(Cpa::init(sym_nec, true), pub_enc))]
/// ```
pub struct G3<P: PubEnc, S> {
    enc: Hybrid<P, S>,
    pk: P::PublicKey,
}
impl<P: PubEnc, S> G3<P, S> {
    pub fn init(enc: Hybrid<P, S>) -> Self {
        let (pk, _sk) = enc.pub_enc.key_gen();
        Self { enc, pk }
    }
}
impl<P: PubEnc, S> GetPublicKey for G3<P, S> {
    type PublicKey = P::PublicKey;
    fn get_pk(&self) -> &P::PublicKey {
        &self.pk
    }
}
impl<P, S> LeftOrRight for G3<P, S>
where
    S: SymEnc,
    P: PubEnc<Plaintext = S::Key>,
    Standard: Distribution<S::Key>,
{
    type Plaintext = S::Plaintext;
    type Ciphertext = (P::Ciphertext, S::Ciphertext);
    fn left_or_right(
        &self,
        _m_left: &S::Plaintext,
        m_right: &S::Plaintext,
    ) -> (P::Ciphertext, S::Ciphertext) {
        let mut rng = thread_rng();
        let tk_left = rng.gen();
        let tk_right = rng.gen();
        let c_pub = self.enc.pub_enc.encrypt(&self.pk, &tk_right);
        let c_sym = self.enc.sym_enc.encrypt(&tk_left, m_right); // encrypt right plaintext
        (c_pub, c_sym)
    }
}

#[cfg(test)]
mod test_2_3 {
    use crate::{
        joy::hybrid::{
            proof::{game2::G2, FromHybridToSymEnc},
            test_utils, Cpa,
        },
        test_utils::TrivialDistinguisher,
        Distinguisher,
    };

    use super::*;

    #[test]
    fn equiv_game_2_red() {
        let pub_enc = test_utils::TrivialPubEnc;
        let sym_enc = test_utils::TrivialSymEnc;
        let hybrid = Hybrid { pub_enc, sym_enc };
        let adv = TrivialDistinguisher;

        assert_eq!(
            adv.play(G2::init(hybrid)),
            adv.play(FromHybridToSymEnc::init(Cpa::init(sym_enc, false), pub_enc)),
        );
    }

    #[test]
    fn equiv_game_3_red() {
        let pub_enc = test_utils::TrivialPubEnc;
        let sym_enc = test_utils::TrivialSymEnc;
        let hybrid = Hybrid { pub_enc, sym_enc };
        let adv = TrivialDistinguisher;

        assert_eq!(
            adv.play(G3::init(hybrid)),
            adv.play(FromHybridToSymEnc::init(Cpa::init(sym_enc, true), pub_enc)),
        );
    }
}
