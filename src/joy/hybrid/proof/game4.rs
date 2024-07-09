use rand::{
    distributions::{Distribution, Standard},
    prelude::*,
};

use crate::joy::hybrid::{GetPublicKey, Hybrid, LeftOrRight, PubEnc, SymEnc};

/// Game 4: Wrap the right temporary key.
///
/// CLAIM: For all [distinguishers](crate::Distinguisher) `adv`,
///
/// ```text
/// Pr[adv.play(G3::init(hybrid))] =
///     Pr[adv.play(FromHybridToPubEnc::init(PubCpa::init(pub_nec, false), sym_enc, true))]
/// ```
/// and
/// ```text
/// Pr[adv.play(G4::init(hybrid))] =
///     Pr[adv.play(FromHybridToPubEnc::init(PubCpa::init(pub_nec, true), sym_enc, true))]
/// ```
pub struct G4<P: PubEnc, S> {
    enc: Hybrid<P, S>,
    pk: P::PublicKey,
}
impl<P: PubEnc, S> G4<P, S> {
    pub fn init(enc: Hybrid<P, S>) -> Self {
        let (pk, _sk) = enc.pub_enc.key_gen();
        Self { enc, pk }
    }
}
impl<P: PubEnc, S> GetPublicKey for G4<P, S> {
    type PublicKey = P::PublicKey;
    fn get_pk(&self) -> &P::PublicKey {
        &self.pk
    }
}
impl<P, S> LeftOrRight for G4<P, S>
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
        let _tk_left = rng.gen(); // no longer used
        let tk_right = rng.gen();
        let c_pub = self.enc.pub_enc.encrypt(&self.pk, &tk_right);
        let c_sym = self.enc.sym_enc.encrypt(&tk_right, m_right); // use right temporary key
        (c_pub, c_sym)
    }
}

#[cfg(test)]
mod test_3_4 {
    use crate::{
        joy::hybrid::{
            proof::{game3::G3, FromHybridToPubEnc},
            test_utils, PubCpa,
        },
        test_utils::TrivialDistinguisher,
        Distinguisher,
    };

    use super::*;

    #[test]
    fn equiv_game_3_red() {
        let pub_enc = test_utils::TrivialPubEnc;
        let sym_enc = test_utils::TrivialSymEnc;
        let hybrid = Hybrid { pub_enc, sym_enc };
        let adv = TrivialDistinguisher;

        assert_eq!(
            adv.play(G3::init(hybrid)),
            adv.play(FromHybridToPubEnc::init(
                PubCpa::init(pub_enc, false),
                sym_enc,
                true,
            )),
        );
    }

    #[test]
    fn equiv_game_4_red() {
        let pub_enc = test_utils::TrivialPubEnc;
        let sym_enc = test_utils::TrivialSymEnc;
        let hybrid = Hybrid { pub_enc, sym_enc };
        let adv = TrivialDistinguisher;

        assert_eq!(
            adv.play(G4::init(hybrid)),
            adv.play(FromHybridToPubEnc::init(
                PubCpa::init(pub_enc, true),
                sym_enc,
                true,
            )),
        );
    }

    #[test]
    fn equiv_game_4_right() {
        let pub_enc = test_utils::TrivialPubEnc;
        let sym_enc = test_utils::TrivialSymEnc;
        let hybrid = Hybrid { pub_enc, sym_enc };
        let adv = TrivialDistinguisher;

        assert_eq!(
            adv.play(G4::init(hybrid)),
            adv.play(PubCpa::init(hybrid, true)),
        );
    }
}
