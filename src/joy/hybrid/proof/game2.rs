use rand::{
    distributions::{Distribution, Standard},
    prelude::*,
};

use crate::joy::hybrid::{GetPublicKey, Hybrid, LeftOrRight, PubEnc, SymEnc};

/// Game 2: Encrypt the plaintext with the right temporary key.
///
/// The symmetric-key ciphertext is now independent of the public-key ciphertext.
///
/// CLAIM: For all [distinguishers](crate::Distinguisher) `adv`,
///
/// ```text
/// Pr[adv.play(G1::init(hybrid))] =
///     Pr[adv.play(FromHybridToPubEnc::init(PubCpa::init(pub_nec, false), sym_enc, false))]
/// ```
/// and
/// ```text
/// Pr[adv.play(G2::init(hybrid))] =
///     Pr[adv.play(FromHybridToPubEnc::init(PubCpa::init(pub_nec, true), sym_enc, false))]
/// ```
///
/// CLAIM: For all [distinguishers](crate::Distinguisher) `adv`,
///
/// ```text
/// Pr[adv.play(G4::init(hybrid))] = Pr[adv.play(PubCpa::init(hybrid, true))]
/// ```
pub struct G2<P: PubEnc, S> {
    enc: Hybrid<P, S>,
    pk: P::PublicKey,
}
impl<P: PubEnc, S> G2<P, S> {
    pub fn init(enc: Hybrid<P, S>) -> Self {
        let (pk, _sk) = enc.pub_enc.key_gen();
        Self { enc, pk }
    }
}
impl<P: PubEnc, S> GetPublicKey for G2<P, S> {
    type PublicKey = P::PublicKey;
    fn get_pk(&self) -> &P::PublicKey {
        &self.pk
    }
}
impl<P, S> LeftOrRight for G2<P, S>
where
    S: SymEnc,
    P: PubEnc<Plaintext = S::Key>,
    Standard: Distribution<S::Key>,
{
    type Plaintext = S::Plaintext;
    type Ciphertext = (P::Ciphertext, S::Ciphertext);
    fn left_or_right(
        &self,
        m_left: &S::Plaintext,
        _m_right: &S::Plaintext,
    ) -> (P::Ciphertext, S::Ciphertext) {
        let mut rng = thread_rng();
        let tk_left = rng.gen();
        let tk_right = rng.gen(); // new temporary key
        let c_pub = self.enc.pub_enc.encrypt(&self.pk, &tk_right);
        let c_sym = self.enc.sym_enc.encrypt(&tk_left, m_left);
        (c_pub, c_sym)
    }
}

#[cfg(test)]
mod test_1_2 {
    use crate::{
        joy::hybrid::{
            proof::{game1::G1, FromHybridToPubEnc},
            test_utils, PubCpa,
        },
        test_utils::TrivialDistinguisher,
        Distinguisher,
    };

    use super::*;

    #[test]
    fn equiv_game_1_red() {
        let pub_enc = test_utils::TrivialPubEnc;
        let sym_enc = test_utils::TrivialSymEnc;
        let hybrid = Hybrid { pub_enc, sym_enc };
        let adv = TrivialDistinguisher;

        assert_eq!(
            adv.play(G1::init(hybrid)),
            adv.play(FromHybridToPubEnc::init(
                PubCpa::init(pub_enc, false),
                sym_enc,
                false,
            )),
        );
    }

    #[test]
    fn equiv_game_2_red() {
        let pub_enc = test_utils::TrivialPubEnc;
        let sym_enc = test_utils::TrivialSymEnc;
        let hybrid = Hybrid { pub_enc, sym_enc };
        let adv = TrivialDistinguisher;

        assert_eq!(
            adv.play(G2::init(hybrid)),
            adv.play(FromHybridToPubEnc::init(
                PubCpa::init(pub_enc, true),
                sym_enc,
                false,
            )),
        );
    }
}
