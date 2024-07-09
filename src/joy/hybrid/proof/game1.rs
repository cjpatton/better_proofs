use rand::{
    distributions::{Distribution, Standard},
    prelude::*,
};

use crate::joy::hybrid::{GetPublicKey, Hybrid, LeftOrRight, PubEnc, SymEnc};

/// Game 1: Unroll encryption and key generation and generate another temporary key.
///
/// We call the existing key the "left temporary key" and the new one the "right temporary key".
///
/// CLAIM: For all [distinguishers](crate::Distinguisher) `adv`,
///
/// ```text
/// Pr[adv.play(PubCpa::init(hybrid, false))] = Pr[adv.play(G1::init(hybrid))]
/// ```
pub struct G1<P: PubEnc, S> {
    enc: Hybrid<P, S>,
    pk: P::PublicKey,
}
impl<P: PubEnc, S> G1<P, S> {
    pub fn init(enc: Hybrid<P, S>) -> Self {
        let (pk, _sk) = enc.pub_enc.key_gen();
        Self { enc, pk }
    }
}
impl<P: PubEnc, S> GetPublicKey for G1<P, S> {
    type PublicKey = P::PublicKey;
    fn get_pk(&self) -> &P::PublicKey {
        &self.pk
    }
}
impl<P, S> LeftOrRight for G1<P, S>
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
        let _tk_right = rng.gen(); // new temporary key (unused)
        let c_pub = self.enc.pub_enc.encrypt(&self.pk, &tk_left);
        let c_sym = self.enc.sym_enc.encrypt(&tk_left, m_left);
        (c_pub, c_sym)
    }
}

#[cfg(test)]
mod test_0_1 {
    use crate::{
        joy::hybrid::{test_utils, PubCpa},
        test_utils::TrivialDistinguisher,
        Distinguisher,
    };

    use super::*;

    #[test]
    fn equiv_game_left_1() {
        let pub_enc = test_utils::TrivialPubEnc;
        let sym_enc = test_utils::TrivialSymEnc;
        let hybrid = Hybrid { pub_enc, sym_enc };
        let adv = TrivialDistinguisher;

        assert_eq!(
            adv.play(PubCpa::init(hybrid, false)),
            adv.play(G1::init(hybrid))
        );
    }
}
