//! CPA-security proof for the hybrid public-key encryption scheme of Chapter 16.

use rand::{distributions::Standard, prelude::*};

// Oracles

/// Left-or-right encryption oracle.
pub trait LeftOrRight {
    type Plaintext;
    type Ciphertext;
    fn left_or_right(
        &self,
        m_left: &Self::Plaintext,
        m_right: &Self::Plaintext,
    ) -> Self::Ciphertext;
}

/// Oracle for obtaining the public key in a public-key cryptosystem.
pub trait GetPublicKey {
    type PublicKey;
    fn get_pk(&self) -> &Self::PublicKey;
}

// Chapter 7: Security against Chosen Plaintext Attacks
//
// Syntax

/// Symmetric encryption.
pub trait SymEnc {
    type Key;
    type Plaintext;
    type Ciphertext;
    fn key_gen(&self) -> Self::Key;
    fn encrypt(&self, k: &Self::Key, m: &Self::Plaintext) -> Self::Ciphertext;
    fn decrypt(&self, k: &Self::Key, c: &Self::Ciphertext) -> Option<Self::Plaintext>;
}

// Security

/// Definition 7.1: CPA security of symmetric encryption.
pub struct Cpa<E: SymEnc> {
    enc: E,
    k: E::Key,
    right: bool,
}

impl<E: SymEnc> Cpa<E> {
    /// Initialize the game. If `right` is `true`, then the [`LeftOrRight`] oracle encrypts the
    /// right plaintext.
    pub fn init(enc: E, right: bool) -> Self {
        let k = enc.key_gen();
        Self { enc, k, right }
    }
}

impl<E: SymEnc> LeftOrRight for Cpa<E> {
    type Plaintext = E::Plaintext;
    type Ciphertext = E::Ciphertext;
    fn left_or_right(&self, m_left: &E::Plaintext, m_right: &E::Plaintext) -> E::Ciphertext {
        // NOTE This definition implicitly requires length hiding.
        if self.right {
            self.enc.encrypt(&self.k, m_right)
        } else {
            self.enc.encrypt(&self.k, m_left)
        }
    }
}

// Chapter 15: Public-Key Encryption
//
// Syntax

/// Public-key encryption.
pub trait PubEnc {
    type PublicKey;
    type SecretKey;
    type Plaintext;
    type Ciphertext;
    fn key_gen(&self) -> (Self::PublicKey, Self::SecretKey);
    fn encrypt(&self, pk: &Self::PublicKey, m: &Self::Plaintext) -> Self::Ciphertext;
    fn decrypt(&self, sk: &Self::SecretKey, c: &Self::Ciphertext) -> Option<Self::Plaintext>;
}

// Security

/// Definition 15.1: CPA security for public key encryption.
pub struct PubCpa<E: PubEnc> {
    enc: E,
    pk: E::PublicKey,
    right: bool,
}

impl<E: PubEnc> PubCpa<E> {
    /// Initialize the game. If `right` is `true`, then the [`LeftOrRight`] oracle encrypts the
    /// right plaintext.
    pub fn init(enc: E, right: bool) -> Self {
        let (pk, _sk) = enc.key_gen();
        Self { enc, pk, right }
    }
}

impl<E: PubEnc> GetPublicKey for PubCpa<E> {
    type PublicKey = E::PublicKey;
    fn get_pk(&self) -> &E::PublicKey {
        &self.pk
    }
}

impl<E: PubEnc> LeftOrRight for PubCpa<E> {
    type Plaintext = E::Plaintext;
    type Ciphertext = E::Ciphertext;
    fn left_or_right(&self, m_left: &E::Plaintext, m_right: &E::Plaintext) -> E::Ciphertext {
        // NOTE This definition implicitly requires length hiding.
        if self.right {
            self.enc.encrypt(&self.pk, m_right)
        } else {
            self.enc.encrypt(&self.pk, m_left)
        }
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    //! Tools for driving tests.

    use super::*;

    /// Trivially secure, but not useful.
    #[derive(Clone, Copy)]
    pub struct TrivialSymEnc;
    impl SymEnc for TrivialSymEnc {
        type Key = ();
        type Plaintext = ();
        type Ciphertext = ();
        fn key_gen(&self) -> () {
            ()
        }
        fn encrypt(&self, _k: &(), _m: &()) -> () {
            ()
        }
        fn decrypt(&self, _k: &(), _c: &()) -> Option<()> {
            Some(())
        }
    }

    /// Trivially secure, but not useful.
    #[derive(Clone, Copy)]
    pub struct TrivialPubEnc;
    impl PubEnc for TrivialPubEnc {
        type PublicKey = ();
        type SecretKey = ();
        type Plaintext = ();
        type Ciphertext = ();
        fn key_gen(&self) -> ((), ()) {
            ((), ())
        }
        fn encrypt(&self, _pk: &(), _m: &()) -> () {
            ()
        }
        fn decrypt(&self, _sk: &(), _c: &()) -> Option<()> {
            Some(())
        }
    }
}

// Construction

/// Construction 15.8.
#[derive(Clone, Copy)]
pub struct Hybrid<P, S> {
    pub_enc: P,
    sym_enc: S,
}

impl<P, S> PubEnc for Hybrid<P, S>
where
    S: SymEnc,
    P: PubEnc<Plaintext = S::Key>,
    Standard: Distribution<S::Key>,
{
    type PublicKey = P::PublicKey;
    type SecretKey = P::SecretKey;
    type Plaintext = S::Plaintext;
    type Ciphertext = (P::Ciphertext, S::Ciphertext);

    fn key_gen(&self) -> (P::PublicKey, P::SecretKey) {
        self.pub_enc.key_gen()
    }

    fn encrypt(&self, pk: &P::PublicKey, m: &S::Plaintext) -> (P::Ciphertext, S::Ciphertext) {
        let tk = thread_rng().gen(); // "temporary key"
        let c_pub = self.pub_enc.encrypt(pk, &tk);
        let c_sym = self.sym_enc.encrypt(&tk, m);
        (c_pub, c_sym)
    }

    fn decrypt(
        &self,
        sk: &Self::SecretKey,
        (c_pub, c_sym): &(P::Ciphertext, S::Ciphertext),
    ) -> Option<Self::Plaintext> {
        let tk = self.pub_enc.decrypt(sk, c_pub)?;
        let m = self.sym_enc.decrypt(&tk, c_sym)?;
        Some(m)
    }
}

// Proof
//
// Claim 15.9: If [`PubEnc`] and [`SymEnc`] are CPA-secure, then so is [`Hybrid<PubEnc, SymEnc>`].

/// Reduction from a [`Hybrid`] attacker to a [`PubEnc`] attacker.
pub struct FromHybridToPubEnc<P, S>
where
    P: PubEnc,
{
    sym_enc: S,
    game: PubCpa<P>,
    right: bool,
}
impl<P, S> FromHybridToPubEnc<P, S>
where
    P: PubEnc,
{
    pub fn init(game: PubCpa<P>, sym_enc: S, right: bool) -> Self {
        Self {
            game,
            sym_enc,
            right,
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
        // Simulation: If `self.left`, then transition from `G1` to `G2`; otherwise, transition
        // from `G3` to `G4`. If `game.left`, then simulate the former; otherwise simulate the
        // latter.
        let c_pub = self.game.left_or_right(&tk_left, &tk_right);
        let c_sym = if self.right {
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
    game: Cpa<S>,
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
        let mut rng = thread_rng();
        let _tk_left = rng.gen();
        let tk_right = rng.gen();
        let c_pub = self.pub_enc.encrypt(&self.pk, &tk_right);
        // Simulation: if `game.left`, then this simulates `G2`; otherwise, this simulates `G3`.
        let c_sym = self.game.left_or_right(m_left, m_right);
        (c_pub, c_sym)
    }
}

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
    use crate::{test_utils::TrivialDistinguisher, Distinguisher};

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
        let tk_right = rng.gen();
        let c_pub = self.enc.pub_enc.encrypt(&self.pk, &tk_right); // produced with new temporary key
        let c_sym = self.enc.sym_enc.encrypt(&tk_left, m_left);
        (c_pub, c_sym)
    }
}

#[cfg(test)]
mod test_1_2 {
    use crate::{test_utils::TrivialDistinguisher, Distinguisher};

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
    use crate::{test_utils::TrivialDistinguisher, Distinguisher};

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
    use crate::{test_utils::TrivialDistinguisher, Distinguisher};

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
