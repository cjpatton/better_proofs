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
    fn left_or_right(
        &self,
        m_left: &E::Plaintext,
        m_right: &E::Plaintext,
    ) -> E::Ciphertext {
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
    fn decrypt(
        &self,
        sk: &Self::SecretKey,
        c: &Self::Ciphertext,
    ) -> Option<Self::Plaintext>;
}

// Security

/// Definition 15.1: CPA security for public key encryption.
pub struct PubCpa<E: PubEnc> {
    enc: E,
    pk: E::PublicKey,
    right: bool,
}

impl<E: PubEnc> PubCpa<E> {
    /// Initialize the game. If `right` is `true`, then the [`LeftOrRight`] oracle
    /// encrypts the right plaintext.
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
    fn left_or_right(
        &self,
        m_left: &E::Plaintext,
        m_right: &E::Plaintext,
    ) -> E::Ciphertext {
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

    fn encrypt(
        &self,
        pk: &P::PublicKey,
        m: &S::Plaintext,
    ) -> (P::Ciphertext, S::Ciphertext) {
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

pub mod proof;
