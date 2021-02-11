use crate::schemes::bls::*;
use pairing_plus::CurveProjective;
use std::marker::PhantomData;

/// A keypair
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KeyPair<Pk: BlsSigBasic<PKType = Pk>, Sg: CurveProjective> {
    pub(crate) secret_key: Pk::Scalar,
    pub(crate) public_key: Pk,
    pub(crate) _signature: PhantomData<Sg>
}

impl<Pk: CurveProjective, Sg: BlsSigBasic<PKType = Pk>> KeyPair<Pk, Sg> {
    /// Restore a key pair from just the secret key
    pub fn from_secret_key(secret_key: Pk::Scalar) -> Self {
        let mut public_key = Pk::one();
        public_key.mul_assign(secret_key);
        Self {
            secret_key,
            public_key,
            _signature: PhantomData
        }
    }

    /// Return the secret key
    pub fn secret_key(&self) -> Pk::Scalar {
        self.secret_key
    }

    /// Return the public key
    pub fn public_key(&self) -> Pk {
        self.public_key
    }

    pub fn sign(&self, msg: &[u8]) -> Sg {
        Sg::sign(self, msg)
    }

    pub fn verify(&self, signature: Sg, msg: &[u8]) -> bool {
        Sg::verify(self, signature, msg)
    }
}

pub(crate) type ScalarT<PtT> = <PtT as CurveProjective>::Scalar;

/// Curve key generation methods
pub trait KeyGen: CurveProjective {
    /// The public key type
    type PKType: CurveProjective<Engine = <Self as CurveProjective>::Engine, Scalar = ScalarT<Self>>;

    /// Generate a keypair
    fn generate_key_pair(seed: Option<&[u8]>) -> Result<KeyPair<Self::PKType, Self>, String>;
}

/// Operations for the BLS12-381 curve
pub mod bls12_381;
