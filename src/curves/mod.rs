use pairing_plus::CurveProjective;

/// A keypair
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyPair<P: CurveProjective> {
    pub(crate) secret_key: P::Scalar,
    pub(crate) public_key: P,
}

impl<P: CurveProjective> KeyPair<P> {
    /// Restore a key pair from just the secret key
    pub fn from_secret_key(secret_key: P::Scalar) -> Self {
        let mut public_key = P::one();
        public_key.mul_assign(secret_key);
        Self {
            secret_key,
            public_key,
        }
    }

    /// Return the secret key
    pub fn secret_key(&self) -> P::Scalar {
        self.secret_key
    }

    /// Return the public key
    pub fn public_key(&self) -> P {
        self.public_key
    }
}

pub(crate) type ScalarT<PtT> = <PtT as CurveProjective>::Scalar;

/// Curve key generation methods
pub trait KeyGen: CurveProjective {
    /// The public key type
    type PKType: CurveProjective<Engine = <Self as CurveProjective>::Engine, Scalar = ScalarT<Self>>;

    /// Generate a keypair
    fn keygen(seed: Option<&[u8]>) -> KeyPair<Self::PKType>;
}

/// Operations for the BLS12-381 curve
pub mod bls12_381;
