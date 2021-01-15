use crate::curves::{
    KeyPair, ScalarT,
};
use pairing_plus::{
    CurveProjective,
    hash_to_curve::HashToCurve,
    bls12_381::{G1, G2},
};
use sha2::Sha256;

pub trait BlsSigCore: CurveProjective {
    type PKType: CurveProjective<Engine = <Self as CurveProjective>::Engine, Scalar = ScalarT<Self>>;

    /// Sign a message
    fn core_sign(kp: &KeyPair<Self::PKType>, msg: &[u8], ciphersuite: &[u8]) -> Self;
}

pub trait BlsSigBasic: BlsSigCore {
    const CSUITE: &'static [u8];

    fn sign(kp: &KeyPair<Self::PKType>, msg: &[u8]) -> Self {
        <Self as BlsSigCore>::core_sign(kp, msg, Self::CSUITE)
    }
}

impl BlsSigCore for G2 {
    type PKType = G1;

    fn core_sign(kp: &KeyPair<<Self as BlsSigCore>::PKType>, msg: &[u8], ciphersuite: &[u8]) -> Self {
        let mut p = <G2 as HashToCurve<Sha256>>::hash_to_curve(msg, ciphersuite);
        p.mul_assign(kp.secret_key);
        p
    }
}

impl BlsSigBasic for G2 {
   const CSUITE: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
}