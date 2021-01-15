use crate::curves::{KeyPair, ScalarT};
use ff::Field;
use pairing_plus::bls12_381::{G1Prepared, G2Prepared};
use pairing_plus::{
    bls12_381::{Bls12, Fq12, G1, G2},
    hash_to_curve::HashToCurve,
    hash_to_field::ExpandMsgXmd,
    CurveAffine, CurveProjective, Engine,
};
use sha2::Sha256;

/// Provides the BLS core operations
pub trait BlsSigCore: CurveProjective {
    /// The public key type
    type PKType: CurveProjective<Engine = <Self as CurveProjective>::Engine, Scalar = ScalarT<Self>>;

    /// Sign a message
    fn core_sign(kp: &KeyPair<Self::PKType>, msg: &[u8], ciphersuite: &[u8]) -> Self;

    /// Verify a message
    fn core_verify(pk: Self::PKType, sig: Self, msg: &[u8], ciphersuite: &[u8]) -> bool;
}

/// Provides sign and verify according to the basic signature scheme
pub trait BlsSigBasic: BlsSigCore {
    /// The ciphersuite domain separation tag
    const CSUITE: &'static [u8];

    /// Sign `msg` using with `kp`
    fn sign(kp: &KeyPair<Self::PKType>, msg: &[u8]) -> Self {
        <Self as BlsSigCore>::core_sign(kp, msg, Self::CSUITE)
    }

    /// Verify `sig` is over `msg` using with `pk`
    fn verify(pk: Self::PKType, sig: Self, msg: &[u8]) -> bool {
        <Self as BlsSigCore>::core_verify(pk, sig, msg, Self::CSUITE)
    }
}

#[inline]
fn pair_g2_g1(p1: &G2Prepared, g1: &G1Prepared, p2: &G2Prepared, g2: &G1Prepared) -> bool {
    match Bls12::final_exponentiation(&Bls12::miller_loop(&[(g1, p1), (g2, p2)])) {
        None => false,
        Some(fq) => fq == Fq12::one(),
    }
}

#[inline]
fn pair_g1_g2(p1: &G1Prepared, g1: &G2Prepared, p2: &G1Prepared, g2: &G2Prepared) -> bool {
    match Bls12::final_exponentiation(&Bls12::miller_loop(&[(p1, g1), (p2, g2)])) {
        None => false,
        Some(fq) => fq == Fq12::one(),
    }
}

macro_rules! sig_core_impl {
    ($ty1:ident, $ty2:ident, $pair:ident) => {
        impl BlsSigCore for $ty1 {
            type PKType = $ty2;
            fn core_sign(
                kp: &KeyPair<<Self as BlsSigCore>::PKType>,
                msg: &[u8],
                ciphersuite: &[u8],
            ) -> Self {
                let mut p =
                    <$ty1 as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msg, ciphersuite);
                p.mul_assign(kp.secret_key);
                p
            }

            fn core_verify(
                pk: <Self as BlsSigCore>::PKType,
                sig: Self,
                msg: &[u8],
                ciphersuite: &[u8],
            ) -> bool {
                let p =
                    <Self as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msg, ciphersuite)
                        .into_affine()
                        .prepare();
                let g = {
                    let mut t = <Self as BlsSigCore>::PKType::one();
                    t.negate();
                    t.into_affine().prepare()
                };
                $pair(
                    &pk.into_affine().prepare(),
                    &p,
                    &g,
                    &sig.into_affine().prepare(),
                )
            }
        }
    };
}
macro_rules! sig_basic_impl {
    ($ty:ident, $suite:expr) => {
        impl BlsSigBasic for $ty {
            const CSUITE: &'static [u8] = $suite;
        }
    };
}

sig_core_impl!(G1, G2, pair_g2_g1);
sig_core_impl!(G2, G1, pair_g1_g2);

sig_basic_impl!(G1, b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_");
sig_basic_impl!(G2, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_");
