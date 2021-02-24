use ff::Field;
use hkdf::Hkdf;
use pairings::{
    bls12_381::{Bls12, ClearH, Fq12, Fr, G1Prepared, G2Prepared, G1, G2},
    hash_to_curve::HashToCurve,
    hash_to_field::ExpandMsgXmd,
    CurveAffine, CurveProjective, Engine,
};
use rand::prelude::*;
use sha2::{
    digest::generic_array::{typenum::U48, GenericArray},
    Sha256,
};
use std::marker::PhantomData;

/// A keypair
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyPair<Sg: CurveProjective, Pk: CurveProjective> {
    pub(crate) secret_key: Pk::Scalar,
    pub(crate) _public_key: PhantomData<Pk>,
    pub(crate) _signature: PhantomData<Sg>,
}

impl<Sg: CurveProjective, Pk: CurveProjective> KeyPair<Sg, Pk> {
    const KEY_SALT: &'static [u8] = b"BLS-SIG-KEYGEN-SALT-";

    pub fn new() -> Self {
        let mut seed = [0u8; 33];
        thread_rng().fill_bytes(&mut seed.as_mut());
        seed[32] = 0u8;
        let mut m = GenericArray::<u8, U48>::default();
        let _ = Hkdf::<Sha256>::new(Some(Self::KEY_SALT), &seed).expand(&[0, 48], &mut m);
        Ok(Fr::from_okm(&m))
    }

    pub fn with_ikm(ikm: &[u8]) -> Self {
        let mut s = ikm.to_vec();
        s.push(0u8);
        let mut m = GenericArray::<u8, U48>::default();
        let _ = Hkdf::<Sha256>::new(Some(Self::KEY_SALT), &s).expand(&[0, 48], &mut m);
        Ok(Fr::from_okm(&m))
    }

    /// Restore a key pair from just the secret key
    pub fn from_secret_key(secret_key: Pk::Scalar) -> Self {
        Self {
            secret_key,
            _public_key: PhantomData,
            _signature: PhantomData,
        }
    }

    /// Return the secret key
    pub fn secret_key(&self) -> Pk::Scalar {
        self.secret_key
    }

    /// Return the public key
    pub fn public_key(&self) -> Pk {
        let mut pk = Pk::one();
        pk.mul_assign(self.secret_key);
        pk
    }

    pub fn sign(&self, msg: &[u8]) -> Sg {}

    pub fn verify(&self, signature: Sg, msg: &[u8]) -> bool {}

    fn core_sign(&self, msg: &[u8], dst: &[u8]) -> Sg {
        let mut p = <Sg as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msg, dst);
        p.mul_assign(self.secret_key);
        p
    }

    fn core_verify(&self, sig: &Sg, msg: &[u8], dst: &[u8]) -> bool {
        let p = <Sg as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msg, dst);
        let g = {
            let mut t = Pk::one();
            t.negate();
            t
        };
        let pk = self.public_key();
        <Self as Pair<T1 = Pk, T2 = Sg>>::pair(&pk, &p, &g, &sig)
    }
}

impl Pair for KeyPair<G1, G2> {
    type T1 = G1;
    type T2 = G2;

    fn pair(p1: &Self::T1, g1: &Self::T2, p2: &Self::T1, g2: &Self::T2) -> bool {
        pair_g1_g2(
            &p1.into_affine().prepare(),
            &g1.into_affine().prepare(),
            &p2.into_affine().prepare(),
            &g2.into_affine().prepare(),
        )
    }
}

impl Pair for KeyPair<G2, G1> {
    type T1 = G2;
    type T2 = G1;

    fn pair(p1: &Self::T2, g1: &Self::T1, p2: &Self::T2, g2: &Self::T1) -> bool {
        pair_g2_g1(
            &g1.into_affine().prepare(),
            &p1.into_affine().prepare(),
            &g2.into_affine().prepare(),
            &p2.into_affine().prepare(),
        )
    }
}

impl Scheme for KeyPair<G1, G2> {
    type T1 = G1;
    type T2 = G2;
    const CSUITE: &'static [u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
}

impl Scheme for KeyPair<G2, G1> {
    type T1 = G2;
    type T2 = G1;
    const CSUITE: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
}

pub(crate) type ScalarT<PtT> = <PtT as CurveProjective>::Scalar;

/// Curve key generation methods
pub trait KeyGen: CurveProjective {
    /// The public key type
    type PKType: CurveProjective<Engine = <Self as CurveProjective>::Engine, Scalar = ScalarT<Self>>;

    /// Generate a keypair
    fn generate_key_pair(seed: Option<&[u8]>) -> Result<KeyPair<Self::PKType, Self>, String>;
}

trait Pair {
    type T1: CurveProjective;
    type T2: CurveProjective;
    fn pair(p1: &Self::T1, g1: &Self::T2, p2: &Self::T1, g2: &Self::T2) -> bool;
}

trait Scheme {
    /// The ciphersuite domain separation tag
    const CSUITE: &'static [u8];
    type T1: CurveProjective;
    type T2: CurveProjective;
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

#[inline]
fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    thread_rng().fill_bytes(&mut seed.as_mut());
    seed
}

// /// Operations for the BLS12-381 curve
//pub mod bls12_381;
