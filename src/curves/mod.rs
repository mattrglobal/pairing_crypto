use crate::BigArray;
use ff::Field;
use hkdf::Hkdf;
use pairings::{
    bls12_381::{Bls12, Fq12, Fr, G1Prepared, G2Prepared, G1, G2},
    hash_to_curve::HashToCurve,
    hash_to_field::{BaseFromRO, ExpandMsgXmd},
    serdes::SerDes,
    CurveAffine, CurveProjective, Engine,
};
use rand::prelude::*;
use sha2::{
    digest::generic_array::{typenum::U48, GenericArray},
    Sha256,
};
use std::convert::TryFrom;
use zeroize::Zeroize;

#[macro_use]
mod macros;

const SIGN_SUITE_G1: &'static [u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
const SIGN_SUITE_G2: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const POP_SUITE_G1: &'static [u8] = b"BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
const POP_SUITE_G2: &'static [u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// A keypair
#[derive(Clone, Debug, Eq, PartialEq, Zeroize)]
pub struct SecretKey(pub(crate) Fr);

/// A public key in G1
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PublicKey(pub(crate) G1);

/// A public key in G1 composed of many public keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MultiPublicKey(pub(crate) G1);

/// A public key in G2
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PublicKeyVt(pub(crate) G2);

/// A public key in G2 composed of many public keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MultiPublicKeyVt(pub(crate) G2);

/// A signature in G2
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Signature(pub(crate) G2);

/// A signature in G2 composed of many signatures
/// where the same message was signed by unique secret keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MultiSignature(pub(crate) G2);

/// A proof of possession in G2
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct KeyProof(pub(crate) G2);

/// A signature in G1
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SignatureVt(pub(crate) G1);

/// A proof of possession in G1
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct KeyProofVt(pub(crate) G1);

/// A signature in G1 composed of many signatures
/// where the same message was signed by unique secret keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MultiSignatureVt(pub(crate) G1);

impl SecretKey {
    const KEY_SALT: &'static [u8] = b"BLS-SIG-KEYGEN-SALT-";

    /// Create a new key pair
    pub fn new() -> Self {
        let mut seed = [0u8; 33];
        thread_rng().fill_bytes(&mut seed.as_mut());
        seed[32] = 0u8;
        let mut m = GenericArray::<u8, U48>::default();
        let _ = Hkdf::<Sha256>::new(Some(Self::KEY_SALT), &seed).expand(&[0, 48], &mut m);
        Self(Fr::from_okm(&m))
    }

    pub fn with_ikm(ikm: &[u8]) -> Self {
        let mut s = ikm.to_vec();
        s.push(0u8);
        let mut m = GenericArray::<u8, U48>::default();
        let _ = Hkdf::<Sha256>::new(Some(Self::KEY_SALT), &s).expand(&[0, 48], &mut m);
        Self(Fr::from_okm(&m))
    }

    to_bytes!(32);

    /// Return the public key in G1
    pub fn public_key(&self) -> PublicKey {
        let mut pk = G1::one();
        pk.mul_assign(self.0);
        PublicKey(pk)
    }

    /// Return the public key in G2
    pub fn public_key_vt(&self) -> PublicKeyVt {
        let mut pk = G2::one();
        pk.mul_assign(self.0);
        PublicKeyVt(pk)
    }

    /// Return a proof of possession in G2
    pub fn key_proof(&self) -> KeyProof {
        let mut p = hash_g2(&self.public_key().to_bytes(), POP_SUITE_G2);
        p.mul_assign(self.0);
        KeyProof(p)
    }

    /// Return a proof of possession in G1
    pub fn key_proof_vt(&self) -> KeyProofVt {
        let mut p = hash_g1(&self.public_key_vt().to_bytes(), POP_SUITE_G1);
        p.mul_assign(self.0);
        KeyProofVt(p)
    }

    /// Return a signature in G2
    pub fn sign<M: AsRef<[u8]>>(&self, msg: M) -> Signature {
        let mut p =
            <G2 as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msg.as_ref(), SIGN_SUITE_G2);
        p.mul_assign(self.0);
        Signature(p)
    }

    /// Return a signature in G1
    pub fn sign_vt<M: AsRef<[u8]>>(&self, msg: M) -> SignatureVt {
        let mut p =
            <G1 as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msg.as_ref(), SIGN_SUITE_G1);
        p.mul_assign(self.0);
        SignatureVt(p)
    }
}

from_impl!(SecretKey, Fr, 32);
serial!(SecretKey, Fr, 32);

impl Signature {
    to_bytes!(96);

    pub fn verify<M: AsRef<[u8]>>(&self, msg: M, pk: PublicKey) -> bool {
        verify(pk.0, self.0, msg, SIGN_SUITE_G2)
    }
}

default_impl!(Signature, G2);
sum_impl!(Signature);
from_impl!(Signature, G2, 96);
serial!(Signature, G2, 96);

impl MultiSignature {
    to_bytes!(96);

    pub fn verify<M: AsRef<[u8]>>(&self, msg: M, pk: MultiPublicKey) -> bool {
        verify(pk.0, self.0, msg, SIGN_SUITE_G2)
    }
}

impl From<&[Signature]> for MultiSignature {
    fn from(sigs: &[Signature]) -> Self {
        let sig: Signature = sigs.iter().sum();
        Self(sig.0)
    }
}

sum_impl!(MultiSignature);
default_impl!(MultiSignature, G2);
from_impl!(MultiSignature, G2, 96);
serial!(MultiSignature, G2, 96);

impl KeyProof {
    to_bytes!(96);

    pub fn verify<M: AsRef<[u8]>>(&self, pk: PublicKey) -> bool {
        verify(pk.0, self.0, &self.to_bytes(), POP_SUITE_G2)
    }
}

default_impl!(KeyProof, G2);
from_impl!(KeyProof, G2, 96);
serial!(KeyProof, G2, 96);

impl PublicKeyVt {
    to_bytes!(96);
}

default_impl!(PublicKeyVt, G2);
sum_impl!(PublicKeyVt);
from_impl!(PublicKeyVt, G2, 96);
from_secret!(PublicKeyVt);
serial!(PublicKeyVt, G2, 96);

impl MultiPublicKeyVt {
    to_bytes!(96);
}

impl From<&[PublicKeyVt]> for MultiPublicKeyVt {
    fn from(keys: &[PublicKeyVt]) -> Self {
        let key: PublicKeyVt = keys.iter().sum();
        Self(key.0)
    }
}

default_impl!(MultiPublicKeyVt, G2);
sum_impl!(MultiPublicKeyVt);
from_impl!(MultiPublicKeyVt, G2, 96);
serial!(MultiPublicKeyVt, G2, 96);

impl PublicKey {
    to_bytes!(48);
}

default_impl!(PublicKey, G1);
sum_impl!(PublicKey);
from_impl!(PublicKey, G1, 48);
from_secret!(PublicKey);
serial!(PublicKey, G1, 48);

impl MultiPublicKey {
    to_bytes!(48);
}

default_impl!(MultiPublicKey, G1);
sum_impl!(MultiPublicKey);
from_impl!(MultiPublicKey, G1, 48);
serial!(MultiPublicKey, G1, 48);

impl SignatureVt {
    to_bytes!(48);

    pub fn verify<M: AsRef<[u8]>>(&self, msg: M, pk: PublicKeyVt) -> bool {
        verify_vt(pk.0, self.0, msg, SIGN_SUITE_G1)
    }
}

default_impl!(SignatureVt, G1);
sum_impl!(SignatureVt);
from_impl!(SignatureVt, G1, 48);
serial!(SignatureVt, G1, 48);

impl MultiSignatureVt {
    to_bytes!(48);

    pub fn verify<M: AsRef<[u8]>>(&self, msg: M, pk: MultiPublicKeyVt) -> bool {
        verify_vt(pk.0, self.0, msg, SIGN_SUITE_G1)
    }
}

default_impl!(MultiSignatureVt, G1);
sum_impl!(MultiSignatureVt);
from_impl!(MultiSignatureVt, G1, 48);
serial!(MultiSignatureVt, G1, 48);

impl From<&[SignatureVt]> for MultiSignatureVt {
    fn from(sigs: &[SignatureVt]) -> Self {
        let sig: SignatureVt = sigs.iter().sum();
        Self(sig.0)
    }
}

impl KeyProofVt {
    to_bytes!(48);

    pub fn verify<M: AsRef<[u8]>>(&self, pk: PublicKeyVt) -> bool {
        verify_vt(pk.0, self.0, &self.to_bytes(), POP_SUITE_G1)
    }
}

default_impl!(KeyProofVt, G1);
from_impl!(KeyProofVt, G1, 48);
serial!(KeyProofVt, G1, 48);

fn verify<M: AsRef<[u8]>>(pk: G1, sig: G2, msg: M, dst: &[u8]) -> bool {
    let p = hash_g2(msg.as_ref(), dst);
    let g = neg_g1();
    pair_g1_g2(
        &pk.into_affine().prepare(),
        &p.into_affine().prepare(),
        &g.into_affine().prepare(),
        &sig.into_affine().prepare(),
    )
}

fn verify_vt<M: AsRef<[u8]>>(pk: G2, sig: G1, msg: M, dst: &[u8]) -> bool {
    let p = hash_g1(msg.as_ref(), dst);
    let g = neg_g2();
    pair_g2_g1(
        &pk.into_affine().prepare(),
        &p.into_affine().prepare(),
        &g.into_affine().prepare(),
        &sig.into_affine().prepare(),
    )
}

fn hash_g1<M: AsRef<[u8]>>(msg: M, dst: &[u8]) -> G1 {
    <G1 as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msg.as_ref(), dst)
}

fn hash_g2<M: AsRef<[u8]>>(msg: M, dst: &[u8]) -> G2 {
    <G2 as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msg.as_ref(), dst)
}

fn neg_g2() -> G2 {
    let mut g = G2::one();
    g.negate();
    g
}

fn neg_g1() -> G1 {
    let mut g = G1::one();
    g.negate();
    g
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
