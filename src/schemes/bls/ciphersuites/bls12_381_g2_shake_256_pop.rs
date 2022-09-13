use crate::{
    bls::core::key_pair::{PublicKey, SecretKey},
    common::{ciphersuite::CipherSuiteId, h2c::HashToCurveParameter},
    curves::bls12_381::{
        hash_to_curve::ExpandMsgXof,
        G1Projective,
        G2Projective,
    },
    Error,
};
use sha3::Shake256;

use super::{
    bls12_381::BLS_SIG_BLS12381G2_SIGNATURE_LENGTH,
    BlsCiphersuiteParameters,
};
#[derive(Debug, Clone)]
pub(crate) struct Bls12381G2XofShake256PopCipherSuiteParameter;

impl BlsCiphersuiteParameters for Bls12381G2XofShake256PopCipherSuiteParameter {}

impl HashToCurveParameter for Bls12381G2XofShake256PopCipherSuiteParameter {
    const ID: CipherSuiteId = CipherSuiteId::BlsSigBls12381G2XofShake256Pop;

    fn hash_to_g1(
        message: &[u8],
        dst: &[u8],
    ) -> Result<blstrs::G1Projective, Error> {
        Ok(G1Projective::hash_to::<ExpandMsgXof<Shake256>>(
            message, dst,
        ))
    }

    fn hash_to_g2(
        message: &[u8],
        dst: &[u8],
    ) -> Result<blstrs::G2Projective, Error> {
        Ok(G2Projective::hash_to::<ExpandMsgXof<Shake256>>(
            message, dst,
        ))
    }
}

/// Sign a message.
pub fn sign<T>(
    sk: &SecretKey,
    message: T,
) -> Result<[u8; BLS_SIG_BLS12381G2_SIGNATURE_LENGTH], Error>
where
    T: AsRef<[u8]>,
{
    let signature = crate::schemes::bls::core::signature::Signature::new::<
        _,
        Bls12381G2XofShake256PopCipherSuiteParameter,
    >(sk, message.as_ref(), Bls12381G2XofShake256PopCipherSuiteParameter::default_hash_to_point_g2_dst().as_ref())?;
    Ok(signature.to_octets())
}

/// Verify a `Signature`.
pub fn verify<T>(
    pk: &PublicKey,
    message: T,
    signature: &[u8; BLS_SIG_BLS12381G2_SIGNATURE_LENGTH],
) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
{
    let signature =
        crate::schemes::bls::core::signature::Signature::from_octets(
            signature,
        )?;
    signature
        .verify::<_, Bls12381G2XofShake256PopCipherSuiteParameter>(pk, message.as_ref(), Bls12381G2XofShake256PopCipherSuiteParameter::default_hash_to_point_g2_dst().as_ref())
}

/// Compute proof of posession of a secret key.
pub fn pop_prove(
    sk: &SecretKey,
) -> Result<[u8; BLS_SIG_BLS12381G2_SIGNATURE_LENGTH], Error> {
    let pk: PublicKey = sk.into();

    let pop = crate::schemes::bls::core::signature::Signature::new::<
        _,
        Bls12381G2XofShake256PopCipherSuiteParameter,
    >(
        sk,
        pk.to_octets().as_ref(),
        pop_dst::<Bls12381G2XofShake256PopCipherSuiteParameter>().as_ref(),
    )?;
    Ok(pop.to_octets())
}

/// Verify proof of posession of a secret key.
pub fn pop_verify(
    pk: &PublicKey,
    proof: &[u8; BLS_SIG_BLS12381G2_SIGNATURE_LENGTH],
) -> Result<bool, Error> {
    let proof =
        crate::schemes::bls::core::signature::Signature::from_octets(proof)?;
    proof.verify::<_, Bls12381G2XofShake256PopCipherSuiteParameter>(
        pk,
        pk.to_octets().as_ref(),
        pop_dst::<Bls12381G2XofShake256PopCipherSuiteParameter>().as_ref(),
    )
}

fn pop_dst<C>() -> Vec<u8>
where
    C: BlsCiphersuiteParameters,
{
    [b"BLS_POP_", C::ID.as_octets()].concat()
}
