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
pub(crate) struct Bls12381G2XofShake256AugCipherSuiteParameter;

impl BlsCiphersuiteParameters for Bls12381G2XofShake256AugCipherSuiteParameter {}

impl HashToCurveParameter for Bls12381G2XofShake256AugCipherSuiteParameter {
    const ID: CipherSuiteId = CipherSuiteId::BlsSigBls12381G2XofShake256Aug;

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
    let pk: PublicKey = sk.into();
    let data_to_sign = [pk.to_octets().as_ref(), message.as_ref()].concat();
    let signature = crate::schemes::bls::core::signature::Signature::new::<
        _,
        Bls12381G2XofShake256AugCipherSuiteParameter,
    >(sk, data_to_sign, Bls12381G2XofShake256AugCipherSuiteParameter::default_hash_to_point_g2_dst())?;
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
    let data_to_sign = [pk.to_octets().as_ref(), message.as_ref()].concat();
    let signature =
        crate::schemes::bls::core::signature::Signature::from_octets(
            signature,
        )?;
    signature.verify::<_, Bls12381G2XofShake256AugCipherSuiteParameter>(
        pk,
        data_to_sign, Bls12381G2XofShake256AugCipherSuiteParameter::default_hash_to_point_g2_dst()
    )
}
