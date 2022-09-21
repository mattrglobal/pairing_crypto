use crate::{
    bls::core::key_pair::{PublicKey, SecretKey},
    common::{
        ciphersuite::{CipherSuiteId, CipherSuiteParameter},
        h2c::HashToCurveParameter,
    },
    curves::bls12_381::{
        hash_to_curve::ExpandMsgXmd,
        G1Projective,
        G2Projective,
    },
    Error,
};
use sha2::Sha256;

use super::{
    bls12_381::BLS_SIG_BLS12381G2_SIGNATURE_LENGTH,
    BlsCiphersuiteParameters,
};

#[derive(Debug, Clone)]
pub(crate) struct Bls12381G2XmdSha256NulCipherSuiteParameter;

impl CipherSuiteParameter for Bls12381G2XmdSha256NulCipherSuiteParameter {
    const ID: CipherSuiteId = CipherSuiteId::BlsSigBls12381G2XmdSha256Nul;
}

impl BlsCiphersuiteParameters for Bls12381G2XmdSha256NulCipherSuiteParameter {}

impl HashToCurveParameter for Bls12381G2XmdSha256NulCipherSuiteParameter {
    fn hash_to_g1(
        message: &[u8],
        dst: &[u8],
    ) -> Result<blstrs::G1Projective, Error> {
        Ok(G1Projective::hash_to::<ExpandMsgXmd<Sha256>>(message, dst))
    }

    fn hash_to_g2(
        message: &[u8],
        dst: &[u8],
    ) -> Result<blstrs::G2Projective, Error> {
        Ok(G2Projective::hash_to::<ExpandMsgXmd<Sha256>>(message, dst))
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
        Bls12381G2XmdSha256NulCipherSuiteParameter,
    >(
        sk,
        message.as_ref(),
        Bls12381G2XmdSha256NulCipherSuiteParameter::default_hash_to_point_dst()
            .as_ref(),
    )?;
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
    signature.verify::<_, Bls12381G2XmdSha256NulCipherSuiteParameter>(
        pk,
        message.as_ref(),
        Bls12381G2XmdSha256NulCipherSuiteParameter::default_hash_to_point_dst()
            .as_ref(),
    )
}
