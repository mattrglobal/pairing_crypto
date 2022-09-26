use crate::{
    bls::core::key_pair::{PublicKey, SecretKey},
    common::{
        ciphersuite::{CipherSuiteId, CipherSuiteParameter},
        hash_param::{h2c::HashToCurveParameter, ExpandMessageParameter},
    },
    curves::bls12_381::hash_to_curve::ExpandMsgXmd,
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

impl ExpandMessageParameter for Bls12381G2XmdSha256NulCipherSuiteParameter {
    type Expander = ExpandMsgXmd<Sha256>;
}

impl HashToCurveParameter for Bls12381G2XmdSha256NulCipherSuiteParameter {}

impl BlsCiphersuiteParameters for Bls12381G2XmdSha256NulCipherSuiteParameter {}

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
