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
    BlsSigAugCiphersuiteParameters,
};

#[derive(Debug, Clone)]
pub(crate) struct Bls12381G2XmdSha256AugCipherSuiteParameter;

impl CipherSuiteParameter for Bls12381G2XmdSha256AugCipherSuiteParameter {
    const ID: CipherSuiteId = CipherSuiteId::BlsSigBls12381G2XmdSha256Aug;
}

impl BlsSigAugCiphersuiteParameters
    for Bls12381G2XmdSha256AugCipherSuiteParameter
{
}

impl ExpandMessageParameter for Bls12381G2XmdSha256AugCipherSuiteParameter {
    type Expander = ExpandMsgXmd<Sha256>;
}

impl HashToCurveParameter for Bls12381G2XmdSha256AugCipherSuiteParameter {}

impl BlsCiphersuiteParameters for Bls12381G2XmdSha256AugCipherSuiteParameter {}

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
        Bls12381G2XmdSha256AugCipherSuiteParameter,
    >(
        sk,
        data_to_sign,
        Bls12381G2XmdSha256AugCipherSuiteParameter::default_hash_to_point_dst(),
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
    let data_to_sign = [pk.to_octets().as_ref(), message.as_ref()].concat();
    let signature =
        crate::schemes::bls::core::signature::Signature::from_octets(
            signature,
        )?;
    signature.verify::<_, Bls12381G2XmdSha256AugCipherSuiteParameter>(
        pk,
        data_to_sign,
        Bls12381G2XmdSha256AugCipherSuiteParameter::default_hash_to_point_dst(),
    )
}
