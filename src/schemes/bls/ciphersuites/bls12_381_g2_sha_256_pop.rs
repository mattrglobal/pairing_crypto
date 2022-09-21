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
pub(crate) struct Bls12381G2XmdSha256PopCipherSuiteParameter;

impl CipherSuiteParameter for Bls12381G2XmdSha256PopCipherSuiteParameter {
    const ID: CipherSuiteId = CipherSuiteId::BlsSigBls12381G2XmdSha256Pop;
}

impl ExpandMessageParameter for Bls12381G2XmdSha256PopCipherSuiteParameter {
    type Expander = ExpandMsgXmd<Sha256>;
}

impl HashToCurveParameter for Bls12381G2XmdSha256PopCipherSuiteParameter {}

impl BlsCiphersuiteParameters for Bls12381G2XmdSha256PopCipherSuiteParameter {}

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
        Bls12381G2XmdSha256PopCipherSuiteParameter,
    >(
        sk,
        message.as_ref(),
        Bls12381G2XmdSha256PopCipherSuiteParameter::default_hash_to_point_dst()
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
    signature.verify::<_, Bls12381G2XmdSha256PopCipherSuiteParameter>(
        pk,
        message.as_ref(),
        Bls12381G2XmdSha256PopCipherSuiteParameter::default_hash_to_point_dst()
            .as_ref(),
    )
}

/// Compute proof of posession of a secret key.
pub fn pop_prove(
    sk: &SecretKey,
) -> Result<[u8; BLS_SIG_BLS12381G2_SIGNATURE_LENGTH], Error> {
    let pk: PublicKey = sk.into();

    let pop = crate::schemes::bls::core::signature::Signature::new::<
        _,
        Bls12381G2XmdSha256PopCipherSuiteParameter,
    >(
        sk,
        pk.to_octets().as_ref(),
        pop_dst::<Bls12381G2XmdSha256PopCipherSuiteParameter>().as_ref(),
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
    proof.verify::<_, Bls12381G2XmdSha256PopCipherSuiteParameter>(
        pk,
        pk.to_octets().as_ref(),
        pop_dst::<Bls12381G2XmdSha256PopCipherSuiteParameter>().as_ref(),
    )
}

fn pop_dst<C>() -> Vec<u8>
where
    C: BlsCiphersuiteParameters,
{
    [b"BLS_POP_", C::ID.as_octets()].concat()
}
