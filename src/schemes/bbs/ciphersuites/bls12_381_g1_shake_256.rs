use super::{
    bls12_381::BBS_BLS12381G1_SIGNATURE_LENGTH,
    BbsCiphersuiteParameters,
    CipherSuiteId,
};
use crate::{
    bbs::{
        BbsProofGenRequest,
        BbsProofVerifyRequest,
        BbsSignRequest,
        BbsVerifyRequest,
    },
    common::{
        ciphersuite::CipherSuiteParameter,
        hash_param::{
            h2c::HashToCurveParameter,
            h2s::HashToScalarParameter,
            ExpandMessageParameter,
        },
    },
    curves::bls12_381::hash_to_curve::ExpandMsgXof,
    Error,
};
use sha3::Shake256;

#[cfg(feature = "__private_bbs_fixtures_generator_api")]
use rand::{CryptoRng, RngCore};

#[derive(Debug, Clone)]
pub(crate) struct Bls12381Shake256CipherSuiteParameter;

impl CipherSuiteParameter for Bls12381Shake256CipherSuiteParameter {
    const ID: CipherSuiteId = CipherSuiteId::BbsBls12381G1XofShake256;
}

impl ExpandMessageParameter for Bls12381Shake256CipherSuiteParameter {
    type Expander = ExpandMsgXof<Shake256>;
}

impl HashToScalarParameter for Bls12381Shake256CipherSuiteParameter {}

impl HashToCurveParameter for Bls12381Shake256CipherSuiteParameter {}

impl BbsCiphersuiteParameters for Bls12381Shake256CipherSuiteParameter {}

/// Create a BLS12-381-G1-Shake-256 BBS signature.
/// Security Warning: `secret_key` and `public_key` in `request` must be related
/// key-pair generated using `KeyPair` APIs.
pub fn sign<T>(
    request: &BbsSignRequest<'_, T>,
) -> Result<[u8; BBS_BLS12381G1_SIGNATURE_LENGTH], Error>
where
    T: AsRef<[u8]>,
{
    crate::bbs::api::signature::sign::<_, Bls12381Shake256CipherSuiteParameter>(
        request,
    )
}

/// Verify a BLS12-381-G1-Shake-256 BBS signature.
pub fn verify<T>(request: &BbsVerifyRequest<'_, T>) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
{
    crate::bbs::api::signature::verify::<_, Bls12381Shake256CipherSuiteParameter>(
        request,
    )
}

/// Generate a BLS12-381-G1-Shake-256 BBS signature proof of knowledge.
pub fn proof_gen<T>(
    request: &BbsProofGenRequest<'_, T>,
) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]>,
{
    crate::bbs::api::proof::proof_gen::<_, Bls12381Shake256CipherSuiteParameter>(
        request,
    )
}

/// Verify a BLS12-381-G1-Shake-256 BBS signature proof of knowledge.
pub fn proof_verify<T>(
    request: &BbsProofVerifyRequest<'_, T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
{
    crate::bbs::api::proof::proof_verify::<
        _,
        Bls12381Shake256CipherSuiteParameter,
    >(request)
}

/// Create generators.
#[cfg(feature = "__private_bbs_fixtures_generator_api")]
#[cfg_attr(docsrs, doc(cfg(feature = "__private_bbs_fixtures_generator_api")))]
pub fn create_generators(
    count: usize,
    private_holder_binding: Option<bool>,
) -> Result<Vec<Vec<u8>>, Error> {
    crate::bbs::api::generators::create_generators::<
        Bls12381Shake256CipherSuiteParameter,
    >(count, private_holder_binding)
}

#[cfg(feature = "__private_bbs_fixtures_generator_api")]
use crate::curves::bls12_381::OCTET_SCALAR_LENGTH;

/// Hash to scalar.
#[cfg(feature = "__private_bbs_fixtures_generator_api")]
#[cfg_attr(docsrs, doc(cfg(feature = "__private_bbs_fixtures_generator_api")))]
pub fn hash_to_scalar(
    msg_octets: &[u8],
    dst: Option<&[u8]>,
) -> Result<[u8; OCTET_SCALAR_LENGTH], Error> {
    let scalars =
        Bls12381Shake256CipherSuiteParameter::hash_to_scalar(msg_octets, dst);

    match scalars {
        Ok(scalar) => Ok(scalar.to_bytes_be()),
        Err(e) => Err(e),
    }
}

/// Map message to scalar as hash.
#[cfg(feature = "__private_bbs_fixtures_generator_api")]
#[cfg_attr(docsrs, doc(cfg(feature = "__private_bbs_fixtures_generator_api")))]
pub fn map_message_to_scalar_as_hash(
    message: &[u8],
    dst: Option<&[u8]>,
) -> Result<[u8; OCTET_SCALAR_LENGTH], Error> {
    let scalar =
        Bls12381Shake256CipherSuiteParameter::map_message_to_scalar_as_hash(
            message, dst,
        );

    match scalar {
        Ok(val) => Ok(val.to_bytes_be()),
        Err(e) => Err(e),
    }
}

/// Return the default hash to scalar dst.
#[cfg(feature = "__private_bbs_fixtures_generator_api")]
#[cfg_attr(docsrs, doc(cfg(feature = "__private_bbs_fixtures_generator_api")))]
pub fn default_hash_to_scalar_dst() -> Vec<u8> {
    Bls12381Shake256CipherSuiteParameter::default_hash_to_scalar_dst()
}

/// Return the default map message to scalar as hash dst.
#[cfg(feature = "__private_bbs_fixtures_generator_api")]
#[cfg_attr(docsrs, doc(cfg(feature = "__private_bbs_fixtures_generator_api")))]
pub fn default_map_message_to_scalar_as_hash_dst() -> Vec<u8> {
    Bls12381Shake256CipherSuiteParameter::default_map_message_to_scalar_as_hash_dst()
}

/// Get ciphersuite id.
#[cfg(feature = "__private_bbs_fixtures_generator_api")]
#[cfg_attr(docsrs, doc(cfg(feature = "__private_bbs_fixtures_generator_api")))]
pub fn ciphersuite_id() -> Vec<u8> {
    Bls12381Shake256CipherSuiteParameter::ID
        .as_octets()
        .to_vec()
}

#[cfg(feature = "__private_bbs_fixtures_generator_api")]
use crate::schemes::bbs::core::types::{ProofTrace, SignatureTrace};

/// Generate a BLS12-381-G1-Shake-256 BBS signature using a trace
/// to populate the signature fixtures.
#[cfg_attr(docsrs, doc(cfg(feature = "__private_bbs_fixtures_generator_api")))]
#[cfg(feature = "__private_bbs_fixtures_generator_api")]
pub fn sign_with_trace<T>(
    request: &BbsSignRequest<'_, T>,
    trace: Option<&mut SignatureTrace>,
) -> Result<[u8; BBS_BLS12381G1_SIGNATURE_LENGTH], Error>
where
    T: AsRef<[u8]>,
{
    crate::bbs::api::signature::sign_with_trace::<
        _,
        Bls12381Shake256CipherSuiteParameter,
    >(request, trace)
}

/// Generate a BLS12-381-G1-Shake-256 BBS signature proof of knowledge with
/// a given rng.
#[cfg_attr(docsrs, doc(cfg(feature = "__private_bbs_fixtures_generator_api")))]
#[cfg(feature = "__private_bbs_fixtures_generator_api")]
pub fn proof_with_rng_and_trace<T, R>(
    request: &BbsProofGenRequest<'_, T>,
    rng: R,
    trace: Option<&mut ProofTrace>,
) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]>,
    R: RngCore + CryptoRng,
{
    crate::bbs::api::proof::proof_gen_with_rng_and_trace::<
        _,
        _,
        Bls12381Shake256CipherSuiteParameter,
    >(request, rng, trace)
}
