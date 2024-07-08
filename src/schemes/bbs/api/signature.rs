use super::{
    dtos::{BbsSignRequest, BbsVerifyRequest},
    utils::digest_messages,
};
use crate::{
    bbs::{
        ciphersuites::{
            bls12_381::BBS_BLS12381G1_SIGNATURE_LENGTH,
            BbsCiphersuiteParameters,
        },
        core::{
            generator::memory_cached_generator::MemoryCachedGenerators,
            key_pair::{PublicKey, SecretKey},
            signature::Signature,
            types::Message,
        },
    },
    error::Error,
};

// Create a BBS signature.
pub(crate) fn sign<T, C>(
    request: &BbsSignRequest<'_, T>,
) -> Result<[u8; BBS_BLS12381G1_SIGNATURE_LENGTH], Error>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters,
{
    // Parse the secret key
    let sk = SecretKey::from_bytes(request.secret_key)?;

    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    // Digest the supplied messages
    let messages: Vec<Message> = digest_messages::<_, C>(request.messages)?;

    // Derive generators
    let generators = MemoryCachedGenerators::<C>::new(messages.len(), None)?;

    // Produce the signature and return
    Signature::new::<_, _, _, C>(
        &sk,
        &pk,
        request.header.as_ref(),
        &generators,
        &messages,
    )
    .map(|sig| sig.to_octets())
}

// Verify a BBS signature.
pub(crate) fn verify<T, C>(
    request: &BbsVerifyRequest<'_, T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters,
{
    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    // Digest the supplied messages
    let messages: Vec<Message> = digest_messages::<_, C>(request.messages)?;

    // Derive generators
    let generators = MemoryCachedGenerators::<C>::new(messages.len(), None)?;

    // Parse signature from request
    let signature = Signature::from_octets(request.signature)?;

    signature.verify::<_, _, _, C>(
        &pk,
        request.header.as_ref(),
        &generators,
        &messages,
    )
}

#[cfg_attr(
    docsrs,
    doc(cfg(feature = "__private_bbs_fixtures_generator_api"))
)]
#[cfg(feature = "__private_bbs_fixtures_generator_api")]
use crate::bbs::core::types::SignatureTrace;

#[cfg_attr(docsrs, doc(cfg(feature = "__private_bbs_fixtures_generator_api")))]
#[cfg(feature = "__private_bbs_fixtures_generator_api")]
pub(crate) fn sign_with_trace<T, C>(
    request: &BbsSignRequest<'_, T>,
    trace: Option<&mut SignatureTrace>,
) -> Result<[u8; BBS_BLS12381G1_SIGNATURE_LENGTH], Error>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters,
{
    // Parse the secret key
    let sk = SecretKey::from_bytes(request.secret_key)?;

    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    // Digest the supplied messages
    let messages: Vec<Message> = digest_messages::<_, C>(request.messages)?;

    // Derive generators
    let generators = MemoryCachedGenerators::<C>::new(messages.len(), None)?;

    // Produce the signature and return
    Signature::new_with_trace::<_, _, _, C>(
        &sk,
        &pk,
        request.header.as_ref(),
        &generators,
        &messages,
        trace,
    )
    .map(|sig| sig.to_octets())
}
