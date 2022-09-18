use super::{
    dtos::{
        BbsBoundSignRequest,
        BbsBoundVerifyRequest,
        BbsSignRequest,
        BbsVerifyRequest,
    },
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

use crate::bls::core::key_pair::{
    PublicKey as BlsPublicKey,
    SecretKey as BlsSecretKey,
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
    let generators = MemoryCachedGenerators::<C>::new(messages.len(), 0)?;

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

// Create a BBS Bound signature.
pub(crate) fn bound_sign<T, C>(
    request: &BbsBoundSignRequest<'_, T>,
) -> Result<[u8; BBS_BLS12381G1_SIGNATURE_LENGTH], Error>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters,
{
    // Parse the secret key
    let sk = SecretKey::from_bytes(request.secret_key)?;

    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    // Parse BLS public key from request
    let bls_pk = BlsPublicKey::from_octets(request.bls_public_key)?;

    // Digest the supplied messages
    let messages: Vec<Message> = digest_messages::<_, C>(request.messages)?;

    // Derive generators
    let generators = MemoryCachedGenerators::<C>::new(messages.len(), 1)?;

    // Produce the signature and return
    Signature::new_bound::<_, _, _, C>(
        &sk,
        &pk,
        &bls_pk,
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
    let generators = MemoryCachedGenerators::<C>::new(messages.len(), 0)?;

    // Parse signature from request
    let signature = Signature::from_octets(request.signature)?;

    signature.verify::<_, _, _, C>(
        &pk,
        request.header.as_ref(),
        &generators,
        &messages,
    )
}

// Verify a BBS bound signature.
pub(crate) fn bound_verify<T, C>(
    request: &BbsBoundVerifyRequest<'_, T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters,
{
    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    // Parse BLS secret key from request
    let bls_sk = BlsSecretKey::from_bytes(request.bls_secret_key)?;

    // Digest the supplied messages
    let mut messages: Vec<Message> = digest_messages::<_, C>(request.messages)?;
    messages.push(Message(*bls_sk.0));

    // Derive generators
    let generators = MemoryCachedGenerators::<C>::new(messages.len() - 1, 1)?;

    // Parse signature from request
    let signature = Signature::from_octets(request.signature)?;

    signature.verify::<_, _, _, C>(
        &pk,
        request.header.as_ref(),
        &generators,
        &messages,
    )
}
