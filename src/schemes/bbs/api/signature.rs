use super::{
    dtos::{BbsSignRequest, BbsVerifyRequest},
    utils::digest_messages,
};
use crate::{
    bbs::{
        ciphersuites::bls12_381::BBS_BLS12381G1_SIGNATURE_LENGTH,
        core::{
            generator::memory_cached_generator::MemoryCachedGenerators,
            key_pair::{PublicKey, SecretKey},
            signature::Signature,
            types::Message,
        },
        interface::BbsInterfaceParameter,
    },
    error::Error,
};

// Create a BBS signature.
pub(crate) fn sign<T, I>(
    request: &BbsSignRequest<'_, T>,
) -> Result<[u8; BBS_BLS12381G1_SIGNATURE_LENGTH], Error>
where
    T: AsRef<[u8]>,
    I: BbsInterfaceParameter,
{
    // Parse the secret key
    let sk = SecretKey::from_bytes(request.secret_key)?;

    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    // Digest the supplied messages
    let messages: Vec<Message> = digest_messages::<_, I>(request.messages)?;

    // Derive generators
    let generators = MemoryCachedGenerators::<I>::new(messages.len(), None)?;

    // Produce the signature and return
    Signature::new::<_, _, _, I::Ciphersuite>(
        &sk,
        &pk,
        request.header.as_ref(),
        &generators,
        &messages,
        Some(I::api_id()),
    )
    .map(|sig| sig.to_octets())
}

// Verify a BBS signature.
pub(crate) fn verify<T, I>(
    request: &BbsVerifyRequest<'_, T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
    I: BbsInterfaceParameter,
{
    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    // Digest the supplied messages
    let messages: Vec<Message> = digest_messages::<_, I>(request.messages)?;

    // Derive generators
    let generators = MemoryCachedGenerators::<I>::new(messages.len(), None)?;

    // Parse signature from request
    let signature = Signature::from_octets(request.signature)?;

    signature.verify::<_, _, _, I::Ciphersuite>(
        &pk,
        request.header.as_ref(),
        &generators,
        &messages,
        Some(I::api_id()),
    )
}
