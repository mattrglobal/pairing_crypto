use super::{
    dtos::{BbsSignRequest, BbsVerifyRequest},
    utils::digest_messages,
};
use crate::{
    bbs::{
        ciphersuites::BbsCiphersuiteParameters,
        core::{
            constants::BBS_BLS12381G1_SIGNATURE_LENGTH,
            generator::Generators,
            key_pair::{PublicKey, SecretKey},
            signature::Signature,
            types::Message,
        },
    },
    error::Error,
};

// Create a BLS12-381 signature.
pub(crate) fn sign<T, C>(
    request: &BbsSignRequest<'_, T>,
) -> Result<[u8; BBS_BLS12381G1_SIGNATURE_LENGTH], Error>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters<'static>,
{
    // Parse the secret key
    let sk = SecretKey::from_bytes(request.secret_key)?;

    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    // Digest the supplied messages
    let messages: Vec<Message> = digest_messages::<_, C>(request.messages)?;

    // Derive generators
    let generators = Generators::new::<C>(messages.len())?;

    // Produce the signature and return
    Signature::new::<_, _, C>(
        &sk,
        &pk,
        request.header.as_ref(),
        &generators,
        &messages,
    )
    .map(|sig| sig.to_octets())
}

// Verify a BLS12-381 signature.
pub(crate) fn verify<T, C>(
    request: &BbsVerifyRequest<'_, T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters<'static>,
{
    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    // Digest the supplied messages
    let messages: Vec<Message> = digest_messages::<_, C>(request.messages)?;

    // Derive generators
    let generators = Generators::new::<C>(messages.len())?;

    // Parse signature from request
    let signature = Signature::from_octets(request.signature)?;

    signature.verify::<_, _, C>(
        &pk,
        request.header.as_ref(),
        &generators,
        &messages,
    )
}
