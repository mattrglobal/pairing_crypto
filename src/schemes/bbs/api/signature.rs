use super::{
    dtos::{BbsSignRequest, BbsVerifyRequest},
    utils::digest_messages,
};
use crate::{
    error::Error,
    schemes::bbs::ciphersuites::bls12_381::{
        Generators,
        Message,
        PublicKey,
        SecretKey,
        Signature,
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        GLOBAL_MESSAGE_GENERATOR_SEED,
        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
    },
};

/// Creates a signature.
/// Security Warning: `secret_key` and `public_key` in `request` must be related
/// key-pair generated using `KeyPair` APIs.
pub fn sign(request: BbsSignRequest) -> Result<[u8; 112], Error> {
    // Parse the secret key
    let sk = SecretKey::from_vec(&request.secret_key)?;

    // Parse public key from request
    let pk = PublicKey::from_vec(&request.public_key)?;

    // Digest the supplied messages
    let messages: Vec<Message> = digest_messages(request.messages.as_ref())?;

    // Derive generators
    let generators = Generators::new(
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
        GLOBAL_MESSAGE_GENERATOR_SEED,
        messages.len(),
    )?;

    // Produce the signature and return
    Signature::new(&sk, &pk, request.header.as_ref(), &generators, &messages)
        .map(|sig| sig.to_octets())
}

/// Verifies a signature.
pub fn verify(request: BbsVerifyRequest) -> Result<bool, Error> {
    // Parse public key from request
    let pk = PublicKey::from_vec(&request.public_key)?;

    // Digest the supplied messages
    let messages: Vec<Message> = digest_messages(request.messages.as_ref())?;

    // Derive generators
    let generators = Generators::new(
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
        GLOBAL_MESSAGE_GENERATOR_SEED,
        messages.len(),
    )?;

    // Parse signature from request
    let signature = Signature::from_vec(&request.signature)?;

    signature.verify(&pk, request.header.as_ref(), &generators, &messages)
}
