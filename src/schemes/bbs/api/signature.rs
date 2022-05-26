use super::{
    dtos::{BbsSignRequest, BbsVerifyRequest},
    utils::digest_messages,
};
use crate::{
    error::Error,
    schemes::bbs::ciphersuites::bls12_381::{
        Message,
        MessageGenerators,
        PublicKey,
        SecretKey,
        Signature,
    },
};

/// Creates a signature
pub fn sign(request: BbsSignRequest) -> Result<[u8; 112], Error> {
    // Parse the secret key
    let sk = SecretKey::from_vec(request.secret_key)?;

    // Derive the public key from the secret key
    let pk = PublicKey::from(&sk);

    // Digest the supplied messages
    let messages: Vec<Message> = digest_messages(request.messages)?;

    // Use generators derived from the signers public key
    // TODO this approach is likely to change soon
    let generators = MessageGenerators::from_public_key(pk, messages.len());

    // Produce the signature and return
    Signature::new(&sk, &generators, &messages).map(|sig| sig.to_bytes())
}

/// Verifies a signature
pub fn verify(request: BbsVerifyRequest) -> Result<bool, Error> {
    // Parse public key from request
    let pk = PublicKey::from_vec(request.public_key)?;

    // Digest the supplied messages
    let messages: Vec<Message> = digest_messages(request.messages)?;

    // Use generators derived from the signers public key
    // TODO this approach is likely to change soon
    let generators = MessageGenerators::from_public_key(pk, messages.len());

    // Parse signature from request
    let signature = Signature::from_vec(request.signature)?;

    Ok(signature.verify(&pk, &generators, &messages))
}
