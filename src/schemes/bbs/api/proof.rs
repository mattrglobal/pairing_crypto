use super::{
    dtos::{BbsDeriveProofRequest, BbsVerifyProofRequest},
    utils::{
        digest_messages,
        digest_proof_messages,
        digest_revealed_proof_messages,
    },
};
use crate::{
    error::Error,
    schemes::bbs::ciphersuites::bls12_381::{
        Generators,
        Message,
        PokSignature,
        PokSignatureProof,
        ProofMessage,
        PublicKey,
        Signature,
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        GLOBAL_MESSAGE_GENERATOR_SEED,
        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
    },
};

/// Derives a signature proof of knowledge.
pub fn derive(request: BbsDeriveProofRequest) -> Result<Vec<u8>, Error> {
    // Parse public key from request
    let pk = PublicKey::from_vec(request.public_key)?;

    let mut digested_messages = vec![];
    if request.messages.is_some() {
        let request_messages = request.messages.as_ref().unwrap();
        let request_messages = request_messages
            .iter()
            .map(|element| element.value.clone())
            .collect::<Vec<Vec<u8>>>();
        // Digest the supplied messages
        digested_messages = digest_messages(Some(&request_messages))?;
    }

    // Derive generators
    let generators = Generators::new(
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
        GLOBAL_MESSAGE_GENERATOR_SEED,
        digested_messages.len(),
    )?;
    // Parse signature from request
    let signature = Signature::from_vec(request.signature)?;

    // Verify the signature to check the messages supplied are valid
    signature.verify(
        &pk,
        request.header.as_ref(),
        &generators,
        &digested_messages,
    )?;

    // Digest the supplied messages
    let messages: Vec<ProofMessage> =
        match digest_proof_messages(request.messages.as_ref()) {
            Ok(messages) => messages,
            Err(e) => return Err(e),
        };

    let mut pok = PokSignature::init(
        &pk,
        &signature,
        request.header.as_ref(),
        &generators,
        &messages,
    )?;

    let challenge =
        pok.compute_challenge(&pk, request.presentation_message.as_ref())?;

    match pok.generate_proof(challenge) {
        Ok(proof) => Ok(proof.to_octets()),
        Err(e) => Err(e),
    }
}

/// Verifies a signature proof of knowledge.
pub fn verify(request: BbsVerifyProofRequest) -> Result<bool, Error> {
    // Parse public key from request
    let public_key = PublicKey::from_vec(request.public_key)?;

    // Digest the revealed proof messages
    let messages: Vec<(usize, Message)> = digest_revealed_proof_messages(
        request.messages.as_ref(),
        request.total_message_count,
    )?;

    // Derive generators
    let generators = Generators::new(
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
        GLOBAL_MESSAGE_GENERATOR_SEED,
        request.total_message_count,
    )?;

    let proof = PokSignatureProof::from_octets(request.proof)?;

    let cv = proof.compute_challenge(
        &public_key,
        request.header.as_ref(),
        &generators,
        &messages,
        request.presentation_message.as_ref(),
        proof.c,
    )?;

    Ok(proof.verify_signature_proof(public_key)? && proof.c == cv)
}
