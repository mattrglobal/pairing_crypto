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
        g1_affine_compressed_size,
        Challenge,
        Generators,
        Message,
        PokSignature,
        PokSignatureProof,
        PresentationMessage,
        ProofMessage,
        PublicKey,
        Signature,
        APP_MESSAGE_DST,
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        GLOBAL_MESSAGE_GENERATOR_SEED,
        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
    },
};
use digest::{ExtendableOutput, Update, XofReader};

/// Derives a signature proof of knowledge
pub fn derive(request: BbsDeriveProofRequest) -> Result<Vec<u8>, Error> {
    // Parse public key from request
    let pk = PublicKey::from_vec(request.public_key)?;

    // Digest the supplied messages
    let digested_messages = digest_messages(
        request
            .messages
            .iter()
            .map(|element| element.value.clone())
            .collect(),
    )
    .unwrap();

    // Derive generators
    let generators = Generators::new(
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
        GLOBAL_MESSAGE_GENERATOR_SEED,
        request.messages.len(),
    );
    // Parse signature from request
    let signature = match Signature::from_vec(request.signature) {
        Ok(result) => result,
        Err(_) => {
            return Err(Error::CryptoMalformedSignature {
                cause: "parsing failed".to_owned(),
            });
        }
    };

    // Verify the signature to check the messages supplied are valid
    match signature.verify(&pk, &generators, &digested_messages) {
        false => {
            return Err(Error::CryptoSignatureVerification);
        }
        true => {}
    };

    // Digest the supplied messages
    let messages: Vec<ProofMessage> =
        match digest_proof_messages(request.messages) {
            Ok(messages) => messages,
            Err(e) => return Err(e),
        };

    let presentation_message = PresentationMessage::hash(
        request.presentation_message,
        APP_MESSAGE_DST,
    )?;

    let mut pok = PokSignature::init(signature, &generators, &messages)?;

    let mut data = [0u8; g1_affine_compressed_size()];
    let mut hasher = sha3::Shake256::default();
    pok.add_proof_contribution(&mut hasher);
    hasher.update(presentation_message.to_bytes());
    let mut reader = hasher.finalize_xof();
    reader.read(&mut data[..]);
    let challenge = Challenge::hash(&data, APP_MESSAGE_DST)?;

    match pok.generate_proof(challenge) {
        Ok(proof) => Ok(proof.to_bytes()),
        Err(e) => Err(e),
    }
}

/// Verifies a signature proof of knowledge
pub fn verify(request: BbsVerifyProofRequest) -> Result<bool, Error> {
    // Parse public key from request
    let public_key = PublicKey::from_vec(request.public_key)?;

    // Digest the revealed proof messages
    let messages: Vec<(usize, Message)> = digest_revealed_proof_messages(
        request.messages,
        request.total_message_count,
    )?;

    // Derive generators
    let generators = Generators::new(
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
        GLOBAL_MESSAGE_GENERATOR_SEED,
        request.total_message_count,
    );

    let proof = match PokSignatureProof::from_bytes(request.proof) {
        Some(result) => result,
        None => {
            return Err(Error::Conversion {
                cause: "failed to parse signature-PoK proof".into(),
            });
        }
    };

    let presentation_message = PresentationMessage::hash(
        request.presentation_message,
        APP_MESSAGE_DST,
    )?;

    let mut data = [0u8; g1_affine_compressed_size()];
    let mut hasher = sha3::Shake256::default();

    proof.add_challenge_contribution(
        &generators,
        &messages,
        proof.challenge,
        &mut hasher,
    )?;

    hasher.update(&presentation_message.to_bytes()[..]);
    let mut reader = hasher.finalize_xof();
    reader.read(&mut data[..]);
    let v_challenge = Challenge::hash(&data, APP_MESSAGE_DST)?;

    Ok(proof.verify(public_key) && proof.challenge == v_challenge)
}
