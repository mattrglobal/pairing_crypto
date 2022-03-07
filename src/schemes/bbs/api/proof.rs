use super::dtos::{BbsDeriveProofRequest, BbsVerifyProofRequest};
use super::utils::{
    digest_messages, digest_proof_messages, digest_revealed_proof_messages, BbsErrorCode,
};
use crate::bls12_381::bbs::{MessageGenerators, PokSignature, PokSignatureProof, Signature};
use crate::bls12_381::PublicKey;
use crate::schemes::core::*;
use digest::{ExtendableOutput, Update, XofReader};

/// Derives a signature proof of knowledge
pub fn derive(request: BbsDeriveProofRequest) -> Result<Vec<u8>, Error> {
    // Parse public key from request
    let pk = match PublicKey::from_vec(request.public_key) {
        Ok(result) => result,
        Err(_) => {
            return Err(Error::new_bbs_error(
                BbsErrorCode::ParsingError,
                "Failed to parse public key",
            ))
        }
    };

    // Digest the supplied messages
    let digested_messages = digest_messages(
        request
            .messages
            .iter()
            .map(|element| element.value.clone())
            .collect(),
    )
    .unwrap();

    // Use generators derived from the signers public key
    // TODO this approach is likely to change soon
    let generators = MessageGenerators::from_public_key(pk, request.messages.len());

    // Parse signature from request
    let signature = match Signature::from_vec(request.signature) {
        Ok(result) => result,
        Err(e) => return Err(Error::new_bbs_error(BbsErrorCode::ParsingError, &e)),
    };

    // Verify the signature to check the messages supplied are valid
    match signature.verify(&pk, &generators, &digested_messages) {
        false => {
            return Err(Error::new_bbs_error(
                BbsErrorCode::InvalidSignature,
                "Invalid signature, unable to verify",
            ))
        }
        true => {}
    };

    // Digest the supplied messages
    let messages: Vec<ProofMessage> = match digest_proof_messages(request.messages) {
        Ok(messages) => messages,
        Err(e) => return Err(e),
    };

    let presentation_message = PresentationMessage::hash(request.presentation_message);

    let mut pok = match PokSignature::init(signature, &generators, &messages) {
        Ok(proof) => proof,
        Err(e) => return Err(e),
    };

    let mut data = [0u8; COMMITMENT_G1_BYTES];
    let mut hasher = sha3::Shake256::default();
    pok.add_proof_contribution(&mut hasher);
    hasher.update(presentation_message.to_bytes());
    let mut reader = hasher.finalize_xof();
    reader.read(&mut data[..]);
    let challenge = Challenge::from_okm(&data);

    match pok.generate_proof(challenge) {
        Ok(proof) => Ok(proof.to_bytes()),
        Err(e) => Err(e),
    }
}

/// Verifies a signature proof of knowledge
pub fn verify(request: BbsVerifyProofRequest) -> Result<bool, Error> {
    // Parse public key from request
    let public_key = match PublicKey::from_vec(request.public_key) {
        Ok(result) => result,
        Err(_) => {
            return Err(Error::new_bbs_error(
                BbsErrorCode::ParsingError,
                "Failed to parse public key",
            ))
        }
    };

    // Digest the revealed proof messages
    let messages: Vec<(usize, Message)> =
        match digest_revealed_proof_messages(request.messages, request.total_message_count) {
            Ok(result) => result,
            Err(e) => return Err(e),
        };

    // Use generators derived from the signers public key
    // TODO this approach is likely to change soon
    let generators = MessageGenerators::from_public_key(public_key, request.total_message_count);

    // TODO dont use unwrap here
    let proof = match PokSignatureProof::from_bytes(request.proof) {
        Some(result) => result,
        None => {
            return Err(Error::new_bbs_error(
                BbsErrorCode::ParsingError,
                "Failed to parse proof",
            ))
        }
    };

    let presentation_message = PresentationMessage::hash(request.presentation_message);

    let mut data = [0u8; COMMITMENT_G1_BYTES];
    let mut hasher = sha3::Shake256::default();

    match proof.add_challenge_contribution(&generators, &messages, proof.challenge, &mut hasher) {
        Err(_) => {
            return Err(Error::new_bbs_error(
                BbsErrorCode::InvalidProof,
                "Failed to recompute challenge",
            ))
        }
        _ => {}
    }

    hasher.update(&presentation_message.to_bytes()[..]);
    let mut reader = hasher.finalize_xof();
    reader.read(&mut data[..]);
    let v_challenge = Challenge::from_okm(&data);

    Ok(proof.verify(public_key) && proof.challenge == v_challenge)
}
