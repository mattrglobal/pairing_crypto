use super::{
    dtos::{BbsProofGenRequest, BbsProofVerifyRequest},
    utils::{digest_proof_messages, digest_revealed_proof_messages},
};
use crate::{
    bbs::{
        core::{
            generator::memory_cached_generator::MemoryCachedGenerators,
            types::ProofMessage,
        },
        interface::BbsInterfaceParameter,
    },
    error::Error,
    schemes::bbs::core::{
        key_pair::PublicKey,
        proof::Proof,
        signature::Signature,
        types::Message,
    },
};

#[cfg(feature = "__private_bbs_fixtures_generator_api")]
use rand::{CryptoRng, RngCore};

#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;

#[cfg(not(feature = "alloc"))]
use std::collections::BTreeMap;

/// Return the size of proof in bytes for `num_undisclosed_messages`.
pub fn get_proof_size(num_undisclosed_messages: usize) -> usize {
    Proof::get_size(num_undisclosed_messages)
}

// helper function for parsing a BBS Proof Generation Request
fn _parse_request_helper<T, I>(
    request: &BbsProofGenRequest<'_, T>,
) -> Result<
    (
        PublicKey,
        Signature,
        MemoryCachedGenerators<I>,
        Vec<ProofMessage>,
    ),
    Error,
>
where
    T: AsRef<[u8]>,
    I: BbsInterfaceParameter,
{
    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    let (digested_messages, proof_messages) =
        digest_proof_messages::<_, I>(request.messages)?;

    // Derive generators
    let generators =
        MemoryCachedGenerators::<I>::new(digested_messages.len(), None)?;

    // Parse signature from request
    let signature = Signature::from_octets(request.signature)?;

    let verify_signature = request.verify_signature.unwrap_or(true);
    if verify_signature {
        // Verify the signature to check the messages supplied are valid
        if !(signature.verify::<_, _, _, I::Ciphersuite>(
            &pk,
            request.header.as_ref(),
            &generators,
            &digested_messages,
            Some(I::api_id()),
        )?) {
            return Err(Error::SignatureVerification);
        }
    };

    Ok((pk, signature, generators, proof_messages))
}

// Generate a BBS signature proof of knowledge.
pub(crate) fn proof_gen<T, I>(
    request: &BbsProofGenRequest<'_, T>,
) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]>,
    I: BbsInterfaceParameter,
{
    let (pk, signature, generators, proof_messages) =
        _parse_request_helper::<T, I>(request)?;

    // Generate the proof
    let proof = Proof::new::<_, _, I::Ciphersuite>(
        &pk,
        &signature,
        request.header.as_ref(),
        request.presentation_header.as_ref(),
        &generators,
        &proof_messages,
        Some(I::api_id()),
    )?;

    Ok(proof.to_octets())
}

// Verify a BBS signature proof of knowledge.
pub(crate) fn proof_verify<T, I>(
    request: &BbsProofVerifyRequest<'_, T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
    I: BbsInterfaceParameter,
{
    // Parse public key from request
    let public_key = PublicKey::from_octets(request.public_key)?;

    // Parse proof from the request
    let proof = Proof::from_octets(request.proof)?;

    // Deserialize the messages
    let messages = request.messages.unwrap_or(&[] as &[(usize, T)]);

    // Calculate total messages count
    let total_message_count = proof.m_hat_list.len() + messages.len();

    // Digest the revealed proof messages
    let messages: BTreeMap<usize, Message> =
        digest_revealed_proof_messages::<_, I>(messages, total_message_count)?;

    // Derive generators
    let generators =
        MemoryCachedGenerators::<I>::new(total_message_count, None)?;

    proof.verify::<_, _, I::Ciphersuite>(
        &public_key,
        request.header.as_ref(),
        request.presentation_header.as_ref(),
        &generators,
        &messages,
        Some(I::api_id()),
    )
}

// Generate a BBS signature proof of knowledge with a given rng.
#[cfg(feature = "__private_bbs_fixtures_generator_api")]
pub(crate) fn proof_gen_with_rng<T, R, I>(
    request: &BbsProofGenRequest<'_, T>,
    rng: R,
) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]>,
    R: RngCore + CryptoRng,
    I: BbsInterfaceParameter,
{
    let (pk, signature, generators, proof_messages) =
        _parse_request_helper::<T, I>(request)?;

    // Generate the proof
    let proof = Proof::new_with_rng::<_, _, _, I::Ciphersuite>(
        &pk,
        &signature,
        request.header.as_ref(),
        request.presentation_header.as_ref(),
        &generators,
        &proof_messages,
        Some(I::api_id()),
        rng,
    )?;

    Ok(proof.to_octets())
}
