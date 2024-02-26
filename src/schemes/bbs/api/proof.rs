use super::{
    dtos::{BbsProofGenRequest, BbsProofVerifyRequest},
    utils::{digest_proof_messages, digest_revealed_proof_messages},
};
use crate::{
    bbs::{
        ciphersuites::BbsCiphersuiteParameters,
        core::{
            generator::memory_cached_generator::MemoryCachedGenerators,
            types::ProofMessage,
        },
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
fn _parse_request_helper<T, C>(
    request: &BbsProofGenRequest<'_, T>,
) -> Result<
    (
        PublicKey,
        Signature,
        MemoryCachedGenerators<C>,
        Vec<ProofMessage>,
    ),
    Error,
>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters,
{
    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    let (digested_messages, proof_messages) =
        digest_proof_messages::<_, C>(request.messages)?;

    // Derive generators
    let generators =
        MemoryCachedGenerators::<C>::new(digested_messages.len(), None)?;

    // Parse signature from request
    let signature = Signature::from_octets(request.signature)?;

    let verify_signature = request.verify_signature.unwrap_or(true);
    if verify_signature {
        // Verify the signature to check the messages supplied are valid
        if !(signature.verify::<_, _, _, C>(
            &pk,
            request.header.as_ref(),
            &generators,
            &digested_messages,
        )?) {
            return Err(Error::SignatureVerification);
        }
    };

    Ok((pk, signature, generators, proof_messages))
}

// Generate a BBS signature proof of knowledge.
pub(crate) fn proof_gen<T, C>(
    request: &BbsProofGenRequest<'_, T>,
) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters,
{
    let (pk, signature, generators, proof_messages) =
        _parse_request_helper::<T, C>(request)?;

    // Generate the proof
    let proof = Proof::new::<_, _, C>(
        &pk,
        &signature,
        request.header.as_ref(),
        request.presentation_header.as_ref(),
        &generators,
        &proof_messages,
    )?;

    Ok(proof.to_octets())
}

// Verify a BBS signature proof of knowledge.
pub(crate) fn proof_verify<T, C>(
    request: &BbsProofVerifyRequest<'_, T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters,
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
        digest_revealed_proof_messages::<_, C>(messages, total_message_count)?;

    // Derive generators
    let generators =
        MemoryCachedGenerators::<C>::new(total_message_count, None)?;

    proof.verify::<_, _, C>(
        &public_key,
        request.header.as_ref(),
        request.presentation_header.as_ref(),
        &generators,
        &messages,
    )
}

// Generate a BBS signature proof of knowledge with a given rng and a trace.
#[cfg_attr(
    docsrs,
    doc(cfg(feature = "__private_bbs_fixtures_generator_api"))
)]
#[cfg(feature = "__private_bbs_fixtures_generator_api")]
use crate::schemes::bbs::core::types::ProofTrace;

#[cfg_attr(docsrs, doc(cfg(feature = "__private_bbs_fixtures_generator_api")))]
#[cfg(feature = "__private_bbs_fixtures_generator_api")]
pub(crate) fn proof_gen_with_rng_and_trace<T, R, C>(
    request: &BbsProofGenRequest<'_, T>,
    rng: R,
    trace: Option<&mut ProofTrace>,
) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]>,
    R: RngCore + CryptoRng,
    C: BbsCiphersuiteParameters,
{
    let (pk, signature, generators, proof_messages) =
        _parse_request_helper::<T, C>(request)?;

    // Generate the proof
    let proof = Proof::new_with_trace::<_, _, _, C>(
        &pk,
        &signature,
        request.header.as_ref(),
        request.presentation_header.as_ref(),
        &generators,
        &proof_messages,
        rng,
        trace,
    )?;

    Ok(proof.to_octets())
}
