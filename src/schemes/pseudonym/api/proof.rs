use super::dtos::{BbsProofGenRequest, BbsProofVerifyRequest};

use crate::{
    bbs::{
        api::utils::{digest_proof_messages, digest_revealed_proof_messages},
        core::{
            generator::memory_cached_generator::MemoryCachedGenerators,
            key_pair::PublicKey,
            signature::Signature,
            types::Message,
        },
        interface::BbsInterfaceParameter,
    },
    error::Error,
    pseudonym::core::{proof::ProofWithNym, pseudonym::Pseudonym},
};

fn pid_to_message<T, I>(pid: &T) -> Result<Message, Error>
where
    T: AsRef<[u8]> + Default,
    I: BbsInterfaceParameter,
{
    Message::from_arbitrary_data::<I>(pid.as_ref(), None)
}

pub(crate) fn proof_gen<T, I>(
    request: &BbsProofGenRequest<'_, T>,
) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]> + Default,
    I: BbsInterfaceParameter,
{
    let pk = PublicKey::from_octets(request.public_key)?;

    let (mut digested_messages, proof_messages) =
        digest_proof_messages::<_, I>(request.messages)?;

    let generators =
        MemoryCachedGenerators::<I>::new(digested_messages.len() + 1, None)?;

    let signature = Signature::from_octets(request.signature)?;
    let pseudonym = Pseudonym::from_octets(request.pseudonym)?;

    // digest the pid message
    let pid = pid_to_message::<_, I>(&request.pid)?;
    digested_messages.push(pid);
    // proof_messages.push(ProofMessage::Hidden(pid));

    let verify_signature = request.verify_signature.unwrap_or(true);
    if verify_signature
        && !(signature.verify::<_, _, _, I::Ciphersuite>(
            &pk,
            request.header.as_ref(),
            &generators,
            &digested_messages,
            Some(I::api_id()),
        )?)
    {
        return Err(Error::SignatureVerification);
    };

    let proof = ProofWithNym::new::<_, _, I::Ciphersuite>(
        &pk,
        &signature,
        &pseudonym,
        &request.verifier_id,
        pid,
        request.header.as_ref(),
        request.presentation_header.as_ref(),
        &generators,
        &proof_messages,
        Some(I::api_id()),
    )?;

    Ok(proof.to_octets())
}

pub(crate) fn proof_verify<T, I>(
    request: &BbsProofVerifyRequest<'_, T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]> + Default,
    I: BbsInterfaceParameter,
{
    let pk = PublicKey::from_octets(request.public_key)?;
    let proof = ProofWithNym::from_octets(request.proof)?;

    let pseudonym = Pseudonym::from_octets(request.pseudonym)?;

    let messages = request.messages.unwrap_or(&[] as &[(usize, T)]);
    let total_message_count = proof.0.m_hat_list.len() + messages.len();

    let messages = digest_revealed_proof_messages::<_, I>(
        messages,
        total_message_count, // The last message should not be disclosed
    )?;

    let generators =
        MemoryCachedGenerators::<I>::new(total_message_count, None)?;

    proof.verify::<_, _, I::Ciphersuite>(
        &pk,
        &pseudonym,
        &request.verifier_id,
        request.header.as_ref(),
        request.presentation_header.as_ref(),
        &generators,
        &messages,
        Some(I::api_id()),
    )
}
