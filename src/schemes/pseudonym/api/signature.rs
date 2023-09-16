use super::dtos::{BbsSignRequest, BbsVerifyRequest};

use crate::{
    bbs::{
        api::utils::digest_messages,
        ciphersuites::bls12_381::BBS_BLS12381G1_SIGNATURE_LENGTH,
        core::{
            generator::memory_cached_generator::MemoryCachedGenerators,
            key_pair::{PublicKey, SecretKey},
            signature::Signature,
        },
        interface::BbsInterfaceParameter,
    },
    error::Error,
};

pub(crate) fn sign<T, I>(
    request: &BbsSignRequest<'_, T>,
) -> Result<[u8; BBS_BLS12381G1_SIGNATURE_LENGTH], Error>
where
    T: AsRef<[u8]> + Default,
    I: BbsInterfaceParameter,
{
    let sk = SecretKey::from_bytes(request.secret_key)?;
    let pk = PublicKey::from_octets(request.public_key)?;

    let mut messages = digest_messages::<_, I>(request.messages)?;
    let pid_msg = digest_messages::<_, I>(Some(&[&request.prover_id]))?;
    messages.push(pid_msg[0]);

    let generators = MemoryCachedGenerators::<I>::new(messages.len(), None)?;

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

pub(crate) fn verify<T, I>(
    request: &BbsVerifyRequest<'_, T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]> + Default,
    I: BbsInterfaceParameter,
{
    let pk = PublicKey::from_octets(request.public_key)?;

    let mut messages = digest_messages::<_, I>(request.messages)?;
    let pid_msg = digest_messages::<_, I>(Some(&[&request.prover_id]))?;
    messages.push(pid_msg[0]);

    let generators = MemoryCachedGenerators::<I>::new(messages.len(), None)?;
    let signature = Signature::from_octets(request.signature)?;

    signature.verify::<_, _, _, I::Ciphersuite>(
        &pk,
        request.header.as_ref(),
        &generators,
        &messages,
        Some(I::api_id()),
    )
}
