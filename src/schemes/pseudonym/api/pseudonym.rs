use super::dtos::BbsPseudonymGenRequest;

use crate::{
    bbs::interface::BbsInterfaceParameter,
    curves::bls12_381::OCTET_POINT_G1_LENGTH,
    error::Error,
    pseudonym::core::pseudonym::Pseudonym,
};

pub(crate) fn generate<T, I>(
    request: &BbsPseudonymGenRequest<T>,
) -> Result<[u8; OCTET_POINT_G1_LENGTH], Error>
where
    T: AsRef<[u8]>,
    I: BbsInterfaceParameter,
{
    let pseudonym = Pseudonym::new::<_, I>(
        &request.verifier_id,
        &request.prover_id,
        Some(I::api_id()),
    )?;

    Ok(pseudonym.to_octets())
}
