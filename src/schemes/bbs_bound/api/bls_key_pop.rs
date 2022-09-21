use crate::{
    bbs::ciphersuites::BbsCiphersuiteParameters,
    bls::ciphersuites::{
        bls12_381::{
            PublicKey as BlsPublicKey,
            SecretKey as BlsSecretKey,
            BLS_SIG_BLS12381G2_SIGNATURE_LENGTH,
        },
        bls12_381_g2_sha_256_aug::{
            sign as bls_aug_sign,
            verify as bls_aug_verify,
        },
        BlsSigAugCiphersuiteParameters,
    },
    common::{h2s::constant::MAX_DST_SIZE, serialization::i2osp_with_data},
    Error,
};

use super::dtos::{BlsKeyPopGenRequest, BlsKeyPopVerifyRequest};

const MAX_AUD_SIZE: usize = 65535;
const MAX_EXTRA_INFO_SIZE: usize = 65535;
const BBS_BLS_POP_DST_SUFFIX: &[u8] = b"BBS_BLS_POP_MSG_";

///  Generate a commitment to a BLS secret key.
pub(crate) fn generate<C1, C2>(
    request: &BlsKeyPopGenRequest<'_>,
) -> Result<[u8; BLS_SIG_BLS12381G2_SIGNATURE_LENGTH], Error>
where
    C1: BbsCiphersuiteParameters,
    C2: BlsSigAugCiphersuiteParameters,
{
    // Parse BLS secret key from request
    let bls_sk = BlsSecretKey::from_bytes(request.bls_secret_key)?;

    let bls_pop_message = get_bls_pop_message::<C1, C2>(
        request.aud,
        request.dst,
        request.extra_info,
    )?;

    bls_aug_sign(&bls_sk, bls_pop_message)
}

///  Validate a proof of possession of a BLS secret key (KeyPoP) created using
/// the `key_pop` operation.
pub(crate) fn verify<C1, C2>(
    request: &BlsKeyPopVerifyRequest<'_>,
) -> Result<bool, Error>
where
    C1: BbsCiphersuiteParameters,
    C2: BlsSigAugCiphersuiteParameters,
{
    // Parse BLS public key from request
    let bls_pk = BlsPublicKey::from_octets(request.bls_public_key)?;

    // Validate the public key; it should not be an identity and should
    // belong to subgroup.
    if bls_pk.is_valid().unwrap_u8() == 0 {
        return Err(Error::InvalidPublicKey);
    }

    let bls_pop_message = get_bls_pop_message::<C1, C2>(
        request.aud,
        request.dst,
        request.extra_info,
    )?;
    bls_aug_verify(&bls_pk, bls_pop_message, request.bls_key_pop)
}

fn get_bls_pop_message<C1, C2>(
    aud: &[u8],
    dst: Option<&[u8]>,
    extra_info: Option<&[u8]>,
) -> Result<Vec<u8>, Error>
where
    C1: BbsCiphersuiteParameters,
    C2: BlsSigAugCiphersuiteParameters,
{
    let dst = dst.unwrap_or(b"");
    let extra_info = extra_info.unwrap_or(b"");

    if aud.len() > MAX_AUD_SIZE {
        return Err(Error::BadParams {
            cause: "aud is too large".to_owned(),
        });
    }
    if extra_info.len() > MAX_EXTRA_INFO_SIZE {
        return Err(Error::BadParams {
            cause: "extra-info is too large".to_owned(),
        });
    }
    if dst.len() > MAX_DST_SIZE as usize {
        return Err(Error::DstIsTooLarge);
    }

    let mut bls_pop_message = vec![];
    bls_pop_message.extend(C1::ID.as_octets());
    bls_pop_message.extend(C2::ID.as_octets());
    bls_pop_message.extend(BBS_BLS_POP_DST_SUFFIX);
    bls_pop_message.extend(i2osp_with_data(aud, 2)?);
    bls_pop_message.extend(i2osp_with_data(extra_info, 2)?);
    bls_pop_message.extend(dst);
    Ok(bls_pop_message)
}
