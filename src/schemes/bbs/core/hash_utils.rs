use super::constants::{
    MAX_DST_SIZE,
    MAX_MESSAGE_SIZE,
    MAX_VALUE_GENERATION_RETRY_COUNT,
    NON_NEGATIVE_INTEGER_ENCODING_LENGTH,
    XOF_NO_OF_BYTES,
};
use crate::{
    bbs::ciphersuites::BbsCiphersuiteParameters,
    common::serialization::{i2osp, i2osp_with_data},
    curves::bls12_381::{
        hash_to_curve::{ExpandMessage, ExpandMessageState},
        G1Projective,
        Scalar,
    },
    error::Error,
};
use ff::Field;
use group::Group;
use rand::RngCore;

/// Hash arbitrary data to a scalar as specified in [3.3.9.1 Hash to scalar](https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-mapmessagetoscalarashash).
pub(crate) fn map_message_to_scalar_as_hash<C>(
    message: &[u8],
    dst: Option<&[u8]>,
) -> Result<Scalar, Error>
where
    C: BbsCiphersuiteParameters<'static>,
{
    let default_map_message_to_scalar_as_hash_dst =
        C::default_map_message_to_scalar_as_hash_dst();
    let dst = dst.unwrap_or(&default_map_message_to_scalar_as_hash_dst);

    if !dst.is_ascii() {
        return Err(Error::BadParams {
            cause: "non-ascii dst".to_owned(),
        });
    }

    // If len(dst) > 2^8 - 1 or len(msg) > 2^64 - 1, abort
    if message.len() as u64 > MAX_MESSAGE_SIZE {
        return Err(Error::MessageIsTooLarge);
    }
    if dst.len() > MAX_DST_SIZE as usize {
        return Err(Error::DstIsTooLarge);
    }

    // msg_prime = I2OSP(len(msg), 8) || msg
    let msg_prime =
        i2osp_with_data(message, NON_NEGATIVE_INTEGER_ENCODING_LENGTH)?;

    // hash_to_scalar(msg_prime || dst_prime, 1)
    Ok(C::hash_to_scalar(&msg_prime, 1, Some(dst))?[0])
}

/// Hash arbitrary data to `n` number of scalars as specified in BBS specification [section Hash to scalar](https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-hash-to-scalar).
/// Hashes a byte string of arbitrary length into one or more elements of
/// `Self`, using [`ExpandMessage`] variant `X`.
pub(crate) fn do_hash_to_scalar<C, X>(
    msg_octets: &[u8],
    count: usize,
    dst_octets: Option<&[u8]>,
) -> Result<Vec<Scalar>, Error>
where
    C: BbsCiphersuiteParameters<'static>,
    X: ExpandMessage,
{
    let len_in_bytes = count * XOF_NO_OF_BYTES;
    let default_hash_to_scalar_dst = C::default_hash_to_scalar_dst();
    let dst_octets = dst_octets.unwrap_or(&default_hash_to_scalar_dst);

    if !dst_octets.is_ascii() {
        return Err(Error::BadParams {
            cause: "non-ascii dst".to_owned(),
        });
    }

    let mut t = 0;
    loop {
        if t == MAX_VALUE_GENERATION_RETRY_COUNT {
            return Err(Error::MaxRetryReached);
        }
        let msg_prime = [
            [msg_octets, &i2osp(t as u64, 1)?].concat(),
            i2osp(count as u64, 4)?,
        ]
        .concat();

        let mut expander = X::init_expand(&msg_prime, dst_octets, len_in_bytes);

        let mut buf = [0u8; 64];
        let output = (0..count)
            .map(|_| {
                expander.read_into(&mut buf[16..]);
                Scalar::from_wide_bytes_be_mod_r(&buf)
            })
            .collect::<Vec<Scalar>>();

        if output.iter().any(|item| item.is_zero().unwrap_u8() == 1u8) {
            t += 1;
            continue;
        }
        return Ok(output);
    }
}

/// Utility function to create random `Scalar` values using `hash_to_scalar`
/// function.
pub(crate) fn create_random_scalar<R, C>(mut rng: R) -> Result<Scalar, Error>
where
    R: RngCore,
    C: BbsCiphersuiteParameters<'static>,
{
    let mut raw = [0u8; 32];
    rng.fill_bytes(&mut raw[..]);
    Ok(C::hash_to_scalar(&raw, 1, None)?[0])
}

/// A convenient wrapper over underlying `hash_to_curve_g1` implementation(from
/// pairing lib) which is used in `Generators` creation.
pub(crate) fn do_create_generators<C, X>(
    count: usize,
    generator_seed: Option<&[u8]>,
    generator_seed_dst: Option<&[u8]>,
    generator_dst: Option<&[u8]>,
) -> Result<Vec<G1Projective>, Error>
where
    C: BbsCiphersuiteParameters<'static>,
    X: ExpandMessage,
{
    let default_generator_seed = C::generator_seed();
    let generator_seed = generator_seed.unwrap_or(&default_generator_seed);
    let default_generator_seed_dst = C::generator_seed_dst();
    let generator_seed_dst =
        generator_seed_dst.unwrap_or(&default_generator_seed_dst);
    let default_generator_dst = C::generator_dst();
    let generator_dst = generator_dst.unwrap_or(&default_generator_dst);

    let mut points = Vec::with_capacity(count);

    //  v = expand_message(generator_seed, seed_dst, seed_len)
    let mut expander =
        X::init_expand(generator_seed, generator_seed_dst, XOF_NO_OF_BYTES);
    let mut v = [0u8; XOF_NO_OF_BYTES];
    expander.read_into(&mut v);

    let mut n = 1;

    let mut i = 0;
    while i < count {
        // v = expand_message(v || I2OSP(n, 4), seed_dst, seed_len)
        let mut expander = X::init_expand(
            &[v.as_ref(), &i2osp(n, 4)?].concat(),
            generator_seed_dst,
            XOF_NO_OF_BYTES,
        );
        expander.read_into(&mut v);

        n += 1;

        // candidate = hash_to_curve_g1(v, generator_dst)
        let candidate = G1Projective::hash_to::<X>(&v, generator_dst);

        if (candidate.is_identity().unwrap_u8() == 1)
            || candidate == C::p1()
            || points.iter().any(|e| e == &candidate)
        {
            continue;
        }

        points.push(candidate);
        i += 1;
    }
    Ok(points)
}
