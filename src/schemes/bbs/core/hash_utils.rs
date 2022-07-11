use super::constants::{
    DST_LENGTH_ENCODING_LENGTH,
    GENERATOR_DST,
    GENERATOR_SEED,
    HASH_TO_SCALAR_DST,
    MAX_DST_SIZE,
    MAX_MESSAGE_SIZE,
    MAX_VALUE_GENERATION_RETRY_COUNT,
    OCTETS_MESSAGE_LENGTH_ENCODING_LENGTH,
    SEED_DST,
    XOF_NO_OF_BYTES,
};
use crate::{
    common::serialization::{i2osp, i2osp_with_data},
    curves::bls12_381::{
        hash_to_curve::{ExpandMessage, ExpandMessageState, ExpandMsgXof},
        G1Projective,
        Scalar,
    },
    error::Error,
};
use ff::Field;
use group::Group;
use sha3::Shake256;

/// Hash arbitrary data to a scalar as specified in [3.3.9.1 Hash to scalar](https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-mapmessagetoscalarashash).
pub(crate) fn map_message_to_scalar_as_hash<T>(
    msg: T,
    dst: T,
) -> Result<Scalar, Error>
where
    T: AsRef<[u8]>,
{
    let msg = msg.as_ref();
    let dst = dst.as_ref();
    // If len(dst) > 2^8 - 1 or len(msg) > 2^64 - 1, abort
    if msg.len() as u64 > MAX_MESSAGE_SIZE {
        return Err(Error::MessageIsTooLarge);
    }
    if dst.len() > MAX_DST_SIZE as usize {
        return Err(Error::DstIsTooLarge);
    }

    // msg_prime = I2OSP(len(msg), 8) || msg
    let msg_prime =
        i2osp_with_data(msg, OCTETS_MESSAGE_LENGTH_ENCODING_LENGTH)?;

    // dst_prime = I2OSP(len(dst), 1) || dst
    let dst_prime = i2osp_with_data(dst, DST_LENGTH_ENCODING_LENGTH)?;

    // hash_to_scalar(msg_prime || dst_prime, 1)
    Ok(hash_to_scalar::<ExpandMsgXof<Shake256>>(
        &[msg_prime, dst_prime].concat(),
        1,
    )?[0])
}

/// Hash arbitrary data to `n` number of scalars as specified in BBS specification [section Hash to scalar](https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-hash-to-scalar).
/// Hashes a byte string of arbitrary length into one or more elements of
/// `Self`, using [`ExpandMessage`] variant `X`.
pub(crate) fn hash_to_scalar<X: ExpandMessage>(
    msg_octets: &[u8],
    count: usize,
) -> Result<Vec<Scalar>, Error> {
    let len_in_bytes = count * XOF_NO_OF_BYTES;

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

        let mut expander =
            X::init_expand(&msg_prime, HASH_TO_SCALAR_DST, len_in_bytes);

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

/// A convenient wrapper over underlying `hash_to_curve_g1` implementation(from
/// pairing lib) which is used in `Generators` creation.
pub(crate) fn create_generators<X: ExpandMessage>(
    count: usize,
) -> Result<Vec<G1Projective>, Error> {
    // Spec doesn't define P1
    let p1 = G1Projective::generator();

    let mut points = Vec::with_capacity(count);

    //  v = expand_message(generator_seed, seed_dst, seed_len)
    let mut expander =
        X::init_expand(GENERATOR_SEED, SEED_DST, XOF_NO_OF_BYTES);
    let mut v = [0u8; XOF_NO_OF_BYTES];
    expander.read_into(&mut v);

    let mut n = 1;

    let mut i = 0;
    while i < count {
        // v = expand_message(v || I2OSP(n, 4), seed_dst, seed_len)
        let mut expander = X::init_expand(
            &[v.as_ref(), &i2osp(n, 4)?].concat(),
            SEED_DST,
            XOF_NO_OF_BYTES,
        );
        expander.read_into(&mut v);

        n += 1;

        // candidate = hash_to_curve_g1(v, generator_dst)
        let candidate = G1Projective::hash_to::<X>(&v, GENERATOR_DST);

        if (candidate.is_identity().unwrap_u8() == 1)
            || candidate == p1
            || points.iter().any(|e| e == &candidate)
        {
            continue;
        }

        points.push(candidate);
        i += 1;
    }
    Ok(points)
}
