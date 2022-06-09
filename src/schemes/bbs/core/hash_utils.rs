use super::constants::{
    DST_LENGTH_ENCODING_LENGTH,
    HASH_TO_CURVE_G1_DST,
    MAX_DST_SIZE,
    MAX_MESSAGE_SIZE,
    MAX_VALUE_GENERATION_RETRY_COUNT,
    OCTETS_MESSAGE_LENGTH_ENCODING_LENGTH,
    XOF_NO_OF_BYTES,
};
use crate::{
    common::serialization::i2osp_with_data,
    curves::bls12_381::{G1Projective, Scalar},
    error::Error,
};
use ff::Field;
use group::Group;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

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
        return Err(Error::CryptoMessageIsTooLarge);
    }
    if dst.len() > MAX_DST_SIZE as usize {
        return Err(Error::CryptoDstIsTooLarge);
    }

    // msg_prime = I2OSP(len(msg), 8) || msg
    let msg_prime =
        i2osp_with_data(msg, OCTETS_MESSAGE_LENGTH_ENCODING_LENGTH)?;

    // dst_prime = I2OSP(len(dst), 1) || dst
    let dst_prime = i2osp_with_data(dst, DST_LENGTH_ENCODING_LENGTH)?;

    // hash_to_scalar(msg_prime || dst_prime, 1)
    Ok(hash_to_scalar([msg_prime, dst_prime].concat(), 1)?[0])
}

/// Hash arbitrary data to `n` number of scalars as specified in [3.3.10. Hash to scalar](https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-hash-to-scalar).
// TODO make const time
pub(crate) fn hash_to_scalar<T>(
    msg_octets: T,
    n: usize,
) -> Result<Vec<Scalar>, Error>
where
    T: AsRef<[u8]>,
{
    // Return early if no Scalar need to be produced
    if n == 0 {
        return Ok(vec![]);
    }
    let mut i = 0;
    let mut scalars = Vec::with_capacity(n);

    let mut hasher = Shake256::default();
    hasher.update(msg_octets);
    let mut xof_reader = hasher.finalize_xof();

    while i < n {
        let mut data_to_hash = [0u8; XOF_NO_OF_BYTES];
        let mut retry_count = 0;
        loop {
            if retry_count == MAX_VALUE_GENERATION_RETRY_COUNT {
                return Err(Error::CryptoMaxRetryReached);
            }
            xof_reader.read(&mut data_to_hash);
            let s = Scalar::from_bytes_wide(&data_to_hash);
            if s.is_some().unwrap_u8() == 1u8 {
                let s = s.unwrap();
                if s.is_zero().unwrap_u8() == 1u8 {
                    retry_count += 1;
                    continue;
                }
                scalars.push(s);
                break;
            } else {
                retry_count += 1;
                continue;
            }
        }
        i += 1;
    }
    Ok(scalars)
}

/// A convenient wrapper over underlying `hash_to_curve_g1` implementation(from
/// pairing lib) to use during `Generators` value generation.
// TODO make const time
pub(crate) fn hash_to_curve_g1<T>(
    seed: T,
    n: usize,
) -> Result<Vec<G1Projective>, Error>
where
    T: AsRef<[u8]>,
{
    // Return early if no Point need to be produced
    if n == 0 {
        return Ok(vec![]);
    }
    let mut i = 0;
    let mut points = Vec::with_capacity(n);

    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut xof_reader = hasher.finalize_xof();

    while i < n {
        let mut data_to_hash = [0u8; XOF_NO_OF_BYTES];
        let mut retry_count = 0;
        loop {
            if retry_count == MAX_VALUE_GENERATION_RETRY_COUNT {
                return Err(Error::CryptoMaxRetryReached);
            }
            xof_reader.read(&mut data_to_hash);
            let p = G1Projective::hash_to_curve(
                &data_to_hash,
                HASH_TO_CURVE_G1_DST,
                &[],
            );
            // Spec doesn't define P1
            let p1 = G1Projective::generator();
            if (p.is_identity().unwrap_u8() == 1) || p == p1 {
                retry_count += 1;
                continue;
            }
            points.push(p);
            break;
        }
        i += 1;
    }
    Ok(points)
}
