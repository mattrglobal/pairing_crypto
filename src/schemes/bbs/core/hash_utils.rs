use super::constants::{
    MAX_DST_SIZE,
    MAX_MESSAGE_SIZE,
    MAX_VALUE_GENERATION_RETRY_COUNT,
    XOF_NO_OF_BYTES,
};
use crate::{curves::bls12_381::Scalar, error::Error};
use ff::Field;
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
    // Number of bytes specified to encode length of a message octet string
    const MESSAGE_LENGTH_ENCODING_LENGTH: usize = 8;
    // Number of bytes specified to encode length of a dst octet string
    const DST_LENGTH_ENCODING_LENGTH: usize = 1;

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
    let msg_prime = i2osp_with_data(msg, MESSAGE_LENGTH_ENCODING_LENGTH)?;

    // dst_prime = I2OSP(len(dst), 1) || dst
    let dst_prime = i2osp_with_data(dst, 1)?;

    // hash_to_scalar(msg_prime || dst_prime, 1)
    Ok(hash_to_scalar([msg_prime, dst_prime].concat(), 1)?[0])
}

/// Hash arbitrary data to `n` number of scalars as specified in [3.3.10. Hash to scalar](https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-hash-to-scalar).
pub(crate) fn hash_to_scalar<T>(
    msg_octets: T,
    n: usize,
) -> Result<Vec<Scalar>, Error>
where
    T: AsRef<[u8]>,
{
    let mut i = 0;
    let mut scalars = Vec::with_capacity(n);

    let mut hasher = Shake256::default();
    hasher.update(msg_octets);
    let mut xof_reader = hasher.finalize_xof();

    // Note: If Scalar conversion from hashed data is failing continuously or
    // continuously Zero Scalar is returned from underlying implementation,
    // this loop will iterate infinetly.
    while i < n {
        let mut data_to_hash = [0u8; XOF_NO_OF_BYTES];
        let mut retry_count = 0;
        loop {
            xof_reader.read(&mut data_to_hash);
            let s = Scalar::from_bytes_wide(&data_to_hash);
            if s.is_some().unwrap_u8() == 1u8 {
                let s = s.unwrap();
                if s.is_zero().unwrap_u8() == 1u8 {
                    retry_count += 1;
                    continue;
                }
                scalars.push(s);
            } else {
                retry_count += 1;
                continue;
            }
            if retry_count == MAX_VALUE_GENERATION_RETRY_COUNT {
                return Err(Error::CryptoMaxRetryReached);
            }
        }
        i += 1;
    }
    Ok(scalars)
}
