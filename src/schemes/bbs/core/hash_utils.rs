use super::constants::{MAX_DST_SIZE, MAX_MESSAGE_SIZE, XOF_NO_OF_BYTES};
use crate::{curves::bls12_381::Scalar, error::Error};
use digest::consts::{U1, U8};
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
    let msg_len = i2osp::<U8>(msg.len())?;
    let msg_prime = [&msg_len, msg].concat();

    // dst_prime = I2OSP(len(dst), 1) || dst
    let dst_len = i2osp::<U1>(dst.len())?;
    let dst_prime = [&dst_len, dst].concat();

    // hash_to_scalar(msg_prime || dst_prime, 1)
    let data_to_hash = [msg_prime, dst_prime].concat();
    Ok(hash_to_scalar(data_to_hash, 1)[0])
}

/// Hash arbitrary data to `n` number of scalars as specified in [3.3.10. Hash to scalar](https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-hash-to-scalar).
pub(crate) fn hash_to_scalar<T>(msg_octets: T, n: usize) -> Vec<Scalar>
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
        xof_reader.read(&mut data_to_hash);
        // todo change byte_wide implementation to be
        let s = Scalar::from_bytes_wide(&data_to_hash);
        if s.is_some().unwrap_u8() == 1u8 {
            let s = s.unwrap();
            if s.is_zero().unwrap_u8() == 1u8 {
                continue;
            }
            scalars.push(s);
            i += 1;
        } else {
            continue;
        }
    }
    scalars
}
