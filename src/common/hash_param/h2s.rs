use ff::Field;
use rand::RngCore;

use crate::{
    common::serialization::{i2osp, i2osp_with_data},
    curves::bls12_381::{
        hash_to_curve::{ExpandMessageState, InitExpandMessage},
        Scalar,
    },
    Error,
};

use super::{
    constant::{
        MAX_DST_SIZE,
        MAX_MESSAGE_SIZE,
        MAX_VALUE_GENERATION_RETRY_COUNT,
        NON_NEGATIVE_INTEGER_ENCODING_LENGTH,
        XOF_NO_OF_BYTES,
    },
    ExpandMessageParameter,
};

pub(crate) trait HashToScalarParameter: ExpandMessageParameter {
    /// Default domain separation tag for `hash_to_scalar` operation.
    fn default_hash_to_scalar_dst() -> Vec<u8> {
        [Self::ID.as_octets(), b"H2S_"].concat()
    }

    /// Default domain separation tag to be used in [MapMessageToScalarAsHash](https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-mapmessagetoscalarashash).
    fn default_map_message_to_scalar_as_hash_dst() -> Vec<u8> {
        [Self::ID.as_octets(), b"MAP_MSG_TO_SCALAR_AS_HASH_"].concat()
    }

    /// Hash arbitrary data to `n` number of scalars as specified in BBS
    /// specification.
    fn hash_to_scalar(
        msg_octets: &[u8],
        count: usize,
        dst: Option<&[u8]>,
    ) -> Result<Vec<Scalar>, Error> {
        let len_in_bytes = count * XOF_NO_OF_BYTES;
        let default_hash_to_scalar_dst = Self::default_hash_to_scalar_dst();
        let dst_octets = dst.unwrap_or(&default_hash_to_scalar_dst);

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
            let msg_prime =
                [msg_octets, &i2osp(t as u64, 1)?, &i2osp(count as u64, 4)?]
                    .concat();

            let mut expander = Self::Expander::init_expand(
                &msg_prime,
                dst_octets,
                len_in_bytes,
            );

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

    /// Hash arbitrary data to a scalar as specified in [3.3.9.1 Hash to scalar](https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-mapmessagetoscalarashash).
    fn map_message_to_scalar_as_hash(
        message: &[u8],
        dst: Option<&[u8]>,
    ) -> Result<Scalar, Error> {
        let default_map_message_to_scalar_as_hash_dst =
            Self::default_map_message_to_scalar_as_hash_dst();
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
        Ok(Self::hash_to_scalar(&msg_prime, 1, Some(dst))?[0])
    }
}

/// Utility function to create random `Scalar` values using `hash_to_scalar`
/// function.
pub(crate) fn create_random_scalar<R, C>(mut rng: R) -> Result<Scalar, Error>
where
    R: RngCore,
    C: HashToScalarParameter,
{
    let mut raw = [0u8; 32];
    rng.fill_bytes(&mut raw[..]);
    Ok(C::hash_to_scalar(&raw, 1, None)?[0])
}
