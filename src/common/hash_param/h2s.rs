use blstrs::hash_to_curve::ExpandMessageState;
use ff::Field;

use crate::{
    common::serialization::i2osp,
    curves::bls12_381::{
        hash_to_curve::InitExpandMessage,
        Scalar,
        OCTET_SCALAR_LENGTH,
    },
    Error,
};

use super::{
    constant::{
        MAX_DST_SIZE,
        MAX_MESSAGE_SIZE,
        MAX_VALUE_GENERATION_RETRY_COUNT,
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
        dst: Option<&[u8]>,
    ) -> Result<Scalar, Error> {
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
            let msg_prime = [msg_octets, &i2osp(t as u64, 1)?].concat();

            let mut expander = Self::Expander::init_expand(
                &msg_prime,
                dst_octets,
                XOF_NO_OF_BYTES,
            );

            let mut buf = [0u8; 64];
            expander.read_into(&mut buf[16..]);
            let out_scalar = Scalar::from_wide_bytes_be_mod_r(&buf);

            if out_scalar.is_zero().unwrap_u8() == 1u8 {
                t += 1;
                continue;
            }
            return Ok(out_scalar);
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

        // hash_to_scalar(message || dst_prime, 1)
        Ok(Self::hash_to_scalar(message, Some(dst))?)
    }

    /// Hash the input octets to 2 scalar values representing the e and s
    /// components of a BBS signature.
    fn hash_to_e_s(input_octets: &[u8]) -> Result<(Scalar, Scalar), Error> {
        let e_s_dst = [Self::ID.as_octets(), b"SIG_DET_DST_"].concat();
        let mut expander = Self::Expander::init_expand(
            input_octets,
            &e_s_dst,
            2 * OCTET_SCALAR_LENGTH,
        );

        // 32 pseudo-random bytes will be used for each scalar.
        let mut buf = [0u8; OCTET_SCALAR_LENGTH];

        // calculate e
        expander.read_into(&mut buf);
        let e = Self::hash_to_scalar(&buf, None)?;

        // calculate s
        expander.read_into(&mut buf);
        let s = Self::hash_to_scalar(&buf, None)?;

        Ok((e, s))
    }
}
