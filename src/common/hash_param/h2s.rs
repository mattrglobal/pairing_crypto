use blstrs::hash_to_curve::ExpandMessageState;

use crate::{
    curves::bls12_381::{hash_to_curve::InitExpandMessage, Scalar},
    Error,
};

use super::{
    constant::{DEFAULT_DST_SUFFIX_H2S, XOF_NO_OF_BYTES},
    ExpandMessageParameter,
};

pub(crate) trait HashToScalarParameter: ExpandMessageParameter {
    /// Default domain separation tag for `hash_to_scalar` operation.
    fn default_hash_to_scalar_dst() -> Vec<u8> {
        [Self::ID.as_octets(), DEFAULT_DST_SUFFIX_H2S.as_bytes()].concat()
    }

    // /// Default domain separation tag to be used in [MapMessageToScalarAsHash](https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-mapmessagetoscalarashash).
    // fn default_map_message_to_scalar_as_hash_dst() -> Vec<u8> {
    //     [
    //         Self::ID.as_octets(),
    //         DEFAULT_DST_SUFFIX_MESSAGE_TO_SCALAR.as_bytes(),
    //     ]
    //     .concat()
    // }

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
        let mut expander = Self::Expander::init_expand(
            msg_octets,
            dst_octets,
            XOF_NO_OF_BYTES,
        );

        let mut buf = [0u8; 64];
        expander.read_into(&mut buf[16..]);
        let out_scalar = Scalar::from_wide_bytes_be_mod_r(&buf);

        Ok(out_scalar)
    }
}
