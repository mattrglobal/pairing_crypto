use blstrs::hash_to_curve::ExpandMessageState;

use crate::{
    curves::bls12_381::{hash_to_curve::InitExpandMessage, Scalar},
    Error,
};

use super::{constant::XOF_NO_OF_BYTES, ExpandMessageParameter};

pub(crate) trait HashToScalarParameter: ExpandMessageParameter {
    /// Hash arbitrary data to `n` number of scalars as specified in BBS
    /// specification.
    fn hash_to_scalar(msg_octets: &[u8], dst: &[u8]) -> Result<Scalar, Error> {
        if !dst.is_ascii() {
            return Err(Error::BadParams {
                cause: "non-ascii dst".to_owned(),
            });
        }
        let mut expander =
            Self::Expander::init_expand(msg_octets, dst, XOF_NO_OF_BYTES);

        let mut buf = [0u8; 64];
        expander.read_into(&mut buf[16..]);
        let out_scalar = Scalar::from_wide_bytes_be_mod_r(&buf);

        Ok(out_scalar)
    }
}
