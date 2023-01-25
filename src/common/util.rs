use super::hash_param::constant::XOF_NO_OF_BYTES;
use crate::{curves::bls12_381::Scalar, error::Error};
use rand::RngCore;

#[macro_export]
/// Print an array of bytes as hex string.
macro_rules! print_byte_array {
    ($formatter:ident, $byte_array:expr) => {
        for &b in $byte_array.iter() {
            write!($formatter, "0x")?;
            write!($formatter, "{:02x}", b)?;
        }
    };
}

pub fn vec_to_byte_array<const N: usize>(
    vec: &Vec<u8>,
) -> Result<[u8; N], Error> {
    use core::convert::TryFrom;
    let data_len = vec.len();
    match <[u8; N]>::try_from(vec.clone()) {
        Ok(result) => Ok(result),
        Err(_) => Err(Error::Conversion {
            cause: format!(
                "source vector size {data_len}, expected destination byte \
                 array size {N}",
            ),
        }),
    }
}

/// Utility function to create random `Scalar` values using `hash_to_scalar`
/// function.
pub(crate) fn create_random_scalar<R>(mut rng: R) -> Result<Scalar, Error>
where
    R: RngCore,
{
    let mut raw = [0u8; 64];
    rng.fill_bytes(&mut raw[64 - XOF_NO_OF_BYTES..]);
    Ok(Scalar::from_wide_bytes_be_mod_r(&raw))
}
