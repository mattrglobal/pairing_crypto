use super::hash_param::constant::XOF_NO_OF_BYTES;
use crate::{curves::bls12_381::Scalar, error::Error};
use rand::RngCore;

// Print an array of bytes as hex string.
macro_rules! print_byte_array {
    ($formatter:ident, $byte_array:expr) => {
        for &b in $byte_array.iter() {
            write!($formatter, "0x")?;
            write!($formatter, "{:02x}", b)?;
        }
    };
}

pub(crate) use print_byte_array;

pub fn vec_to_byte_array<const N: usize>(vec: &[u8]) -> Result<[u8; N], Error> {
    let data_len = vec.len();
    match <[u8; N]>::try_from(vec.to_owned()) {
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
    // Init a 64 bytes buffer required by the Scalar interface (we will
    // need a buffer with at least 48 bytes).
    let mut raw = [0u8; 64];
    // Populate the 48 rightmost bytes (the buffer will need to be in
    // big endian order). 48 bytes are needed to avoid biased results.
    rng.fill_bytes(&mut raw[64 - XOF_NO_OF_BYTES..]);
    // Calculate the random scalar by mapping the buffer to an integer
    // and moding the result.
    Ok(Scalar::from_wide_bytes_be_mod_r(&raw))
}
