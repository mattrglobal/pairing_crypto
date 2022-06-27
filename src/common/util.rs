use crate::error::Error;

#[macro_export]
/// Print an array of bytes as hex string.
macro_rules! print_byte_array {
    ($formatter:ident, $byte_array:expr) => {
        for &b in $byte_array.iter() {
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
                "source vector size {}, expected destination byte array size \
                 {}",
                data_len, N
            ),
        }),
    }
}
