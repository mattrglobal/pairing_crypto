pub fn vec_to_byte_array<const N: usize>(
    vec: Vec<u8>,
) -> Result<[u8; N], String> {
    use std::convert::TryFrom;
    match <[u8; N]>::try_from(vec) {
        Ok(result) => Ok(result),
        // TODO specify mismatch in length?
        Err(_) => Err("Input data length incorrect".to_string()),
    }
}
