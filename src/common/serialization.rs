use crate::error::Error;

/// Implementation of I2OSP() function defined in RFC8017.
// Messages can have size of (2^64-1) bytes, so support direct encoding of u64
// prmitivies.
// TODO make it constant time
pub(crate) fn i2osp(
    integer: u64,
    octet_length: usize,
) -> Result<Vec<u8>, Error> {
    // As per spec, maximum bytes to encode lengths is 8
    if octet_length == 0 || octet_length > 8 {
        return Err(Error::Serde);
    }
    if integer as u128 >= (1 << (8 * octet_length) as u128) {
        return Err(Error::Serde);
    }

    Ok(
        (&integer.to_be_bytes()[core::mem::size_of::<u64>() - octet_length..])
            .to_vec(),
    )
}

/// Helper function to compute "I2OSP(len(input), octent_length) || input".
pub(crate) fn i2osp_with_data(
    input: &[u8],
    octent_length: usize,
) -> Result<Vec<u8>, Error> {
    Ok([&i2osp(input.len() as u64, octent_length)?, input].concat())
}
