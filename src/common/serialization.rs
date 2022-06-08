use crate::error::Error;

/// Implementation of I2OSP() function defined in RFC8017.
// Messages can have size of (2^64-1) bytes, so support direct encoding of u64
// prmitivies.
pub(crate) fn i2osp(
    integer: u64,
    octet_length: usize,
) -> Result<Vec<u8>, Error> {
    if octet_length == 0 {
        return Err(Error::Serde);
    }
    if integer as u128 >= (1 << (8 * octet_length) as u128) {
        return Err(Error::Serde);
    }

    if octet_length <= core::mem::size_of::<u64>() {
        return Ok((&integer.to_be_bytes()
            [core::mem::size_of::<u64>() - octet_length..])
            .to_vec());
    }

    let mut output = vec![0u8; octet_length];
    output.splice(
        octet_length - core::mem::size_of::<u64>()..octet_length,
        integer.to_be_bytes().iter().cloned(),
    );
    Ok(output)
}

/// Helper function to compute "I2OSP(len(input), octent_length) || input".
pub(crate) fn i2osp_with_data(
    input: &[u8],
    octent_length: usize,
) -> Result<Vec<u8>, Error> {
    Ok([&i2osp(input.len() as u64, octent_length)?, input].concat())
}

#[cfg(test)]
mod tests {
    use super::{i2osp, i2osp_with_data};

    #[test]
    fn i2osp_conversions() {
        assert!(i2osp(1, 0).is_err());

        assert!(i2osp(255, 1).is_ok());
        assert!(i2osp(256, 1).is_err());

        assert!(i2osp(1000, 2).is_ok());
        assert!(i2osp(1000, 10).is_ok());

        assert!(i2osp_with_data(&[0x01, 0x02, 0x03], 8).is_ok())
    }
}
