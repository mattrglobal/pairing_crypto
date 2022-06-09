use crate::error::Error;

/// Implementation of I2OSP() function defined in RFC8017.
// Messages can have size of (2^64-1) bytes, so support direct encoding of u64
// prmitivies.
// TODO make it constant time
pub(crate) fn i2osp(
    integer: u64,
    octet_length: usize,
) -> Result<Vec<u8>, Error> {
    println!("{} - {}", integer, octet_length);
    // As per spec, maximum bytes to encode lengths is 8
    if octet_length == 0 || octet_length > 8 {
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
    fn i2osp_operation() {
        assert!(i2osp(1, 0).is_err());

        assert!(i2osp(0, 1).is_ok());
        assert!(i2osp(0, 8).is_ok());
        assert!(i2osp(0, 9).is_err());
        assert!(i2osp(0, 100).is_err());
        assert!(i2osp(0, 1000).is_err());

        assert!(i2osp(u8::MIN as u64, 1).is_ok());
        assert!(i2osp(u8::MAX as u64, 1).is_ok());
        assert!(i2osp(u8::MAX as u64 + 1, 1).is_err());

        assert!(i2osp(u16::MIN as u64, 2).is_ok());
        assert!(i2osp(u16::MAX as u64, 2).is_ok());
        assert!(i2osp(u16::MAX as u64 + 1, 2).is_err());

        assert!(i2osp(u32::MIN as u64, 4).is_ok());
        assert!(i2osp(u32::MAX as u64, 4).is_ok());
        assert!(i2osp(u32::MAX as u64 + 1, 4).is_err());

        assert!(i2osp(u64::MIN, 8).is_ok());
        assert!(i2osp(u64::MAX, 8).is_ok());

        assert!(i2osp(u64::MAX, 7).is_err());
        assert!(i2osp(u64::MAX, 2).is_err());
        assert!(i2osp(u64::MAX, 1).is_err());

        assert!(i2osp_with_data(&[0x01, 0x02, 0x03], 8).is_ok())
    }

    #[test]
    fn i2osp_conversion() {
        assert_eq!(i2osp(0, 1).unwrap(), vec![0x00]);
        assert_eq!(i2osp(1, 1).unwrap(), vec![0x01]);
        assert_eq!(i2osp(255, 1).unwrap(), vec![0xff]);

        assert_eq!(i2osp(0, 2).unwrap(), vec![0x00, 0x00]);
        assert_eq!(i2osp(1, 2).unwrap(), vec![0x00, 0x01]);
        assert_eq!(i2osp(255, 2).unwrap(), vec![0x00, 0xff]);
        assert_eq!(i2osp(256, 2).unwrap(), vec![0x1, 0x0]);
        assert_eq!(i2osp(65535, 2).unwrap(), vec![0xff, 0xff]);
    }

    #[test]
    fn i2osp_with_data_conversion() {
        let input_len_expected = [
            (
                b"test_data",
                1,
                [[9].as_slice(), b"test_data".as_slice()].concat(),
            ),
            (
                b"test_data",
                8,
                [[0, 0, 0, 0, 0, 0, 0, 9].as_slice(), b"test_data".as_slice()]
                    .concat(),
            ),
        ];

        for (input, len, expected) in input_len_expected {
            assert_eq!(i2osp_with_data(input, len).unwrap(), expected);
        }
    }
}
