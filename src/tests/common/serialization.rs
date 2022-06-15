use crate::common::serialization::{i2osp, i2osp_with_data};

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
