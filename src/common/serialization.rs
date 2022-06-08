use digest::generic_array::{ArrayLength, GenericArray};

use crate::error::Error;

// Implementation of I2OSP() function defined in RFC8017.
pub(crate) fn i2osp<L: ArrayLength<u8>>(
    integer: usize,
) -> Result<GenericArray<u8, L>, Error> {
    const SIZEOF_USIZE: usize = core::mem::size_of::<usize>();

    // Make sure input fits in output.
    if (SIZEOF_USIZE as u32 - integer.leading_zeros() / 8) > L::U32 {
        return Err(Error::Serde);
    }

    let mut output = GenericArray::default();
    // copy big-endian bytes
    output[L::USIZE.saturating_sub(SIZEOF_USIZE)..].copy_from_slice(
        &integer.to_be_bytes()[SIZEOF_USIZE.saturating_sub(L::USIZE)..],
    );
    Ok(output)
}
