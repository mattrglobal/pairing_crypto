pub use blstrs::*;

/// Number of bytes to store a scalar.
pub(crate) const OCTET_SCALAR_LENGTH: usize = 32;

/// Number of bytes to store an element of G1 in affine and compressed form.
pub(crate) const OCTET_POINT_G1_LENGTH: usize = 48;

/// Number of bytes to store an element of G2 in affine and compressed form.
pub(crate) const OCTET_POINT_G2_LENGTH: usize = 96;
