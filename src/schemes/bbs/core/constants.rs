/// Maximum retry count to generate a single Scalar or G1 point value.
pub(crate) const MAX_VALUE_GENERATION_RETRY_COUNT: usize = 5;

/// Number of bytes to draw from the XOF when generating Scalars or Generators.
pub(crate) const XOF_NO_OF_BYTES: usize = 48usize;

/// Maximum allowed DST size in bytes as per BBS Signature specification.
/// <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-encoding-of-elements-to-be->
pub(crate) const MAX_DST_SIZE: u8 = u8::MAX - 1;

/// Maximum allowed message size in bytes as per BBS Signature specification.
/// <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-encoding-of-elements-to-be->
pub(crate) const MAX_MESSAGE_SIZE: u64 = u64::MAX - 1;

/// Number of bytes specified to encode length of a non-negative-integer. This
/// value is used in `i2osp` call.
pub(crate) const NON_NEGATIVE_INTEGER_ENCODING_LENGTH: usize = 8;

/// Number of bytes specified to encode length of a dst octet string.
pub(crate) const DST_LENGTH_ENCODING_LENGTH: usize = 1;

/// Number of bytes to store a scalar.
pub(crate) const OCTET_SCALAR_LENGTH: usize = 32;

/// Number of bytes to store an element of G1 in affine and compressed form.
pub(crate) const OCTET_POINT_G1_LENGTH: usize = 48;

/// Number of bytes to store an element of G2 in affine and compressed form.
pub(crate) const OCTET_POINT_G2_LENGTH: usize = 96;

/// Minimum length of key generation IKM data in bytes.
pub const MIN_KEY_GEN_IKM_LENGTH: usize = 32;

/// "SecretKey" length in bytes for "BBS_BLS12381G1" ciphersuite.
pub const BBS_BLS12381G1_SECRET_KEY_LENGTH: usize = OCTET_SCALAR_LENGTH;

/// "PublicKey" length in bytes for "BBS_BLS12381G1" ciphersuite.
pub const BBS_BLS12381G1_PUBLIC_KEY_LENGTH: usize = OCTET_POINT_G2_LENGTH;

/// "Signature" length in bytes for "BBS_BLS12381G1" ciphersuite.
pub const BBS_BLS12381G1_SIGNATURE_LENGTH: usize =
    OCTET_POINT_G1_LENGTH + 2 * OCTET_SCALAR_LENGTH;
