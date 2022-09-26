/// Maximum retry count to generate a single Scalar or G1 point value.
pub(crate) const MAX_VALUE_GENERATION_RETRY_COUNT: usize = 5;

/// Number of bytes to draw from the XOF when generating Scalars or Generators.
pub(crate) const XOF_NO_OF_BYTES: usize = 48usize;

/// Maximum allowed DST size in bytes as per BBS Signature specification.
/// <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-encoding-of-elements-to-be->
pub(crate) const MAX_DST_SIZE: u8 = u8::MAX;

/// Maximum allowed message size in bytes as per BBS Signature specification.
/// <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-encoding-of-elements-to-be->
pub(crate) const MAX_MESSAGE_SIZE: u64 = u64::MAX;

/// Number of bytes specified to encode length of a non-negative-integer. This
/// value is used in `i2osp` call.
pub(crate) const NON_NEGATIVE_INTEGER_ENCODING_LENGTH: usize = 8;
