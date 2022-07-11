/// Maximum retry count to generate a single Scalar or G1 point value.
pub(crate) const MAX_VALUE_GENERATION_RETRY_COUNT: usize = 5;

/// BLS12-381 Ciphersuite ID.
pub(crate) const BBS_CIPHERSUITE_ID: &[u8; 37] =
    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_";

/// DST for `hash_to_scalar` operation.
pub(crate) const HASH_TO_SCALAR_DST: &[u8; 55] =
    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_HASH_TO_SCALAR_DST";

/// Domain separation tag to be used in [MapMessageToScalarAsHash](https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-mapmessagetoscalarashash).
pub(crate) const MAP_MESSAGE_TO_SCALAR_DST: &[u8; 54] =
    b"BBS-MESSAGE-HASH-BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_";

/// A seed value with global scope for `generator_seed` as defined in
/// BBS signature Spec which is used by the `create_generators ` operation to
/// compute the required set of message generators.
pub(crate) const GENERATOR_SEED: &[u8; 59] =
    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_MESSAGE_GENERATOR_SEED";

// /// Generator DST which is used by the `create_generators ` operation.
pub(crate) const GENERATOR_DST: &[u8; 55] =
    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_SIG_GENERATOR_DST_";

// Seed DST which is used by the `create_generators ` operation.
pub(crate) const SEED_DST: &[u8; 56] =
    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_SIG_GENERATOR_SEED_";

/// Number of bytes to draw from the XOF when generating Scalars or Generators.
pub(crate) const XOF_NO_OF_BYTES: usize = 48usize;

/// Maximum allowed DST size in bytes as per BBS Signature specification.
/// <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-encoding-of-elements-to-be->
pub(crate) const MAX_DST_SIZE: u8 = u8::MAX - 1;

/// Maximum allowed message size in bytes as per BBS Signature specification.
/// <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-encoding-of-elements-to-be->
pub(crate) const MAX_MESSAGE_SIZE: u64 = u64::MAX - 1;

/// Number of bytes specified to encode length of a message octet string. This
/// value is used in `i2osp` call.
pub(crate) const OCTETS_MESSAGE_LENGTH_ENCODING_LENGTH: usize = 8;

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
