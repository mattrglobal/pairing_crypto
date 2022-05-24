/// Number of bytes needed to represent the G1 element compressed form
pub const G1_COMPRESSED_SIZE: usize = 48;
/// Number of bytes needed to represent the the G2 element in compressed form
pub const G2_COMPRESSED_SIZE: usize = 96;

/// The number of bytes in a G1 commitment
pub const COMMITMENT_G1_BYTES: usize = G1_COMPRESSED_SIZE;
/// The number of bytes in a G2 commitment
pub const COMMITMENT_G2_BYTES: usize = G2_COMPRESSED_SIZE;
/// The number of bytes in a challenge or nonce
pub const FIELD_BYTES: usize = 32;
