use core::fmt::Debug;

pub(crate) trait CipherSuiteParameter: Debug + Clone {
    /// Ciphersuite ID.
    const ID: CipherSuiteId;
}

/// Ciphersuite ID.
pub(crate) enum CipherSuiteId {
    BbsBls12381G1XmdSha256,
    BbsBls12381G1XofShake256,
    BlsSigBls12381G2XmdSha256Nul,
    BlsSigBls12381G2XmdSha256Aug,
    BlsSigBls12381G2XmdSha256Pop,
}

impl CipherSuiteId {
    /// Convert to a String represenation.
    pub(crate) fn as_octets(&self) -> &[u8] {
        match &self {
            CipherSuiteId::BbsBls12381G1XmdSha256 => {
                b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_"
            }
            CipherSuiteId::BbsBls12381G1XofShake256 => {
                b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_"
            }
            CipherSuiteId::BlsSigBls12381G2XmdSha256Nul => {
                b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
            }
            CipherSuiteId::BlsSigBls12381G2XmdSha256Aug => {
                b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_"
            }
            CipherSuiteId::BlsSigBls12381G2XmdSha256Pop => {
                b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
            }
        }
    }
}
