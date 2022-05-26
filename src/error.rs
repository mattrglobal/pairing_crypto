/// Error enumerates all possible errors occuring in this library.
/// An error returned by the crypto component.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Error {
    /// Invalid arguments are provided in an API call.
    BadParams { cause: String },

    /// A conversion between compatible data types failed.
    Conversion { cause: String },

    /// A generic failure during underlying cryptographic operation.
    CryptoOps { cause: String },

    /// IKM data size is not valid.
    CryptoInvalidIkmLength,

    /// Type encoding is malformed.
    CryptoBadEncoding,

    /// Point is not on underlying curve.
    CryptoPointNotOnCurve,

    /// Point is not in underlying group.
    CryptoPointNotOnGroup,

    /// Scalar is invalid.
    CryptoBadScalar,

    /// A failure occured during Schnorr challenge computation.
    CryptoSchnorrChallengeComputation { cause: String },

    /// Secret key is not valid.
    CryptoInvalidSecretKey,

    /// Public key is malformed.
    CryptoMalformedPublicKey,

    /// Signature is malformed.
    CryptoMalformedSignature { cause: String },

    /// Proof is malformed.
    CryptoMalformedProof,

    /// Not enough message generators.
    CryptoNotEnoughMessageGenerators { generators: usize, messages: usize },

    /// Signature verification failed.
    CryptoSignatureVerification,

    /// Error during serialization deserialization in Serde.
    Serde,
}

impl std::error::Error for Error {}

impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Error::BadParams { ref cause } => {
                write!(f, "bad arguments: cause: {}", cause)
            }
            Error::Conversion { ref cause } => {
                write!(f, "data conversion failed: cause: {}", cause)
            }
            Error::CryptoOps { ref cause } => {
                write!(
                    f,
                    "unexpected failure in cryptographic operation: cause {}",
                    cause
                )
            }
            Error::CryptoInvalidIkmLength => {
                write!(f, "IKM size is too short.")
            }
            Error::CryptoBadEncoding => {
                write!(f, "bad encoding encountered.")
            }
            Error::CryptoPointNotOnCurve => {
                write!(f, "point is not on underlying curve.")
            }
            Error::CryptoPointNotOnGroup => {
                write!(f, "point is not in underlying group.")
            }
            Error::CryptoBadScalar => write!(f, "scalar is invalid."),
            Error::Serde => write!(f, "error during ser-de operation."),
            Error::CryptoSchnorrChallengeComputation { ref cause } => {
                write!(
                    f,
                    "schnorr challenge computation failed: cause: {}",
                    cause
                )
            }
            Error::CryptoInvalidSecretKey => {
                write!(f, "secret key is not valid.")
            }
            Error::CryptoMalformedPublicKey => {
                write!(f, "public key is malformed.")
            }
            Error::CryptoMalformedSignature { ref cause } => {
                write!(f, "signature is malformed: cause: {}", cause)
            }
            Error::CryptoMalformedProof => {
                write!(f, "proof is malformed.")
            }
            Error::CryptoNotEnoughMessageGenerators {
                generators,
                messages,
            } => {
                write!(
                    f,
                    "not enough generators, #generators: {}, #messages: {}.",
                    generators, messages
                )
            }
            Error::CryptoSignatureVerification => {
                write!(f, "bad encoding encountered.")
            }
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}
