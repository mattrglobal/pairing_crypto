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

    /// Maximum defined retry reached for a crypto operation.
    /// For example, during a `HashToCurve` or `HashToScalar` operation, where
    /// we loop infinetly to produce a number of valid `Point` or `Scalar`,
    /// this error is returned if maximum retry is hit during production of
    /// single value.
    CryptoMaxRetryReached,

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

    /// Maximum valid message size in octets is (2^64 -1) as per BBS signature
    /// specification.
    CryptoMessageIsTooLarge,

    /// Maximum valid domain separation tag size in octets is (2^8 -1) as per
    /// BBS signature specification.
    CryptoDstIsTooLarge,

    /// Hast-to-field operation failed.
    CryptoHashToFieldConversion,

    /// A failure occured during Schnorr challenge computation.
    CryptoSchnorrChallengeComputation { cause: String },

    /// Secret key is not valid.
    CryptoInvalidSecretKey,

    /// Public key is not valid.
    CryptoInvalidPublicKey,

    /// Message signing failed.
    CryptoSigning { cause: String },

    /// Signature is malformed.
    CryptoMalformedSignature { cause: String },

    /// Proof is malformed.
    CryptoMalformedProof { cause: String },

    /// Not enough message generators.
    CryptoMessageGeneratorsLengthMismatch { generators: usize, messages: usize },

    /// The given point(from `G1` or `G2`) is an `Identity` element of
    /// respective subgroup.
    CryptoPointIsIdentity,

    /// The given `Scalar` is `Zero`.
    CryptoScalarIsZero,

    /// Signature verification failed.
    CryptoSignatureVerification,

    /// Proof verification failed.
    CryptoProoferification,

    /// Error during serialization deserialization.
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
            Error::CryptoMaxRetryReached => {
                write!(f, "max allowed retry is reached.")
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
            Error::CryptoMessageIsTooLarge => {
                write!(f, "max valid size is (2^64 - 1) bytes.")
            }
            Error::CryptoDstIsTooLarge => {
                write!(f, "max valid size is (2^8 - 1) bytes.")
            }
            Error::CryptoHashToFieldConversion => {
                write!(f, "hash to field conversion failed.")
            }

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
            Error::CryptoInvalidPublicKey => {
                write!(f, "public key is invalid.")
            }
            Error::CryptoSigning { ref cause } => {
                write!(f, "signing failed: cause: {}", cause)
            }
            Error::CryptoMalformedSignature { ref cause } => {
                write!(f, "signature is malformed: cause: {}", cause)
            }
            Error::CryptoMalformedProof { ref cause } => {
                write!(f, "proof is malformed: cause: {}", cause)
            }
            Error::CryptoMessageGeneratorsLengthMismatch {
                generators,
                messages,
            } => {
                write!(
                    f,
                    "not enough generators, #generators: {}, #messages: {}.",
                    generators, messages
                )
            }
            Error::CryptoPointIsIdentity => {
                write!(f, "unexpected `Identity` element.")
            }
            Error::CryptoScalarIsZero => {
                write!(f, "unexpected `Zero` element.")
            }
            Error::CryptoProoferification => {
                write!(f, "proof verification failed.")
            }
            Error::CryptoSignatureVerification => {
                write!(f, "signature verification failed.")
            }
            Error::Serde => write!(f, "error during ser-de operation."),
        }
    }
}

impl From<core::array::TryFromSliceError> for Error {
    fn from(_: core::array::TryFromSliceError) -> Self {
        Error::Conversion {
            cause: "slice to sized-array conversion".to_owned(),
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}
