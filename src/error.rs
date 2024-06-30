/// Error enumerates all possible errors occuring in this library.
/// An error returned by the crypto component.
#[derive(Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// Invalid arguments are provided in an API call.
    BadParams {
        /// Detailed cause.
        cause: String,
    },

    /// A conversion between compatible data types failed.
    Conversion {
        /// Detailed cause.
        cause: String,
    },

    /// A generic failure during underlying cryptographic operation.
    CryptoOps {
        /// Detailed cause.
        cause: String,
    },

    /// Maximum defined retry reached for a crypto operation.
    /// For example, during a `HashToCurve` or `HashToScalar` operation, where
    /// we loop infinetly to produce a number of valid `Point` or `Scalar`,
    /// this error is returned if maximum retry is hit during production of
    /// single value.
    MaxRetryReached,

    /// Type encoding is malformed.
    BadEncoding,

    /// Maximum valid message size in octets is (2^64 -1) as per BBS signature
    /// specification.
    MessageIsTooLarge,

    /// Maximum valid domain separation tag size in octets is (2^8 -1) as per
    /// BBS signature specification.
    DstIsTooLarge,

    /// Secret key is not valid.
    InvalidSecretKey,

    /// Public key is not valid.
    InvalidPublicKey,

    /// Signature is malformed.
    MalformedSignature {
        /// Detailed cause.
        cause: String,
    },

    /// Signature verification failed.
    SignatureVerification,

    /// Proof is malformed.
    MalformedProof {
        /// Detailed cause.
        cause: String,
    },

    /// Not enough message generators.
    MessageGeneratorsLengthMismatch {
        /// Number of message generators.
        generators: usize,
        /// Number of messages.
        messages: usize,
    },

    /// Not enough random scalars during Proof initialization.
    UndisclosedIndexesRandomScalarsLengthMismatch {
        /// Number of random scalars.
        random_scalars: usize,
        /// Number of messages.
        undisclosed_indexes: usize,
    },

    /// The given point(from `G1` or `G2`) is an `Identity` element of
    /// respective subgroup.
    PointIsIdentity,

    /// Unexpected zero value.
    UnexpectedZeroValue,

    /// Error during serialization deserialization.
    Serde,
}

impl std::error::Error for Error {}

impl core::fmt::Debug for Error {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Error::BadParams { ref cause } => {
                write!(f, "bad arguments: cause: {cause}")
            }
            Error::Conversion { ref cause } => {
                write!(f, "data conversion failed: cause: {cause}")
            }
            Error::CryptoOps { ref cause } => {
                write!(
                    f,
                    "unexpected failure in cryptographic operation: cause \
                     {cause}"
                )
            }
            Error::MaxRetryReached => {
                write!(f, "max allowed retry is reached.")
            }
            Error::BadEncoding => {
                write!(f, "bad encoding encountered.")
            }
            Error::MessageIsTooLarge => {
                write!(f, "max valid size is (2^64 - 1) bytes.")
            }
            Error::DstIsTooLarge => {
                write!(f, "max valid size is (2^8 - 1) bytes.")
            }
            Error::InvalidSecretKey => {
                write!(f, "secret key is not valid.")
            }
            Error::InvalidPublicKey => {
                write!(f, "public key is invalid.")
            }
            Error::MalformedSignature { ref cause } => {
                write!(f, "signature is malformed: cause: {cause}")
            }
            Error::SignatureVerification => {
                write!(f, "signature verification failed.")
            }
            Error::MalformedProof { ref cause } => {
                write!(f, "proof is malformed: cause: {cause}")
            }
            Error::MessageGeneratorsLengthMismatch {
                generators,
                messages,
            } => {
                write!(
                    f,
                    "length mismatch, #message-generators: {generators}, \
                     #messages: {messages}."
                )
            }
            Error::UndisclosedIndexesRandomScalarsLengthMismatch {
                random_scalars,
                undisclosed_indexes,
            } => {
                write!(
                    f,
                    "length mismatch #random_scalars: {random_scalars}, \
                     #undisclosed_indexes: {undisclosed_indexes}."
                )
            }
            Error::PointIsIdentity => {
                write!(f, "unexpected `Identity` element.")
            }
            Error::UnexpectedZeroValue => {
                write!(f, "unexpected `Zero` element.")
            }
            Error::Serde => write!(f, "error during ser-de operation."),
        }
    }
}

impl From<core::array::TryFromSliceError> for Error {
    #[inline]
    fn from(_: core::array::TryFromSliceError) -> Self {
        Error::Conversion {
            cause: "slice to sized-array conversion".to_owned(),
        }
    }
}

impl core::fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
