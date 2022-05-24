/// A `Result` with an error of type `CryptoError`.
pub type Result<T> = std::result::Result<T, Error>;

/// Error enumerates all possible errors occuring in this library.
/// An error returned by the crypto component.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Error {
    /// A conversion between compatible data types failed.
    Conversion { cause: String },

    /// A generic failure during underlying cryptographic operation.
    CryptoOps,

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

    /// Error during serialization deserialization in Serde.
    Serde,
}

impl std::error::Error for Error {}

impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Error::Conversion { ref cause } => {
                write!(f, "data conversion failed: cause: {}", cause)
            }
            Error::CryptoOps => {
                write!(f, "unexpected failure in cryptographic operation.")
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
            Error::CryptoSchnorrChallengeComputation { cause } => {
                write!(
                    f,
                    "schnorr challenge computation failed: cause: {}",
                    cause
                )
            }
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}
