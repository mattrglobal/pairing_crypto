/// Error enumerates all possible errors occuring in this library.
#[derive(Debug)]
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

    /// Error during serialization deserialization in Serde.
    Serde,
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Error::Conversion { .. } => None,
            Error::CryptoOps => None,
            Error::CryptoInvalidIkmLength => None,
            Error::CryptoBadEncoding => None,
            Error::CryptoPointNotOnCurve => None,
            Error::CryptoPointNotOnGroup => None,
            Error::CryptoBadScalar => None,
            Error::Serde => None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Error::Conversion { ref cause } => {
                write!(f, "data conversion failed: cause: {}", cause)
            }
            Error::CryptoOps => {
                write!(f, "unexpected failure in cryptographic operation.")
            }
            Error::CryptoInvalidIkmLength => {
                write!(f, "IKM data size is not valid.")
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
        }
    }
}

impl From<blst_lib::BLST_ERROR> for Error {
    fn from(err: blst_lib::BLST_ERROR) -> Error {
        match err {
            blst_lib::BLST_ERROR::BLST_BAD_ENCODING => Error::CryptoBadEncoding,
            blst_lib::BLST_ERROR::BLST_POINT_NOT_ON_CURVE => {
                Error::CryptoPointNotOnCurve
            }
            blst_lib::BLST_ERROR::BLST_POINT_NOT_IN_GROUP => {
                Error::CryptoPointNotOnGroup
            }
            blst_lib::BLST_ERROR::BLST_BAD_SCALAR => Error::CryptoBadScalar,
            _ => Error::CryptoOps,
        }
    }
}
