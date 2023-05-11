// Wrapper for `Scalar` data types.
macro_rules! scalar_wrapper {
    ($(#[$docs:meta])*
     $name:ident) => {
        $(#[$docs])*
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Deserialize, Serialize)]
        pub(crate) struct $name(pub Scalar);

        impl Default for $name {
            fn default() -> Self {
                use ff::Field;
                Self(Scalar::zero())
            }
        }

        impl $name {
            /// The number of bytes needed to represent this type.
            pub const SIZE_BYTES: usize = OCTET_SCALAR_LENGTH;

            /// Convert this type to a big-endian representation.
            pub fn to_bytes(self) -> [u8; Self::SIZE_BYTES] {
                self.0.to_bytes_be()
            }

            /// Convert a big-endian representation to this type.
            #[allow(dead_code)]
            pub fn from_bytes(bytes: &[u8; Self::SIZE_BYTES]) -> CtOption<Self> {
                Scalar::from_bytes_be(bytes).map($name)
            }

        }
    };
}

pub(crate) use scalar_wrapper;
