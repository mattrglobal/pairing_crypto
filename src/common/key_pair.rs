// Key-pair implementation.
macro_rules! bbs_bls_key_pair_impl {
    (
        $min_key_gen_ikm_length:ident,
        $octet_scalar_length:ident,
        $octet_point_length:ident,
        $point_projective_type:ident,
        $point_affine_type:ident,
        $generate_sk:ident,
        $sk_to_pk_fn:ident
    ) => {
        /// Secret key type.
        // The secret key is field element 0 < `x` < `r`
        // where `r` is the curve order. See Section 4.3 in
        // <https://eprint.iacr.org/2016/663.pdf>.
        #[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
        pub struct SecretKey(pub Box<Scalar>);

        impl Default for SecretKey {
            fn default() -> Self {
                Self(Box::new(Scalar::zero()))
            }
        }

        impl core::fmt::Debug for SecretKey {
            fn fmt(
                &self,
                f: &mut std::fmt::Formatter<'_>,
            ) -> std::result::Result<(), std::fmt::Error> {
                write!(f, "****")
            }
        }

        impl Zeroize for SecretKey {
            fn zeroize(&mut self) {
                self.0 = Box::new(Scalar::zero());
            }
        }

        impl Drop for SecretKey {
            fn drop(&mut self) {
                self.zeroize();
            }
        }

        impl From<&SecretKey> for [u8; SecretKey::SIZE_BYTES] {
            fn from(sk: &SecretKey) -> [u8; SecretKey::SIZE_BYTES] {
                sk.to_bytes()
            }
        }

        impl SecretKey {
            /// Number of bytes needed to represent the secret key.
            pub const SIZE_BYTES: usize = $octet_scalar_length;

            /// Computes a secret key from an IKM, as defined by
            /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-2.3>
            /// Note this procedure does not follow
            /// <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-keygen>
            pub fn new(ikm_in: &[u8], key_info: &[u8]) -> Option<Self> {
                let mut random_ikm = [0u8; $min_key_gen_ikm_length];

                let ikm = if ikm_in.is_empty() {
                    let mut rng = rand_core::OsRng;
                    if rng.try_fill_bytes(&mut random_ikm).is_err() {
                        return None;
                    }
                    &random_ikm
                } else {
                    ikm_in
                };

                if let Some(out) = $generate_sk(ikm.as_ref(), key_info) {
                    // Extra assurance
                    if out.is_zero().unwrap_u8() == 1u8 {
                        return None;
                    }
                    return Some(SecretKey(Box::new(out)));
                }
                None
            }

            /// Compute a secret key from a CS-PRNG.
            pub fn random<R>(rng: &mut R, key_info: &[u8]) -> Option<Self>
            where
                R: RngCore + CryptoRng,
            {
                let mut ikm = [0u8; $min_key_gen_ikm_length];

                if rng.try_fill_bytes(&mut ikm).is_ok() {
                    return Self::new(ikm.as_ref(), key_info);
                }
                None
            }

            #[allow(dead_code)]
            pub(super) fn as_scalar(&self) -> Scalar {
                *self.0
            }

            /// Convert a vector of bytes of big-endian representation of the
            /// secret key.
            pub fn from_vec(bytes: &[u8]) -> Result<Self, Error> {
                match vec_to_byte_array::<{ Self::SIZE_BYTES }>(bytes) {
                    Ok(result) => Self::from_bytes(&result),
                    Err(e) => Err(e),
                }
            }

            /// Convert the secret key to a big-endian representation.
            pub fn to_bytes(&self) -> [u8; Self::SIZE_BYTES] {
                self.0.to_bytes_be()
            }

            /// Convert a big-endian representation of the secret key.
            pub fn from_bytes(
                bytes: &[u8; Self::SIZE_BYTES],
            ) -> Result<Self, Error> {
                let s = Scalar::from_bytes_be(bytes);

                if s.is_some().unwrap_u8() == 1u8 {
                    let s = s.unwrap();
                    // Zero check as Scalar::from_bytes_be() can result in zero
                    // value
                    if s.is_zero().unwrap_u8() == 1u8 {
                        return Err(Error::InvalidSecretKey);
                    }
                    Ok(SecretKey(Box::new(s)))
                } else {
                    Err(Error::BadParams {
                        cause: "can't built a valid `SecretKey` from input \
                                data"
                            .to_owned(),
                    })
                }
            }
        }

        /// Public key type.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub struct PublicKey(pub(crate) $point_projective_type);

        impl Default for PublicKey {
            fn default() -> Self {
                Self($point_projective_type::identity())
            }
        }

        impl core::fmt::Display for PublicKey {
            fn fmt(
                &self,
                f: &mut core::fmt::Formatter<'_>,
            ) -> core::fmt::Result {
                write!(f, "PublicKey(")?;
                print_byte_array!(f, self.to_octets());
                write!(f, ")")
            }
        }

        impl From<&SecretKey> for PublicKey {
            fn from(s: &SecretKey) -> Self {
                Self($sk_to_pk_fn(&s.0))
            }
        }

        impl From<PublicKey> for [u8; PublicKey::SIZE_BYTES] {
            fn from(pk: PublicKey) -> Self {
                pk.to_octets()
            }
        }

        impl<'a> From<&'a PublicKey> for [u8; PublicKey::SIZE_BYTES] {
            fn from(pk: &'a PublicKey) -> [u8; PublicKey::SIZE_BYTES] {
                pk.to_octets()
            }
        }

        impl PublicKey {
            /// Number of bytes needed to represent the public key in compressed
            /// form.
            pub const SIZE_BYTES: usize = $octet_point_length;
            /// Number of bytes needed to represent the public key in uncompressed
            /// form.
            pub const SIZE_BYTES_UNCOMPRESSED: usize = 2 * Self::SIZE_BYTES;

            /// Check if the `PublicKey` is valid.
            pub fn is_valid(&self) -> Choice {
                (!self.0.is_identity())
                    & self.0.is_on_curve()
                    & self.0.to_affine().is_torsion_free()
            }

            /// Get the G2 representation in affine, compressed and big-endian
            /// form of PublicKey.
            pub fn to_octets(&self) -> [u8; Self::SIZE_BYTES] {
                self.0.to_affine().to_compressed()
            }

            /// Get the G2 representation in affine, uncompressed and big-endian
            /// form of PublicKey.
            pub fn to_octets_uncompressed(&self) -> [u8; Self::SIZE_BYTES_UNCOMPRESSED] {
                self.0.to_uncompressed()
            }

            /// Convert a vector of bytes of big-endian representation of the
            /// public key.
            pub fn from_vec(bytes: &Vec<u8>) -> Result<Self, Error> {
                match bytes.len() {
                    Self::SIZE_BYTES => { 
                        let byte_array = vec_to_byte_array::<{ Self::SIZE_BYTES }>(bytes)?;
                        Self::from_octets(&byte_array)
                    },
                    Self::SIZE_BYTES_UNCOMPRESSED => {  
                        let byte_array = vec_to_byte_array::<{ Self::SIZE_BYTES_UNCOMPRESSED }>(bytes)?;
                        Self::from_octets_uncompressed(&byte_array)
                    },
                    _ => Err(Error::BadEncoding)
                }
            }

            /// Convert from G2 point in affine, compressed and big-endian form
            /// to PublicKey.
            pub fn from_octets(
                bytes: &[u8; Self::SIZE_BYTES],
            ) -> Result<Self, Error> {
                let result = $point_affine_type::from_compressed(bytes)
                    .map(|p| Self($point_projective_type::from(&p)));

                if result.is_some().unwrap_u8() == 1u8 {
                    Ok(result.unwrap())
                } else {
                    Err(Error::BadEncoding)
                }
            }

            /// Convert from G2 point in affine, uncompressed and big-endian form
            /// to PublicKey.
            pub fn from_octets_uncompressed(bytes: &[u8; Self::SIZE_BYTES_UNCOMPRESSED]) -> Result<Self, Error> {
                let result = $point_projective_type::from_uncompressed(bytes);

                if result.is_some().unwrap_u8() == 1u8 {
                    Ok(Self(result.unwrap()))
                } else {
                    Err(Error::BadEncoding)
                }
            }

            /// Convert a public key from compressed to uncompressed representation
            pub fn compressed_to_uncompressed(bytes: &Vec<u8>) -> Result<[u8; Self::SIZE_BYTES_UNCOMPRESSED], Error> {
                match Self::from_vec(bytes) {
                    Ok(public_key) => Ok(Self::to_octets_uncompressed(&public_key)),
                    Err(e) => Err(e)
                }
            }

            /// Convert a public key from uncompressed to compressed representation
            pub fn uncompressed_to_compressed(bytes: &Vec<u8>) -> Result<[u8; Self::SIZE_BYTES], Error> {
                match Self::from_vec(bytes) {
                    Ok(public_key) => Ok(Self::to_octets(&public_key)),
                    Err(e) => Err(e)
                }
            }
        }

        /// A BBS key pair.
        #[derive(
            Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize,
        )]
        pub struct KeyPair {
            /// Secret key.
            pub secret_key: SecretKey,

            /// Public key.
            pub public_key: PublicKey,
        }

        impl Zeroize for KeyPair {
            fn zeroize(&mut self) {
                self.secret_key.zeroize();
            }
        }

        impl Drop for KeyPair {
            fn drop(&mut self) {
                self.zeroize();
            }
        }

        impl KeyPair {
            /// Generate a BBS key pair from provided IKM.
            pub fn new(ikm: &[u8], key_info: &[u8]) -> Option<Self> {
                if let Some(secret_key) = SecretKey::new(ikm.as_ref(), key_info)
                {
                    return Some(Self {
                        secret_key: secret_key.clone(),
                        public_key: PublicKey::from(&secret_key),
                    });
                }
                None
            }

            /// Compute a secret key from a CS-PRNG.
            pub fn random<R>(rng: &mut R, key_info: &[u8]) -> Option<Self>
            where
                R: RngCore + CryptoRng,
            {
                let mut ikm = [0u8; $min_key_gen_ikm_length];

                if rng.try_fill_bytes(&mut ikm).is_ok() {
                    return Self::new(ikm.as_ref(), key_info);
                }
                None
            }
        }
    };
}

pub(crate) use bbs_bls_key_pair_impl;
