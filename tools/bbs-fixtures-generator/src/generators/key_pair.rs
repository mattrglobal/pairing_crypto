use blstrs::Scalar;
use hkdf::Hkdf;
use pairing_crypto::{
    bbs::ciphersuites::bls12_381::{KeyPair, PublicKey, SecretKey},
    Error,
};
use sha2::{Digest, Sha256};

// a KDF based on the spec recommendation: [https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-01.html#name-keygen],
// for the purpose of creating test vectors.
// NOTE: this KDF is NOT a requirement for spec compatibility
macro_rules! bbs_kdf {
    ($kdf_name:tt,
     $input_salt:expr,
     $hash:ty
    ) => {
        pub(crate) fn $kdf_name(
            input_ikm: &[u8],
            key_info: &[u8],
        ) -> Result<KeyPair, Error> {
            let ikm = input_ikm.as_ref();

            if (ikm.len() < 32) {
                return Err(Error::BadParams {
                    cause: "IKM is too short. Needs to be at least 32 bytes \
                            long"
                        .to_owned(),
                });
            };

            // L = ceil((3 * ceil(log2(r))) / 16)
            const L: usize = 48;

            // salt = H(salt)
            let mut hasher = <$hash>::new();
            hasher.update($input_salt);
            let salt = hasher.finalize();

            // PRK = HKDF-Extract(salt, IKM || I2OSP(0, 1))
            let ikm_prime = [ikm, &[0u8; 1][..]].concat();
            let hk = Hkdf::<$hash>::new(Some(&salt), &ikm_prime);

            // OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
            const L_BYTES: [u8; 2] = (L as u16).to_be_bytes();
            let mut okm = [0u8; 64];

            let key_info_prime = [&key_info, &L_BYTES[..]].concat();
            hk.expand(&key_info_prime, &mut okm[(64 - L)..])
                .expect(&format!(
                    "The output of HKDF expand cannot be more than {} bytes \
                     long",
                    255 * <$hash>::output_size()
                ));

            // SK = OS2IP(OKM) mod r
            let sk_scalar = Scalar::from_wide_bytes_be_mod_r(&okm);
            let sk: SecretKey = SecretKey(Box::new(sk_scalar));

            // PK = SkToPk(SK)
            let pk: PublicKey = PublicKey::from(&sk);

            Ok(KeyPair {
                secret_key: sk,
                public_key: pk,
            })
        }
    };
}

// Sha256 based BBS KDF
bbs_kdf!(
    sha256_bbs_key_gen_tool,
    "BBS-SIG-KEYGEN-SALT-".as_bytes(),
    Sha256
);

#[cfg(test)]
mod tests {
    use super::*;
    use pairing_crypto::bbs::ciphersuites::bls12_381::{
        BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
        BBS_BLS12381G1_SECRET_KEY_LENGTH,
    };
    use std::str;

    const TEST_IKM: &str = "746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579";
    const TEST_KEY_INFO: &str = "746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e";

    #[derive(Debug)]
    struct TestKeyPair<'a> {
        secret_key: &'a str,
        public_key: &'a str,
    }

    // expected bbs key pair
    const SHA256_TEST_KEY_PAIR: TestKeyPair = TestKeyPair {
        secret_key: &"4a39afffd624d69e81808b2e84385cc80bf86adadf764e030caa46c231f2a8d7",
        public_key: &"aaff983278257afc45fa9d44d156c454d716fb1a250dfed132d65b2009331f618c623c14efa16245f50cc92e60334051087f1ae92669b89690f5feb92e91568f95a8e286d110b011e9ac9923fd871238f57d1295395771331ff6edee43e4ccc6"
    };

    // ikm and key info to bytes
    fn get_test_asset() -> (Vec<u8>, Vec<u8>) {
        (
            hex::decode(TEST_IKM).unwrap(),
            hex::decode(TEST_KEY_INFO).unwrap(),
        )
    }

    fn kdf_test_helper() -> KeyPair {
        let (key_ikm, key_info) = get_test_asset();
        let key_pair = sha256_bbs_key_gen_tool(&key_ikm, &key_info)
            .expect("Key pair generation failed");

        key_pair
    }

    // validate that the kdf with the BLS salt will return the same
    // result with the native blstr implementation.
    // [https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-keygen]
    #[test]
    fn expected_bls_key_pair() {
        let (key_ikm, key_info) = get_test_asset();

        // BLS KDF
        bbs_kdf!(
            sha256_bls_key_gen,
            "BLS-SIG-KEYGEN-SALT-".as_bytes(),
            Sha256
        );

        // BLS keyGen
        let key_pair = sha256_bls_key_gen(&key_ikm, &key_info).unwrap();

        // native BLS keyGen
        let kay_pair_native = KeyPair::new(&key_ikm, &key_info).unwrap();

        assert_eq!(key_pair, kay_pair_native)
    }

    // validate that the sha256 based bbs kdf returns the expected results
    #[test]
    fn expected_bbs_key_pair() {
        let key_pair = kdf_test_helper();

        // println!("sk = {:?}", hex::encode(key_pair.secret_key.to_bytes()));
        // println!("pk = {:?}", hex::encode(key_pair.public_key.to_octets()));

        assert_eq!(
            hex::encode(key_pair.secret_key.to_bytes()),
            SHA256_TEST_KEY_PAIR.secret_key
        );
        assert_eq!(
            hex::encode(key_pair.public_key.to_octets()),
            SHA256_TEST_KEY_PAIR.public_key
        );
    }

    // validate that the sha256 based bbs kdf returns valid results
    #[test]
    fn valid_public_key() {
        let key_pair = kdf_test_helper();

        assert_eq!(
            key_pair.public_key.is_valid().unwrap_u8(),
            1,
            "Public Key is invalid"
        );
        assert_eq!(
            key_pair.public_key.to_octets().len(),
            BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
            "Public Key is the wrong length"
        );
        assert_eq!(
            key_pair.secret_key.to_bytes().len(),
            BBS_BLS12381G1_SECRET_KEY_LENGTH,
            "Secret Key is the wrong length"
        );
    }
}
