use pairing_crypto::{
    bbs::ciphersuites::{
        bls12_381::{KeyPair, PublicKey, SecretKey},
        bls12_381_g1_sha_256::{
            ciphersuite_id as sha256_ciphersuite_id,
            hash_to_scalar as sha256_hash_to_scalar,
        },
        bls12_381_g1_shake_256::{
            ciphersuite_id as shake256_ciphersuite_id,
            hash_to_scalar as shake256_hash_to_scalar,
        },
    },
    Error,
};

use crate::{
    model::{FixtureGenInput, FixtureKeyGen},
    util::save_test_vector,
};

use std::path::Path;

// a KDF based on the spec recommendation: [https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-01.html#name-keygen],
// for the purpose of creating test vectors.
// NOTE: this KDF is NOT a requirement for spec compatibility
macro_rules! bbs_kdf {
    ($kdf_name:tt,
     $ciphersuite_id:ident,
     $hash_to_scalar:ident
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

            let keygen_dst =
                [$ciphersuite_id(), b"KEYGEN_DST_".to_vec()].concat();

            // derive_input = key_material || I2OSP(length(key_info), 2) ||
            // key_info
            let derive_input =
                [input_ikm, &(key_info.len() as u16).to_be_bytes(), key_info]
                    .concat();

            let sk_bytes =
                $hash_to_scalar(&derive_input, Some(&keygen_dst)).unwrap();
            let sk = SecretKey::from_bytes(&sk_bytes).unwrap();

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
    sha256_ciphersuite_id,
    sha256_hash_to_scalar
);

// ShaKE256 based BBS KDF
bbs_kdf!(
    shake256_bbs_key_gen_tool,
    shake256_ciphersuite_id,
    shake256_hash_to_scalar
);

macro_rules! generate_keygen_fixture {
    (
     $keygen_fn:ident,
     $fixture_gen_input:ident,
     $ciphersuite_id:ident,
     $output_dir:expr
    ) => {
        let key_pair = $keygen_fn(
            &$fixture_gen_input.key_ikm,
            &$fixture_gen_input.key_info,
        )
        .unwrap();

        let fixture_scratch: FixtureKeyGen = $fixture_gen_input.clone().into();

        let keygen_dst = [$ciphersuite_id(), b"KEYGEN_DST_".to_vec()].concat();

        let mut fixture = FixtureKeyGen {
            case_name: "key pair fixture".to_owned(),
            key_dst: keygen_dst,
            key_pair,
            ..fixture_scratch
        };

        save_test_vector(&mut fixture, &$output_dir.join("keypair.json"));
    };
}

pub fn generate(fixture_gen_input: &FixtureGenInput, output_dir: &Path) {
    generate_keygen_fixture!(
        sha256_bbs_key_gen_tool,
        fixture_gen_input,
        sha256_ciphersuite_id,
        output_dir.join("bls12_381_sha_256")
    );

    generate_keygen_fixture!(
        shake256_bbs_key_gen_tool,
        fixture_gen_input,
        shake256_ciphersuite_id,
        output_dir.join("bls12_381_shake_256")
    );
}

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
        secret_key: "57887f6e42cbf2a76fae89370474abe3d0f2e9db5d66c3f60b13e4fc724cde4e",
        public_key: "a9df410a06798fafcc2a1cc004441c3cb831ffdc408500eb3c24f876714317798ec4ec7cfee653a4c3c44f6158ebebf70a0484cd7d8984a3325c154b7f39f8b1b97ab087e5218ab343011456953219b91cca6c5eb37613b2963e588691a42ec1"
    };

    const SHAKE256_TEST_KEY_PAIR: TestKeyPair = TestKeyPair {
        secret_key: "63bf6d84ff9dc4822dafb362189b5ef63bd89b8f44f6cefe3dd2dadfa9732e39",
        public_key: "acac86a688f260a1fda6291505e68c36df49684c65abb302b0527c77d1392a7b32954e553e910e93b6cc6c613dc25ed0070dba3a671f82dca905c9a8f2605d2b78a142896e849ce0cbe01f098c14d64809645c87d2b788c198e41db2b862199d"
    };

    // ikm and key info to bytes
    fn get_test_asset() -> (Vec<u8>, Vec<u8>) {
        (
            hex::decode(TEST_IKM).unwrap(),
            hex::decode(TEST_KEY_INFO).unwrap(),
        )
    }

    // validate that the sha256 based bbs kdf returns the expected results
    #[test]
    fn expected_bbs_sha256_key_pair() {
        let (key_ikm, key_info) = get_test_asset();
        let key_pair = sha256_bbs_key_gen_tool(&key_ikm, &key_info)
            .expect("Key pair generation failed");

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

    // validate that the shake256 based bbs kdf returns the expected results
    #[test]
    fn expected_bbs_shake256_key_pair() {
        let (key_ikm, key_info) = get_test_asset();
        let key_pair = shake256_bbs_key_gen_tool(&key_ikm, &key_info)
            .expect("Key pair generation failed");

        // println!("sk = {:?}", hex::encode(key_pair.secret_key.to_bytes()));
        // println!("pk = {:?}", hex::encode(key_pair.public_key.to_octets()));

        assert_eq!(
            hex::encode(key_pair.secret_key.to_bytes()),
            SHAKE256_TEST_KEY_PAIR.secret_key
        );
        assert_eq!(
            hex::encode(key_pair.public_key.to_octets()),
            SHAKE256_TEST_KEY_PAIR.public_key
        );
    }

    // validate that the sha256 based bbs kdf returns valid results
    #[test]
    fn valid_public_key() {
        let (key_ikm, key_info) = get_test_asset();
        let key_pair = sha256_bbs_key_gen_tool(&key_ikm, &key_info)
            .expect("Key pair generation failed");

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
