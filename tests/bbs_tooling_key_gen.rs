use bbs_fixtures_generator::{sha256_kdf, TestAsset};
use sha2::{Digest, Sha256};
use pairing_crypto::bbs::ciphersuites::bls12_381::{KeyPair, PublicKey, SecretKey};
use blstrs::Scalar;

#[cfg(test)]
mod tests{
    use pairing_crypto::bbs::core::key_pair;

    use super::*;
    
    #[test]
    fn sha256_tooling_native_kdf() {
        let test_asset_file = "./tests/fixtures/bbs/test_asset.json";
        let test_asset = std::fs::read_to_string(test_asset_file).unwrap();
        let test_asset_obj = serde_json::from_str::<TestAsset>(&test_asset).unwrap();

        let kay_pair = sha256_kdf(
            &test_asset_obj,
            "BLS-SIG-KEYGEN-SALT-".as_bytes());

        let kay_pair_native = KeyPair::new(test_asset_obj.key_ikm, Some(&test_asset_obj.key_info)).unwrap();

        // test that the native impl returns the same result
        assert_eq!(kay_pair.secret_key, kay_pair_native.secret_key);
        assert_eq!(kay_pair.public_key, kay_pair_native.public_key);
    }
}