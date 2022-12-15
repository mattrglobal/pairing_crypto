use sha2::{Digest, Sha256};
use hkdf::Hkdf;
use pairing_crypto::bbs::ciphersuites::bls12_381::{KeyPair, PublicKey, SecretKey};


use blstrs::Scalar;

use crate::{
    model::{
        TestAsset}};


macro_rules! spec_compliant_key_pair {
    ($fixture_gen_input:ident,
     $input_salt:expr,
     $hash:ty) => {{
        // salt = H(salt)
        let mut hasher = <$hash>::new();
        hasher.update($input_salt);
        let salt = hasher.finalize();
        // println!("salt hash = {:?}", salt);

        let ikm_prime = [&$fixture_gen_input.key_ikm, &[0u8; 1][..]].concat();
        let hk = Hkdf::<$hash>::new(Some(&salt), &ikm_prime);

        const L: usize = 48;
        const L_bytes: [u8; 2] = (L as u16).to_be_bytes();
        let mut okm = [0u8; 64];

        let key_info_prime = [&$fixture_gen_input.key_info, &L_bytes[..]].concat();
        hk.expand(&key_info_prime, &mut okm[(64-L)..]) // okm[(64-L)..]
            .expect("48 is a valid length for Sha256 to output");

        let sk_scalar = Scalar::from_wide_bytes_be_mod_r(&okm);
        let sk: SecretKey = SecretKey(Box::new(sk_scalar));

        let pk: PublicKey = PublicKey::from(&sk);

        KeyPair {
            secret_key: sk,
            public_key: pk
        }
     }};
}


pub fn sha256_kdf(fixture_gen_input: &TestAsset, salt: &[u8]) -> KeyPair {

    spec_compliant_key_pair!(
        fixture_gen_input,
        salt,
        Sha256
    )
}

#[cfg(test)]
mod tests{
    use super::*;

    fn test_helper(salt: &[u8]) -> KeyPair {
        const test_asset_file: &str = "../../tests/fixtures/bbs/test_asset.json";
        let test_asset = std::fs::read_to_string(test_asset_file).unwrap();
        let test_asset_obj: TestAsset = serde_json::from_str::<TestAsset>(&test_asset).unwrap();

        sha256_kdf(
            &test_asset_obj,
            "BLS-SIG-KEYGEN-SALT-".as_bytes())
    }

    #[test]
    fn sha256_tooling_native_kdf() {

        const test_asset_file: &str = "../../tests/fixtures/bbs/test_asset.json";
        let test_asset = std::fs::read_to_string(test_asset_file).unwrap();
        let test_asset_obj: TestAsset = serde_json::from_str::<TestAsset>(&test_asset).unwrap();

        let kay_pair = test_helper(
            "BLS-SIG-KEYGEN-SALT-".as_bytes());

        let kay_pair_native = KeyPair::new(test_asset_obj.key_ikm, Some(&test_asset_obj.key_info)).unwrap();

        // test that the native impl returns the same result
        assert_eq!(kay_pair.secret_key, kay_pair_native.secret_key);
        assert_eq!(kay_pair.public_key, kay_pair_native.public_key);
    }

    #[test]
    fn sha_256_kdf() {
        let key_pair = test_helper(
            "BBS-SIG-KEYGEN-SALT-".as_bytes()
        );

        println!("sk = {:?}", hex::encode(key_pair.secret_key.to_bytes()));
        println!("pk = {:?}", hex::encode(key_pair.public_key.to_octets()));
    }
}