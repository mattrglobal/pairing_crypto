use sha2::{Sha256};
use hkdf::Hkdf;
use hex;
use digest::{HashMarker};
use pairing_crypto::bbs::{
    ciphersuites::bls12_381::KeyPair,
    core::key_pair::{PublicKey, SecretKey},
};

use blstrs::Scalar;

use crate::{
    model::{
        TestAsset}};


macro_rules! spec_compliant_key_pair {
    ($fixture_gen_input:ident,
     $salt:expr,
     $hash:ty) => {{
        let hk = Hkdf::<$hash>::new(Some(&$salt[..]), &$fixture_gen_input.key_ikm);

        const L: usize = 48;
        let mut okm = [0u8; 64];
        let mut okm2 = [0u8; L];
        hk.expand(&$fixture_gen_input.key_info, &mut okm2) // okm[(64-L)..]
            .expect("48 is a valid length for Sha256 to output");
        
        println!("{:?}", okm2);
        let sk = Scalar::from_wide_bytes_be_mod_r(&okm);
        let secret_key: SecretKey = SecretKey(Box::new(sk));
        println!("{:?}",secret_key.to_bytes());

     }};
}


pub fn sha256_kdf(fixture_gen_input: &TestAsset) {
    spec_compliant_key_pair!(
        fixture_gen_input,
        "BBS-SALT-".as_bytes(),
        Sha256
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_kdf() {
        let test_asset_file = "../../tests/fixtures/bbs/test_asset.json";
        let test_asset = std::fs::read_to_string(test_asset_file).unwrap();
        let test_asset_obj = serde_json::from_str::<TestAsset>(&test_asset).unwrap();
        sha256_kdf(&test_asset_obj);
        assert_eq!(1, 1)
    }
}