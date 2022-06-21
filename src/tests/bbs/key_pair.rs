use rand_core::OsRng;

use crate::bbs::core::key_pair::{KeyPair, SecretKey};

#[test]
fn secret_key_gen_from_seed() {
    const MIN_IKM_LENGTH_BYTES: usize = 32;

    let seed = [0u8; MIN_IKM_LENGTH_BYTES];
    let key_info = [];

    let sk = SecretKey::new(seed.as_ref(), key_info.as_ref());
    let expected = [
        77, 18, 154, 25, 223, 134, 160, 245, 52, 91, 173, 76, 198, 242, 73,
        236, 42, 129, 156, 204, 51, 134, 137, 91, 235, 79, 125, 152, 179, 219,
        98, 53,
    ];
    assert_eq!(sk.unwrap().to_bytes(), expected);
}

#[test]
fn key_gen_from_ikm() {
    let ikm = b"this-IS-just-an-Test-IKM-to-generate-$e(r@t#-key";
    let key_info = b"this-IS-some-key-metadata-to-be-used-in-test-key-gen";

    let KeyPair {
        secret_key,
        public_key,
    } = KeyPair::new(ikm.as_ref(), key_info.as_ref())
        .expect("key pair generation failed");

    println!("ikm: {:?}", hex::encode(&ikm));
    println!("key_info: {:?}", hex::encode(&key_info));
    println!("sk: {:?}", hex::encode(secret_key.to_bytes()));
    println!("pk: {:?}", hex::encode(&public_key.point_to_octets()));
}

#[test]
fn key_pair_new_random() {
    let _ = KeyPair::random(&mut OsRng::default())
        .expect("random key pair generation failed");
}
