use rand_core::OsRng;

use crate::bbs::core::key_pair::{KeyPair, SecretKey};

#[test]
fn secret_key_gen_from_seed() {
    pub const MIN_IKM_LENGTH_BYTES: usize = 32;

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
fn key_pair_new_random() {
    let _ = KeyPair::random(&mut OsRng::default())
        .expect("random key pair generation failed");
}
