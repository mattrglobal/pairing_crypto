use pairing_crypto::bls::{
    ciphersuites::bls12_381_g2_shake_256_pop::{
        pop_prove,
        pop_verify,
        sign,
        verify,
    },
    core::key_pair::KeyPair,
};

const TEST_KEY_GEN_SEED: &[u8] = b"not_A_random_seed_at_Allllllllll";
const TEST_KEY_INFO: &[u8] = b"test-key-info";
const TEST_MESSAGE: &[u8] = b"test-message";

#[test]
fn sign_verify_e2e_nominal() {
    let key_pair =
        KeyPair::new(TEST_KEY_GEN_SEED.as_ref(), Some(TEST_KEY_INFO))
            .expect("key generation must succeed");

    let signature =
        sign(&key_pair.secret_key, &TEST_MESSAGE).expect("siging must succeed");
    assert!(verify(&key_pair.public_key, &TEST_MESSAGE, &signature)
        .expect("signature verification must succeed"));
}

#[test]
fn pop_prove_verify_e2e_nominal() {
    let key_pair =
        KeyPair::new(TEST_KEY_GEN_SEED.as_ref(), Some(TEST_KEY_INFO))
            .expect("key generation must succeed");

    let proof =
        pop_prove(&key_pair.secret_key).expect("PoP generation must succeed");
    assert!(pop_verify(&key_pair.public_key, &proof)
        .expect("PoP verification must succeed"));
}
