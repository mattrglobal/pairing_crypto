use pairing_crypto::bls::{
    ciphersuites::{
        bls12_381_g2_shake_256_aug::{
            sign as bls12_381_g2_shake_256_aug_sign,
            verify as bls12_381_g2_shake_256_aug_verify,
        },
        bls12_381_g2_shake_256_nul::{
            sign as bls12_381_g2_shake_256_nul_sign,
            verify as bls12_381_g2_shake_256_nul_verify,
        },
        bls12_381_g2_shake_256_pop::{
            pop_prove as bls12_381_g2_shake_256_pop_pop_prove,
            pop_verify as bls12_381_g2_shake_256_pop_pop_verify,
            sign as bls12_381_g2_shake_256_pop_sign,
            verify as bls12_381_g2_shake_256_pop_verify,
        },
    },
    core::key_pair::KeyPair,
};

const TEST_KEY_GEN_SEED: &[u8] = b"not_A_random_seed_at_Allllllllll";
const TEST_KEY_INFO: &[u8] = b"test-key-info";
const TEST_MESSAGE: &[u8] = b"test-message";

macro_rules! sign_verify_e2e_nominal {
    ($sign_fn:ident, $verify_fn:ident) => {
        let key_pair =
            KeyPair::new(TEST_KEY_GEN_SEED.as_ref(), Some(TEST_KEY_INFO))
                .expect("key generation must succeed");

        let signature = $sign_fn(&key_pair.secret_key, &TEST_MESSAGE)
            .expect("siging must succeed");
        assert!($verify_fn(&key_pair.public_key, &TEST_MESSAGE, &signature)
            .expect("signature verification must succeed"));
    };
}

#[test]
fn sign_verify_e2e_nominal() {
    sign_verify_e2e_nominal!(
        bls12_381_g2_shake_256_nul_sign,
        bls12_381_g2_shake_256_nul_verify
    );

    sign_verify_e2e_nominal!(
        bls12_381_g2_shake_256_aug_sign,
        bls12_381_g2_shake_256_aug_verify
    );

    sign_verify_e2e_nominal!(
        bls12_381_g2_shake_256_pop_sign,
        bls12_381_g2_shake_256_pop_verify
    );
}

#[test]
fn pop_prove_verify_e2e_nominal() {
    let key_pair =
        KeyPair::new(TEST_KEY_GEN_SEED.as_ref(), Some(TEST_KEY_INFO))
            .expect("key generation must succeed");

    let proof = bls12_381_g2_shake_256_pop_pop_prove(&key_pair.secret_key)
        .expect("PoP generation must succeed");
    assert!(bls12_381_g2_shake_256_pop_pop_verify(
        &key_pair.public_key,
        &proof
    )
    .expect("PoP verification must succeed"));
}
