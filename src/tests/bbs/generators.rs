use crate::bbs::{
    ciphersuites::bls12_381_shake_256::Bls12381Shake256CipherSuiteParameter,
    core::generator::{
        memory_cached_generator::MemoryCachedGenerators,
        Generators,
    },
};

#[test]
fn nominal() {
    let generators =
        MemoryCachedGenerators::new::<Bls12381Shake256CipherSuiteParameter>(32)
            .expect("generators creation failed");
    assert_eq!(generators.message_generators_length(), 32);
}

#[test]
fn get_point_out_of_bound_index() {
    // Create 32 message generators
    let generators =
        MemoryCachedGenerators::new::<Bls12381Shake256CipherSuiteParameter>(32)
            .expect("generators creation failed");
    assert_eq!(generators.message_generators_length(), 32);

    // Getting any generator at index >= 32 should return None
    assert!(generators.get_message_generator_at_index(32).is_none());
    assert!(generators.get_message_generator_at_index(33).is_none());
}
