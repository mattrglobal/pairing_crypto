use crate::bbs::{
    ciphersuites::bls12_381_shake_256::Bls12381Shake256CipherSuiteParameter,
    core::generator::{
        dynamic_generator::DynamicGenerators,
        memory_cached_generator::MemoryCachedGenerators,
        Generators,
    },
};

#[test]
fn creation_nominal() {
    let generators =
        MemoryCachedGenerators::<Bls12381Shake256CipherSuiteParameter>::new(32)
            .expect("generators creation failed");
    assert_eq!(generators.message_generators_length(), 32);

    let generators =
        DynamicGenerators::<Bls12381Shake256CipherSuiteParameter>::new(32)
            .expect("generators creation failed");
    assert_eq!(generators.message_generators_length(), 32);
}

#[test]
fn get_point_out_of_bound_index() {
    // Create 32 message generators
    let mut generators =
        MemoryCachedGenerators::<Bls12381Shake256CipherSuiteParameter>::new(32)
            .expect("generators creation failed");
    assert_eq!(generators.message_generators_length(), 32);
    // Getting any generator at index >= 32 should return None
    assert!(generators.get_message_generator(32).is_none());
    assert!(generators.get_message_generator(33).is_none());

    // Create 32 message generators
    let mut generators =
        DynamicGenerators::<Bls12381Shake256CipherSuiteParameter>::new(32)
            .expect("generators creation failed");
    assert_eq!(generators.message_generators_length(), 32);
    // Getting any generator at index >= 32 should return None
    for i in 0..32 {
        assert!(generators.get_message_generator(i).is_some());
    }
    assert!(generators.get_message_generator(32).is_none());
    assert!(generators.get_message_generator(33).is_none());
}

#[test]
fn generators_impl_equality() {
    const NUM_GENERATORS: usize = 1000;
    // Create memory-cached generators
    let mut memory_cached_generators = MemoryCachedGenerators::<
        Bls12381Shake256CipherSuiteParameter,
    >::new(NUM_GENERATORS)
    .expect("generators creation failed");

    // Create dynamic generators
    let mut dynamic_generators = DynamicGenerators::<
        Bls12381Shake256CipherSuiteParameter,
    >::new(NUM_GENERATORS)
    .expect("generators creation failed");

    // Test if generators created by these 2 implementation are equal
    for index in 0..NUM_GENERATORS {
        assert_eq!(
            memory_cached_generators.get_message_generator(index),
            dynamic_generators.get_message_generator(index),
            "generator value is different at index {}",
            index
        );
    }
}
