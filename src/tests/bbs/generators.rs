use crate::bbs::{
    ciphersuites::bls12_381_g1_shake_256::Bls12381Shake256CipherSuiteParameter,
    core::generator::{
        memory_cached_generator::MemoryCachedGenerators,
        Generators,
    },
};

#[test]
fn creation_nominal() {
    let generators = MemoryCachedGenerators::<
        Bls12381Shake256CipherSuiteParameter,
    >::new(32, None)
    .expect("generators creation failed");
    assert_eq!(generators.message_generators_length(), 32);
}

#[test]
fn equality() {
    const GENERATORS_COUNT: usize = 1000;
    let generators_1 = MemoryCachedGenerators::<
        Bls12381Shake256CipherSuiteParameter,
    >::new(GENERATORS_COUNT, None)
    .expect("generators creation failed");
    assert_eq!(generators_1.message_generators_length(), GENERATORS_COUNT);

    let generators_2 = MemoryCachedGenerators::<
        Bls12381Shake256CipherSuiteParameter,
    >::new(GENERATORS_COUNT, None)
    .expect("generators creation failed");
    assert_eq!(generators_2.message_generators_length(), GENERATORS_COUNT);

    for i in 0..GENERATORS_COUNT {
        assert_eq!(
            generators_1.get_message_generator(i),
            generators_2.get_message_generator(i)
        );
    }
}

#[test]
fn get_point_out_of_bound_index() {
    // Create 32 message generators
    let generators = MemoryCachedGenerators::<
        Bls12381Shake256CipherSuiteParameter,
    >::new(32, None)
    .expect("generators creation failed");
    assert_eq!(generators.message_generators_length(), 32);
    // Getting any generator at index >= 32 should return None
    assert!(generators.get_message_generator(32).is_none());
    assert!(generators.get_message_generator(33).is_none());
}

// #TODO
// test - generators are constants, store for say 100 of them and match against
// the returned ones
// test - as above match against hardcoded Q_1, Q_2, and BP_1 values
