use sha3::Shake256;

use crate::{
    bbs::core::generator::Generators,
    curves::bls12_381::hash_to_curve::ExpandMsgXof,
};

#[test]
fn nominal() {
    let generators = Generators::new::<ExpandMsgXof<Shake256>>(32)
        .expect("generators creation failed");
    assert_eq!(generators.message_generators_length(), 32);
}

#[test]
fn get_point_out_of_bound_index() {
    // Create 32 message generators
    let generators = Generators::new::<ExpandMsgXof<Shake256>>(32)
        .expect("generators creation failed");
    assert_eq!(generators.message_generators_length(), 32);

    // Getting any generator at index >= 32 should return None
    assert!(generators.get_message_generators_at_index(32).is_none());
    assert!(generators.get_message_generators_at_index(33).is_none());
}
