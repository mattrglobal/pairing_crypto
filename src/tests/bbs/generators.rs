use crate::bbs::core::generator::Generators;

#[test]
fn nominal() {
    let generators =
        Generators::new(&[], &[], &[], 32).expect("generators creation failed");
    assert_eq!(generators.message_blinding_points_length(), 32);
}

#[test]
fn get_point_out_of_bound_index() {
    // Create 32 message generators
    let generators =
        Generators::new(&[], &[], &[], 32).expect("generators creation failed");
    assert_eq!(generators.message_blinding_points_length(), 32);

    // Getting any generator at index >= 32 should return None
    assert!(generators.get_message_blinding_point(32).is_none());
    assert!(generators.get_message_blinding_point(33).is_none());
}
