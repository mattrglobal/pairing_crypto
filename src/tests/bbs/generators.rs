use crate::bbs::core::generator::Generators;

#[test]
fn create() {
    let generators =
        Generators::new(&[], &[], &[], 32).expect("generators creation failed");
    assert_eq!(generators.message_blinding_points_length(), 32);
}
