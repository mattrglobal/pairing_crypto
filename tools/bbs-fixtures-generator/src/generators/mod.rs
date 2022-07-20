use std::path::PathBuf;

use crate::model::FixtureGenInput;

pub mod proof;
pub mod signature;

pub fn generate_fixtures(
    fixture_gen_input: &FixtureGenInput,
    fixture_output_dir: &PathBuf,
) {
    signature::generate(
        &fixture_gen_input,
        &fixture_output_dir.join("signature"),
    );
    proof::generate(&fixture_gen_input, &fixture_output_dir.join("proof"));
}
