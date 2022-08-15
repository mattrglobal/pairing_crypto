use std::path::PathBuf;

use crate::model::FixtureGenInput;

pub mod proof;
pub mod signature;

pub const SIGNATURE_FIXTURES_SUBDIR: &str = "signature";
pub const PROOF_FIXTURES_SUBDIR: &str = "proof";

pub fn generate_fixtures(
    fixture_gen_input: &FixtureGenInput,
    fixture_output_dir: &PathBuf,
) {
    signature::generate(&fixture_gen_input, &fixture_output_dir);

    proof::generate(&fixture_gen_input, &fixture_output_dir);
}
