use std::path::PathBuf;

use crate::model::FixtureGenInput;

pub mod h2s;
pub mod proof;
pub mod signature;

pub const SIGNATURE_FIXTURES_SUBDIR: &str = "signature";
pub const PROOF_FIXTURES_SUBDIR: &str = "proof";
pub const H2S_FIXTURES_SUBDIR: &str = "h2s";

pub fn generate_fixtures(
    fixture_gen_input: &FixtureGenInput,
    fixture_output_dir: &PathBuf,
) {
    signature::generate(&fixture_gen_input, &fixture_output_dir);

    proof::generate(&fixture_gen_input, &fixture_output_dir);

    h2s::generate(&fixture_gen_input, &fixture_output_dir);
}
