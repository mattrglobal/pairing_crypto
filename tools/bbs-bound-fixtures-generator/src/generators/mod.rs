pub mod signature;
use std::path::PathBuf;

use crate::model::BoundFixtureGenInput;

pub fn generate_fixtures(fixture_gen_input: &BoundFixtureGenInput, output_dit: &PathBuf) {
    signature::generate(&fixture_gen_input, &output_dit);
}