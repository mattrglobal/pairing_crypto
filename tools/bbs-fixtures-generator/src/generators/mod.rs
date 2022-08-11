use pairing_crypto::{ExpandMsgXmd, ExpandMsgXof};
use sha2::Sha256;
use sha3::Shake256;
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
    signature::generate::<ExpandMsgXmd<Sha256>>(
        &fixture_gen_input,
        &fixture_output_dir.join(SIGNATURE_FIXTURES_SUBDIR),
    );
    signature::generate::<ExpandMsgXof<Shake256>>(
        &fixture_gen_input,
        &fixture_output_dir.join(SIGNATURE_FIXTURES_SUBDIR),
    );

    proof::generate::<ExpandMsgXof<Shake256>>(
        &fixture_gen_input,
        &fixture_output_dir.join(PROOF_FIXTURES_SUBDIR),
    );
}
