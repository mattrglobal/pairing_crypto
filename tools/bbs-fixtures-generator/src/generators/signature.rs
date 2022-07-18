use pairing_crypto::bbs::ciphersuites::bls12_381::{sign, BbsSignRequest};
use std::path::PathBuf;

use crate::model::{ExpectedResult, FixtureGenInput, FixtureSignature};

pub fn generate(fixture_gen_input: &FixtureGenInput, output_dir: &PathBuf) {
    let sign_request = BbsSignRequest {
        secret_key: &fixture_gen_input.key_pair.secret_key.to_bytes(),
        public_key: &fixture_gen_input.key_pair.public_key.to_octets(),
        header: Some(fixture_gen_input.header.clone()),
        messages: Some(&fixture_gen_input.messages[..1]),
    };

    let mut fixture: FixtureSignature = fixture_gen_input.clone().into();

    fixture.case_name = "single message signature".to_owned();
    fixture.result = ExpectedResult {
        valid: true,
        reason: None,
    };
    generate_helper(
        sign_request,
        &mut fixture,
        output_dir,
        "signature001.json",
    );
}

pub fn generate_helper<T: AsRef<[u8]>>(
    sign_request: BbsSignRequest<T>,
    fixture: &mut FixtureSignature,
    output_dir: &PathBuf,
    test_vector_file_name: &str,
) {
    let signature = sign(sign_request).unwrap();
    fixture.signature = signature.to_vec();

    let mut test_vector_file_path = output_dir.clone();
    test_vector_file_path.extend(&["signature", test_vector_file_name]);

    std::fs::write(
        test_vector_file_path,
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .unwrap();
}
