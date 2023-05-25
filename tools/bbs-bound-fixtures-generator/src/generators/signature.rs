use pairing_crypto::{
    bbs_bound::{
        ciphersuites::bls12_381_bbs_g1_bls_sig_g2_sha_256::{
            bls_key_pop,
            bls_key_pop_verify,
            sign,
            verify,
            proof_gen_with_rng,
            proof_verify
        },
        BlsKeyPopGenRequest,
        BlsKeyPopVerifyRequest,
        BbsBoundSignRequest,
        BbsBoundVerifyRequest,
        BbsBoundProofGenRequest,
        BbsBoundProofVerifyRequest,
        BbsBoundProofGenRevealMessageRequest
    },
    bbs::ciphersuites::bls12_381::{BBS_BLS12381G1_SIGNATURE_LENGTH, BBS_BLS12381G1_EXPAND_LEN},
    bbs::ciphersuites::bls12_381_g1_sha_256::ciphersuite_id
};
use blstrs::hash_to_curve::ExpandMsgXmd;
use bbs_fixtures_generator::{ExpectedResult, save_test_vector, mock_rng::MockRng};
use std::path::PathBuf;
use crate::model::{
    BoundFixtureGenInput,
    FixtureKeyPoP,
    FixtureBoundSignature,
    FixtureBoundProof
};
use sha2::Sha256;

const TEST_AUD: &[u8] = b"test-bbs-signature-issuer-001";
const TEST_DST: &[u8] = b"application-version-200";
const TEST_EXTRA_INFO: &[u8] = b"sample-app-100-apac";
const MOCKED_RNG_SEED: &str = "3.141592653589793238462643383279"; // 30 first digits of pi
const MOCKED_RNG_DST: &str = "MOCK_RANDOM_SCALARS_DST_";


const BOUND_HEADER_SUFFIX: &[u8] = b"BBS_BOUND_";

macro_rules! validate_proof_fixture {
    ($proof_verify_fn:ident, $fixture:expr) => {
        let result = $proof_verify_fn(&BbsBoundProofVerifyRequest {
            public_key: &$fixture.bbs_pub_key.to_octets(),
            header: Some($fixture.header.clone()),
            presentation_header: Some($fixture.presentation_header.clone()),
            messages: Some(&$fixture.disclosed_messages),
            proof: &$fixture.proof,
        });

        if $fixture.result.valid {
            assert!(
                result.is_ok(),
                "proof-verify should not return error, case: {}",
                $fixture.case_name
            );

            assert_eq!(
                result.unwrap(),
                true,
                "proof-verify should return `true`, case: {} - {:?}",
                $fixture.case_name,
                $fixture.result.reason
            );
        } else {
            assert!(
                result.is_err() || (result.unwrap() == false),
                "validation failed, case: {} - {:?}",
                $fixture.case_name,
                $fixture.result.reason
            );
        }
    };
}

fn get_proof_messages(
    messages: Vec<Vec<u8>>, indexes: Vec<usize>
) -> (Vec<BbsBoundProofGenRevealMessageRequest<Vec<u8>>>, Vec<(usize, Vec<u8>)>) {
    let mut proof_messages = Vec::new();
    let mut disclosed_messages = Vec::new();

    for (i, msg) in messages.iter().enumerate() {
        if indexes.contains(&i) {
            proof_messages.push(BbsBoundProofGenRevealMessageRequest {
                reveal: true,
                value: msg.clone()
            });
            disclosed_messages.push((i, msg.clone()))
        } else {
            proof_messages.push(BbsBoundProofGenRevealMessageRequest {
                reveal: false,
                value: msg.clone()
            });
        }
    };

    (proof_messages, disclosed_messages)
}


macro_rules! generate_fixture {
    (
        $ciphersuite_id:ident,
        $expander:ty,
        $bls_key_pop:ident,
        $bls_key_pop_verify:ident,
        $sign_fn:ident,
        $verify_fn:ident,
        $proof_gen_fn:ident,
        $proof_verify_fn:ident,
        $fixture_gen_input:ident,
        $output_dir:expr
    ) => {
        let mut bound_header: Vec<u8> = $fixture_gen_input.header.clone();
        bound_header.extend(BOUND_HEADER_SUFFIX);

        let key_pop = bls_key_pop(&BlsKeyPopGenRequest{
            bls_secret_key: &$fixture_gen_input.bls_key_pair.secret_key.to_bytes(),
            aud: &TEST_AUD,
            dst: Some(TEST_DST),
            extra_info: Some(TEST_EXTRA_INFO)
        })
        .expect("User's secret key PoP generation failed");

        let key_pop_fixture = &FixtureKeyPoP {
            case_name: "User BLS Public Key PoP".to_owned(),
            bls_key_pair: $fixture_gen_input.bls_key_pair.clone(),
            aud: TEST_AUD.to_vec(),
            dst: TEST_DST.to_vec(),
            extra_info: TEST_EXTRA_INFO.to_vec(),
            pop: key_pop.to_vec()
        };
        save_test_vector(key_pop_fixture, &$output_dir.join("key_pop.json"));

        assert!(bls_key_pop_verify(
            &BlsKeyPopVerifyRequest {
                bls_key_pop: &key_pop,
                bls_public_key: &$fixture_gen_input.bls_key_pair.public_key.to_octets(),
                aud: &TEST_AUD,
                dst: Some(TEST_DST),
                extra_info: Some(TEST_EXTRA_INFO)
            }
        ).expect("PoP verification failed"));

        let fixture_scratch = FixtureBoundSignature{
            bbs_key_pair: $fixture_gen_input.bbs_key_pair.clone(),
            bls_key_pair: $fixture_gen_input.bls_key_pair.clone(),
            header: bound_header.clone(),
            ..Default::default()
        };

        // Single message bound signature
        let bound_signature = $sign_fn(&BbsBoundSignRequest{
            secret_key: &$fixture_gen_input.bbs_key_pair.secret_key.to_bytes(),
            public_key: &$fixture_gen_input.bbs_key_pair.public_key.to_octets(),
            bls_public_key: &$fixture_gen_input.bls_key_pair.public_key.to_octets(),
            header: Some(bound_header.clone()),
            messages: Some(&$fixture_gen_input.messages[..1]),
        }).expect("Bound BBS signature generation for a single message failed");

        let fixture = &FixtureBoundSignature {
            case_name: "Single-message bound signature".to_owned(),
            messages: $fixture_gen_input.messages[..1].to_vec(),
            signature: bound_signature.to_vec(),
            result: ExpectedResult { valid: true, reason: None },
            ..fixture_scratch.clone()
        };

        validate_signature_fixture!($verify_fn, fixture);
        save_test_vector(&fixture, &$output_dir.join("signature/signature001.json"));

        // Multiple message bound signature
        let bound_signature = $sign_fn(&BbsBoundSignRequest {
            secret_key: &$fixture_gen_input.bbs_key_pair.secret_key.to_bytes(),
            public_key: &$fixture_gen_input.bbs_key_pair.public_key.to_octets(),
            bls_public_key: &$fixture_gen_input.bls_key_pair.public_key.to_octets(),
            header: Some(bound_header.clone()),
            messages: Some(&$fixture_gen_input.messages),
        }).expect("Bound BBS signature generation for multiple messages failed");

        let fixture = &FixtureBoundSignature {
            case_name: "Multi-message bound signature".to_owned(),
            messages: $fixture_gen_input.messages.to_vec(),
            signature: bound_signature.to_vec(),
            result: ExpectedResult { valid: true, reason: None },
            ..fixture_scratch.clone()
        };

        validate_signature_fixture!($verify_fn, fixture);
        save_test_vector(&fixture, &$output_dir.join("signature/signature002.json"));

        // Proof generation
        let proof_fixture_scratch = FixtureBoundProof {
            bbs_pub_key: $fixture_gen_input.bbs_key_pair.public_key,
            bls_key_pair: $fixture_gen_input.bls_key_pair.clone(),
            header: bound_header.clone(),
            signature: bound_signature.to_vec(),
            presentation_header: $fixture_gen_input.presentation_header.clone(),
            ..Default::default()
        };

        // All messages revealed
        let disclosed_indices: Vec<usize> = (0usize..$fixture_gen_input.messages.len()).collect();
        let (proof_messages, disclosed_messages) = get_proof_messages(
            $fixture_gen_input.messages.clone(),
            disclosed_indices.clone()
        );

        // Mocked rng based on expand_message
        let dst = &[&$ciphersuite_id(), MOCKED_RNG_DST.as_bytes()].concat();
        let mocked_rng = MockRng::<'_, $expander>::new(
            MOCKED_RNG_SEED.as_bytes(),
            dst,
            $fixture_gen_input.messages.len() - disclosed_indices.len() + 6,
            Some(BBS_BLS12381G1_EXPAND_LEN),
        );

        let proof = $proof_gen_fn(&BbsBoundProofGenRequest {
                public_key: &$fixture_gen_input.bbs_key_pair.public_key.to_octets(),
                bls_secret_key: &$fixture_gen_input.bls_key_pair.secret_key.to_bytes(),
                header: Some(bound_header.clone()),
                messages: Some(&proof_messages),
                signature: &bound_signature.clone(),
                presentation_header: Some($fixture_gen_input.presentation_header.clone()),
                verify_signature: None
            }, 
            mocked_rng
        ).expect("Bound proof generation failed");

        let proof_fixture = FixtureBoundProof {
            case_name: "All message revealed".to_owned(),
            proof: proof,
            disclosed_messages: disclosed_messages.clone(),
            result: ExpectedResult { valid: true, reason: None },
            ..proof_fixture_scratch.clone()
        };

        validate_proof_fixture!($proof_verify_fn, proof_fixture);
        save_test_vector(&proof_fixture, &$output_dir.join("proof/proof001.json"));

        // Half the messages revealed
        let disclosed_indices: Vec<usize> = (0usize..$fixture_gen_input.messages.len()).filter(|i| i%2 ==0).collect();
        let (proof_messages, disclosed_messages) = get_proof_messages(
            $fixture_gen_input.messages.clone(),
            disclosed_indices.clone()
        );

        // Mocked rng based on expand_message
        let dst = &[&$ciphersuite_id(), MOCKED_RNG_DST.as_bytes()].concat();
        let mocked_rng = MockRng::<'_, $expander>::new(
            MOCKED_RNG_SEED.as_bytes(),
            dst,
            $fixture_gen_input.messages.len() - disclosed_indices.len() + 6,
            Some(BBS_BLS12381G1_EXPAND_LEN),
        );

        let proof = $proof_gen_fn(&BbsBoundProofGenRequest {
                public_key: &$fixture_gen_input.bbs_key_pair.public_key.to_octets(),
                bls_secret_key: &$fixture_gen_input.bls_key_pair.secret_key.to_bytes(),
                header: Some(bound_header.clone()),
                messages: Some(&proof_messages),
                signature: &bound_signature.clone(),
                presentation_header: Some($fixture_gen_input.presentation_header.clone()),
                verify_signature: None
            },
            mocked_rng
        ).expect("Bound proof generation failed for half the messages");

        let proof_fixture = FixtureBoundProof {
            case_name: "Half the message revealed".to_owned(),
            proof: proof,
            disclosed_messages: disclosed_messages,
            result: ExpectedResult { valid: true, reason: None },
            ..proof_fixture_scratch.clone()
        };

        validate_proof_fixture!($proof_verify_fn, proof_fixture);
        save_test_vector(&proof_fixture, &$output_dir.join("proof/proof002.json"));
    }
}

macro_rules! validate_signature_fixture {
    ($verify_fn:ident, $fixture:expr) => {
        let result = $verify_fn(&BbsBoundVerifyRequest {
            public_key: &$fixture.bbs_key_pair.public_key.to_octets(),
            bls_secret_key: &$fixture.bls_key_pair.secret_key.to_bytes(),
            header: Some($fixture.header.clone()),
            messages: Some(&$fixture.messages),
            signature: &<[u8; BBS_BLS12381G1_SIGNATURE_LENGTH]>::try_from(
                $fixture.signature.clone(),
            )
            .unwrap(),
        })
        .expect(&format!(
            "verify should not return error, case: {}",
            $fixture.case_name
        ));

        assert_eq!(
            result, $fixture.result.valid,
            "validation failed, case: {} - {:?}",
            $fixture.case_name, $fixture.result.reason
        );
    };
}

pub fn generate(test_asset: &BoundFixtureGenInput, output_dir: &PathBuf) {
    generate_fixture!(
        ciphersuite_id,
        ExpandMsgXmd<Sha256>,
        bls_key_pop,
        bls_key_pop_verify,
        sign,
        verify,
        proof_gen_with_rng,
        proof_verify,
        test_asset,
        output_dir
    );
}