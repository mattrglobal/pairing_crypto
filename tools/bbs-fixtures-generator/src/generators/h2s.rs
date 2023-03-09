use pairing_crypto::bbs::ciphersuites::{
    bls12_381_g1_sha_256::{
        default_hash_to_scalar_dst as bls12_381_sha_256_default_hash_to_scalar_dst,
        default_map_message_to_scalar_as_hash_dst as bls12_381_sha_256_default_message_to_scalar_dst,
        hash_to_scalar as bls12_381_sha_256_h2s,
        map_message_to_scalar_as_hash as bls12_381_sha_256_map_message_to_scalar,
    },
    bls12_381_g1_shake_256::{
        default_hash_to_scalar_dst as bls12_381_shake_256_default_hash_to_scalar_dst,
        default_map_message_to_scalar_as_hash_dst as bls12_381_shake_256_default_message_to_scalar_dst,
        hash_to_scalar as bls12_381_shake_256_h2s,
        map_message_to_scalar_as_hash as bls12_381_shake_256_map_message_to_scalar,
    },
};

use crate::{
    model::{
        FixtureGenInput,
        FixtureH2s,
        FixtureMapMessageToScalar,
        MessageToScalarFixtureCase,
    },
    util::save_test_vector,
};

use std::path::PathBuf;

macro_rules! generate_hash_fixtures {
    ($hash_to_scalar_fn:ident,
     $get_default_hash_to_scalar_dst_fn:ident,
     $dst:ident,
     $fixture_gen_input:ident,
     $output_dir:expr) => {
        let msg = &$fixture_gen_input.messages[0];

        // the dst used
        let default_dst = $get_default_hash_to_scalar_dst_fn();
        let dst_used = $dst.unwrap_or(default_dst);

        let msg_scalar =
            $hash_to_scalar_fn(msg, Some(&dst_used)).unwrap().to_owned();

        let h2s_fixture = FixtureH2s {
            case_name: "Hash to scalar output".to_owned(),
            message: msg.to_owned(),
            dst: dst_used,
            scalar: msg_scalar.to_vec(),
        };

        save_test_vector(&h2s_fixture, &$output_dir.join("h2s.json"));
    };
}

macro_rules! generate_map_message_to_scalar_fixtures {
    ($map_message_to_scalar_as_hash_fn:ident,
     $get_default_map_message_to_scalar_dst_fn:ident,
     $fixture_gen_input:ident,
     $output_dir:expr) => {{
        // MapMessageToScalarAsHash fixture
        let default_dst = $get_default_map_message_to_scalar_dst_fn();

        let mut map_msg_to_scalar_fixture = FixtureMapMessageToScalar {
            case_name: "MapMessageToScalar fixture".to_owned(),
            dst: default_dst,
            cases: Vec::new(),
        };

        for msg in &$fixture_gen_input.messages {
            let msg_scalar =
                $map_message_to_scalar_as_hash_fn(msg, None).unwrap();

            map_msg_to_scalar_fixture
                .cases
                .push(MessageToScalarFixtureCase {
                    message: msg.to_owned(),
                    scalar: msg_scalar.to_vec(),
                });
        }

        save_test_vector(
            &map_msg_to_scalar_fixture,
            &$output_dir.join("MapMessageToScalarAsHash.json"),
        )
    }};
}

pub fn generate(fixture_gen_input: &FixtureGenInput, output_dir: &PathBuf) {
    generate_hash_fixtures!(
        bls12_381_shake_256_h2s,
        bls12_381_shake_256_default_hash_to_scalar_dst,
        None,
        fixture_gen_input,
        output_dir.join("bls12_381_shake_256")
    );

    generate_map_message_to_scalar_fixtures!(
        bls12_381_shake_256_map_message_to_scalar,
        bls12_381_shake_256_default_message_to_scalar_dst,
        fixture_gen_input,
        output_dir.join("bls12_381_shake_256")
    );

    generate_hash_fixtures!(
        bls12_381_sha_256_h2s,
        bls12_381_sha_256_default_hash_to_scalar_dst,
        None,
        fixture_gen_input,
        output_dir.join("bls12_381_sha_256")
    );

    generate_map_message_to_scalar_fixtures!(
        bls12_381_sha_256_map_message_to_scalar,
        bls12_381_sha_256_default_message_to_scalar_dst,
        fixture_gen_input,
        output_dir.join("bls12_381_sha_256")
    )
}
