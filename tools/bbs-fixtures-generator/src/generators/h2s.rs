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
    H2S_FIXTURES_SUBDIR,
};

use std::path::PathBuf;

macro_rules! generate_hash_fixtures {
    ($hash_to_scalar_fn:ident,
     $get_default_hash_to_scalar_dst_fn:ident,
     $fixture_gen_input:ident,
     $output_dir:expr) => {
        let msg = &$fixture_gen_input.messages[0];

        // Hash to scalar with output count 1
        let h2s_fixture = h2s_make_fixture_helper!(
            "Hash to curve, 1 scalar output",
            $hash_to_scalar_fn,
            $get_default_hash_to_scalar_dst_fn,
            msg,
            None,
            1,
        );

        save_test_vector(&h2s_fixture, &$output_dir.join("h2s001.json"));

        // Hash to scalar with output count 10
        let h2s_fixture = h2s_make_fixture_helper!(
            "Hash to curve, 10 scalar output",
            $hash_to_scalar_fn,
            $get_default_hash_to_scalar_dst_fn,
            msg,
            None,
            10,
        );

        save_test_vector(&h2s_fixture, &$output_dir.join("h2s002.json"));
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

macro_rules! h2s_make_fixture_helper {
    (
        $case_name:literal,
        $hash_to_scalar_fn:ident,
        $get_default_hash_to_scalar_dst_fn:ident,
        $message: ident,
        $dst: ident,
        $count: literal,
    ) => {{
        // the dst used
        let default_dst = $get_default_hash_to_scalar_dst_fn();
        let dst_used = $dst.unwrap_or(default_dst);

        let msg_scalars =
            $hash_to_scalar_fn($message, $count, Some(&dst_used)).unwrap();

        // use collect_into if it becomes stable, see issue #94780
        let mut scalars_vec: Vec<Vec<u8>> = Vec::new();
        for msg_scalar in msg_scalars {
            scalars_vec.push(Vec::from(msg_scalar.to_owned()));
        }

        FixtureH2s {
            case_name: $case_name.to_owned(),
            message: $message.to_owned(),
            dst: dst_used,
            count: $count,
            scalars: scalars_vec,
        }
    }};
}

pub fn generate(fixture_gen_input: &FixtureGenInput, output_dir: &PathBuf) {
    generate_hash_fixtures!(
        bls12_381_shake_256_h2s,
        bls12_381_shake_256_default_hash_to_scalar_dst,
        fixture_gen_input,
        output_dir
            .join("bls12_381_shake_256")
            .join(H2S_FIXTURES_SUBDIR)
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
        fixture_gen_input,
        output_dir
            .join("bls12_381_sha_256")
            .join(H2S_FIXTURES_SUBDIR)
    );

    generate_map_message_to_scalar_fixtures!(
        bls12_381_sha_256_map_message_to_scalar,
        bls12_381_sha_256_default_message_to_scalar_dst,
        fixture_gen_input,
        output_dir.join("bls12_381_sha_256")
    )
}
