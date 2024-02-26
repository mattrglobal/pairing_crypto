use pairing_crypto::bbs::ciphersuites::{
    bls12_381::suite_constants::BBS_BLS12381G1_EXPAND_LEN,
    bls12_381_g1_sha_256::{
        ciphersuite_id as bls12_381_g1_sha_256_ciphersuite_id,
        default_hash_to_scalar_dst as bls12_381_sha_256_default_hash_to_scalar_dst,
        default_map_message_to_scalar_as_hash_dst as bls12_381_sha_256_default_message_to_scalar_dst,
        hash_to_scalar as bls12_381_sha_256_h2s,
        map_message_to_scalar_as_hash as bls12_381_sha_256_map_message_to_scalar,
    },
    bls12_381_g1_shake_256::{
        ciphersuite_id as bls12_381_g1_shake_256_ciphersuite_id,
        default_hash_to_scalar_dst as bls12_381_shake_256_default_hash_to_scalar_dst,
        default_map_message_to_scalar_as_hash_dst as bls12_381_shake_256_default_message_to_scalar_dst,
        hash_to_scalar as bls12_381_shake_256_h2s,
        map_message_to_scalar_as_hash as bls12_381_shake_256_map_message_to_scalar,
    },
};

use crate::{
    mock_rng::{MockRng, MOCKED_RNG_DST, MOCKED_RNG_SEED},
    model::{
        FixtureGenInput,
        FixtureH2s,
        FixtureMapMessageToScalar,
        FixtureMockedRng,
        MessageToScalarFixtureCase,
    },
    util::save_test_vector,
};
use blstrs::{
    hash_to_curve::{ExpandMsgXmd, ExpandMsgXof},
    Scalar,
};
use rand::RngCore;
use sha2::Sha256;
use sha3::Shake256;
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

        let mut h2s_fixture = FixtureH2s {
            case_name: "Hash to scalar output".to_owned(),
            message: msg.to_owned(),
            dst: dst_used,
            scalar: msg_scalar.to_vec(),
        };

        save_test_vector(&mut h2s_fixture, &$output_dir.join("h2s.json"));
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
            &mut map_msg_to_scalar_fixture,
            &$output_dir.join("MapMessageToScalarAsHash.json"),
        )
    }};
}

macro_rules! generate_mocked_rnd_scalars_fixtures {
    (
     $count:expr,
     $ciphersuite_id:ident,
     $expander:ty,
     $output_dir:expr
    ) => {{
        let dst = &[&$ciphersuite_id(), MOCKED_RNG_DST.as_bytes()].concat();
        let mut mocked_rng = MockRng::<'_, $expander>::new(
            MOCKED_RNG_SEED.as_bytes(),
            dst,
            $count,
            Some(BBS_BLS12381G1_EXPAND_LEN),
        );

        let mut fixture = FixtureMockedRng {
            case_name: "mocked random scalars".to_owned(),
            count: $count,
            seed: MOCKED_RNG_SEED.as_bytes().to_vec(),
            dst: dst.to_vec(),
            mocked_scalars: Vec::<String>::new(),
        };

        for _ in 0..$count {
            let mut buff = [0u8; 64];
            mocked_rng.fill_bytes(&mut buff[16..]);
            let scalar_i = Scalar::from_wide_bytes_be_mod_r(&buff);
            fixture
                .mocked_scalars
                .push(hex::encode(scalar_i.to_bytes_be()));
        }

        save_test_vector(&mut fixture, &$output_dir.join("mockedRng.json"))
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
    );

    generate_mocked_rnd_scalars_fixtures!(
        10,
        bls12_381_g1_sha_256_ciphersuite_id,
        ExpandMsgXmd<Sha256>,
        output_dir.join("bls12_381_sha_256")
    );

    generate_mocked_rnd_scalars_fixtures!(
        10,
        bls12_381_g1_shake_256_ciphersuite_id,
        ExpandMsgXof<Shake256>,
        output_dir.join("bls12_381_shake_256")
    );
}
