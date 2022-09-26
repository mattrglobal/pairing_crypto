use super::constants::MIN_KEY_GEN_IKM_LENGTH;
use crate::{
    bbs_bls_key_pair_impl,
    common::util::vec_to_byte_array,
    curves::bls12_381::{
        generate_sk,
        sk_to_pk_in_g1,
        G1Affine,
        G1Projective,
        Scalar,
        OCTET_POINT_G1_LENGTH,
        OCTET_SCALAR_LENGTH,
    },
    error::Error,
    print_byte_array,
};
use ff::Field;
use group::{Curve, Group};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use subtle::Choice;
use zeroize::Zeroize;

bbs_bls_key_pair_impl!(
    MIN_KEY_GEN_IKM_LENGTH,
    OCTET_SCALAR_LENGTH,
    OCTET_POINT_G1_LENGTH,
    G1Projective,
    G1Affine,
    generate_sk,
    sk_to_pk_in_g1
);
