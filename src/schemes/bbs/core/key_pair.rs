use crate::{
    bbs_bls_key_pair_impl,
    common::util::vec_to_byte_array,
    curves::bls12_381::{
        generate_sk,
        sk_to_pk_in_g2,
        G2Affine,
        G2Projective,
        Scalar,
        OCTET_POINT_G2_LENGTH,
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

use super::constants::MIN_KEY_GEN_IKM_LENGTH;

bbs_bls_key_pair_impl!(
    MIN_KEY_GEN_IKM_LENGTH,
    OCTET_SCALAR_LENGTH,
    OCTET_POINT_G2_LENGTH,
    G2Projective,
    G2Affine,
    generate_sk,
    sk_to_pk_in_g2
);
