#![allow(non_snake_case)]

use super::{
    generator::Generators,
    key_pair::PublicKey,
    types::{Challenge, Message, ProofInitResult},
};
use crate::{
    bbs::ciphersuites::BbsCiphersuiteParameters,
    common::{
        hash_param::constant::NON_NEGATIVE_INTEGER_ENCODING_LENGTH,
        serialization::{i2osp, i2osp_with_data},
    },
    curves::{
        bls12_381::{G1Projective, Scalar},
        point_serde::point_to_octets_g1,
    },
    error::Error,
};
use ff::Field;

#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;

#[cfg(not(feature = "alloc"))]
use std::collections::BTreeMap;

/// Computes `domain` value.
/// domain =
///    hash_to_scalar((PK || L || generators || Ciphersuite_ID || header), 1)
pub(crate) fn compute_domain<T, G, C>(
    PK: &PublicKey,
    header: Option<T>,
    L: usize,
    generators: &G,
) -> Result<Scalar, Error>
where
    T: AsRef<[u8]>,
    G: Generators,
    C: BbsCiphersuiteParameters,
{
    // Error out if length of messages and generators are not equal
    if L != generators.message_generators_length() {
        return Err(Error::MessageGeneratorsLengthMismatch {
            generators: generators.message_generators_length(),
            messages: L,
        });
    }

    // domain = hash_to_scalar((PK || L || generators || Ciphersuite_ID ||
    // header), 1)

    // dom_array = (L, Q, H_1, ..., H_L)
    // dom_octs = serialize(dom_array) || ciphersuite_id
    // dom_input = PK || dom_octs || I2OSP(length(header), 8) || header
    // hash_to_scalar(dom_input, 1)
    let mut data_to_hash = vec![];
    data_to_hash.extend(PK.to_octets().as_ref());
    data_to_hash.extend(i2osp(L as u64, NON_NEGATIVE_INTEGER_ENCODING_LENGTH)?);
    data_to_hash.extend(point_to_octets_g1(&generators.Q()).as_ref());

    for generator in generators.message_generators_iter() {
        data_to_hash.extend(point_to_octets_g1(&generator).as_ref());
    }

    data_to_hash.extend(C::ID.as_octets());

    let _header_bytes = header.as_ref().map_or(&[] as &[u8], |v| v.as_ref());
    data_to_hash.extend(i2osp_with_data(
        _header_bytes,
        NON_NEGATIVE_INTEGER_ENCODING_LENGTH,
    )?);

    C::hash_to_scalar(&data_to_hash, None)
}

/// Computes `B` value.
/// B = P1 + Q * domain + H_1 * msg_1 + ... + H_L * msg_L
pub(crate) fn compute_B<G, C>(
    domain: &Scalar,
    messages: &[Scalar],
    generators: &G,
) -> Result<G1Projective, Error>
where
    G: Generators,
    C: BbsCiphersuiteParameters,
{
    // Input params check
    // Error out if length of generators and messages are not equal
    if messages.len() != generators.message_generators_length() {
        return Err(Error::MessageGeneratorsLengthMismatch {
            generators: generators.message_generators_length(),
            messages: messages.len(),
        });
    }

    let mut points: Vec<_> = vec![C::p1()?, generators.Q()];
    points.extend(generators.message_generators_iter());
    let scalars = [&[Scalar::one(), *domain], messages].concat();

    Ok(G1Projective::multi_exp(&points, &scalars))
}

/// Compute Fiat Shamir heuristic challenge.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_challenge<T, C>(
    proof_init_res: &ProofInitResult,
    disclosed_messages: &BTreeMap<usize, Message>,
    ph: Option<T>,
) -> Result<Challenge, Error>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters,
{
    // c_array = (A_bar, B_bar, C, R, i1, ..., iR, msg_i1, ..., msg_iR,
    //              domain, ph)
    // c_octs = serialize(c_array)
    // if c_octs is INVALID, return INVALID
    let mut data_to_hash = vec![];
    data_to_hash.extend(point_to_octets_g1(&proof_init_res.A_bar).as_ref());
    data_to_hash.extend(point_to_octets_g1(&proof_init_res.B_bar).as_ref());
    data_to_hash.extend(point_to_octets_g1(&proof_init_res.D));
    data_to_hash.extend(point_to_octets_g1(&proof_init_res.T1));
    data_to_hash.extend(point_to_octets_g1(&proof_init_res.T2));

    data_to_hash.extend(i2osp(
        disclosed_messages.len() as u64,
        NON_NEGATIVE_INTEGER_ENCODING_LENGTH,
    )?);
    for &i in disclosed_messages.keys() {
        data_to_hash
            .extend(i2osp(i as u64, NON_NEGATIVE_INTEGER_ENCODING_LENGTH)?);
    }
    for &msg in disclosed_messages.values() {
        data_to_hash.extend(msg.to_bytes());
    }
    data_to_hash.extend(proof_init_res.domain.to_bytes_be());

    let _ph_bytes = ph.as_ref().map_or(&[] as &[u8], |v| v.as_ref());
    data_to_hash.extend(i2osp_with_data(
        _ph_bytes,
        NON_NEGATIVE_INTEGER_ENCODING_LENGTH,
    )?);

    // c = hash_to_scalar(c_for_hash, 1)
    Ok(Challenge(C::hash_to_scalar(&data_to_hash, None)?))
}
