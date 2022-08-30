#![allow(non_snake_case)]

use super::{
    constants::{NON_NEGATIVE_INTEGER_ENCODING_LENGTH, OCTET_POINT_G1_LENGTH},
    generator::Generators,
    key_pair::PublicKey,
    types::{Challenge, Message},
};
use crate::{
    bbs::ciphersuites::BbsCiphersuiteParameters,
    common::serialization::{i2osp, i2osp_with_data},
    curves::bls12_381::{G1Affine, G1Projective, Scalar},
    error::Error,
};
use ff::Field;
use group::Curve;

#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;

#[cfg(not(feature = "alloc"))]
use std::collections::BTreeMap;

/// Get the representation of a point G1(in Projective form) to compressed
/// and big-endian octets form.
pub(crate) fn point_to_octets_g1(
    p: &G1Projective,
) -> [u8; OCTET_POINT_G1_LENGTH] {
    p.to_affine().to_compressed()
}

/// Convert from octets in affine, compressed and big-endian form to
/// `G1Projective` type.
pub(crate) fn octets_to_point_g1(
    octets: &[u8; OCTET_POINT_G1_LENGTH],
) -> Result<G1Projective, Error> {
    let result = G1Affine::from_compressed(octets).map(G1Projective::from);
    if result.is_some().unwrap_u8() == 1u8 {
        Ok(result.unwrap())
    } else {
        Err(Error::BadEncoding)
    }
}

/// Computes `domain` value.
/// domain =
///    hash_to_scalar((PK || L || generators || Ciphersuite_ID || header), 1)
pub(crate) fn compute_domain<T, C>(
    PK: &PublicKey,
    header: Option<T>,
    L: usize,
    generators: &Generators,
) -> Result<Scalar, Error>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters<'static>,
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
    let mut data_to_hash = vec![];
    data_to_hash.extend(PK.to_octets().as_ref());
    data_to_hash.extend(i2osp(L as u64, NON_NEGATIVE_INTEGER_ENCODING_LENGTH)?);
    data_to_hash.extend(point_to_octets_g1(&generators.Q_1()).as_ref());
    data_to_hash.extend(point_to_octets_g1(&generators.Q_2()).as_ref());

    for generator in generators.message_generators_iter() {
        data_to_hash.extend(point_to_octets_g1(generator).as_ref());
    }
    data_to_hash.extend(C::ID.as_octets());
    if let Some(header) = header {
        data_to_hash.extend(i2osp_with_data(
            header.as_ref(),
            NON_NEGATIVE_INTEGER_ENCODING_LENGTH,
        )?);
    }

    Ok(C::hash_to_scalar(&data_to_hash, 1, None)?[0])
}

/// Computes `B` value.
/// B = P1 + Q_1 * s + Q_2 * domain + H_1 * msg_1 + ... + H_L * msg_L
pub(crate) fn compute_B<C>(
    s: &Scalar,
    domain: &Scalar,
    messages: &[Message],
    generators: &Generators,
) -> Result<G1Projective, Error>
where
    C: BbsCiphersuiteParameters<'static>,
{
    // Input params check
    // Error out if length of generators and messages are not equal
    if messages.len() != generators.message_generators_length() {
        return Err(Error::MessageGeneratorsLengthMismatch {
            generators: generators.message_generators_length(),
            messages: messages.len(),
        });
    }

    let mut points: Vec<_> = vec![C::p1(), generators.Q_1(), generators.Q_2()];
    points.extend(generators.message_generators_iter());
    let scalars: Vec<_> = [Scalar::one(), *s, *domain]
        .iter()
        .copied()
        .chain(messages.iter().map(|c| c.0))
        .collect();

    Ok(G1Projective::multi_exp(&points, &scalars))
}

/// Compute Fiat Shamir heuristic challenge.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_challenge<T, C>(
    A_prime: &G1Projective,
    A_bar: &G1Projective,
    D: &G1Projective,
    C1: &G1Projective,
    C2: &G1Projective,
    disclosed_messages: &BTreeMap<usize, Message>,
    domain: &Scalar,
    ph: Option<T>,
) -> Result<Challenge, Error>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters<'static>,
{
    // c_array = (A', Abar, D, C1, C2, R, i1, ..., iR, msg_i1, ..., msg_iR,
    //              domain, ph)
    // c_for_hash = encode_for_hash(c_array)
    // if c_for_hash is INVALID, return INVALID
    let mut data_to_hash = vec![];
    data_to_hash.extend(point_to_octets_g1(A_prime).as_ref());
    data_to_hash.extend(point_to_octets_g1(A_bar).as_ref());
    data_to_hash.extend(point_to_octets_g1(D).as_ref());
    data_to_hash.extend(point_to_octets_g1(C1));
    data_to_hash.extend(point_to_octets_g1(C2));
    data_to_hash.extend(i2osp(
        disclosed_messages.len() as u64,
        NON_NEGATIVE_INTEGER_ENCODING_LENGTH,
    )?);
    for &i in disclosed_messages.keys() {
        data_to_hash
            .extend(i2osp(i as u64, NON_NEGATIVE_INTEGER_ENCODING_LENGTH)?);
    }
    for &msg in disclosed_messages.values() {
        data_to_hash.extend(&msg.to_bytes());
    }
    data_to_hash.extend(&domain.to_bytes_be());
    if let Some(ph) = ph {
        data_to_hash.extend(i2osp_with_data(
            ph.as_ref(),
            NON_NEGATIVE_INTEGER_ENCODING_LENGTH,
        )?);
    }

    // c = hash_to_scalar(c_for_hash, 1)
    Ok(Challenge(C::hash_to_scalar(&data_to_hash, 1, None)?[0]))
}
