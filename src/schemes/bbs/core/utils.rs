#![allow(non_snake_case)]

use super::{
    generator::Generators,
    key_pair::PublicKey,
    types::{Challenge, Message},
};
use crate::{
    bbs::ciphersuites::BbsCiphersuiteParameters,
    common::{
        h2s::constant::{
            NON_NEGATIVE_INTEGER_ENCODING_LENGTH,
            XOF_NO_OF_BYTES,
        },
        serialization::{i2osp, i2osp_with_data},
    },
    curves::{
        bls12_381::{
            hash_to_curve::{ExpandMessage, ExpandMessageState},
            G1Projective,
            Scalar,
        },
        point_serde::point_to_octets_g1,
    },
    error::Error,
};
use ff::Field;

#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;
use group::Group;

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
    let mut data_to_hash = vec![];
    data_to_hash.extend(PK.to_octets().as_ref());
    data_to_hash.extend(i2osp(L as u64, NON_NEGATIVE_INTEGER_ENCODING_LENGTH)?);
    data_to_hash.extend(point_to_octets_g1(&generators.Q_1()).as_ref());
    data_to_hash.extend(point_to_octets_g1(&generators.Q_2()).as_ref());

    for generator in generators.message_generators_iter() {
        data_to_hash.extend(point_to_octets_g1(&generator).as_ref());
    }
    for generator in generators.extension_generators_iter() {
        data_to_hash.extend(point_to_octets_g1(&generator).as_ref());
    }
    // As of now we support only BLS12/381 ciphersuite, it's OK to use this
    // constant here. This should be passed as ciphersuite specific const as
    // generic parameter when initializing a curve specific ciphersuite.
    data_to_hash.extend(i2osp_with_data(
        C::ID.as_octets(),
        NON_NEGATIVE_INTEGER_ENCODING_LENGTH,
    )?);
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
pub(crate) fn compute_B<G, C>(
    s: &Scalar,
    domain: &Scalar,
    messages: &[Message],
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

    let mut points: Vec<_> = vec![C::p1(), generators.Q_1(), generators.Q_2()];
    points.extend(generators.message_generators_iter());
    let mut scalars: Vec<_> = [Scalar::one(), *s, *domain]
        .iter()
        .copied()
        .chain(messages.iter().map(|c| c.0))
        .collect();

    for generator in generators.extension_generators_iter() {
        points.push(generator);
        scalars.push(Scalar::one());
    }

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
    C: BbsCiphersuiteParameters,
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
        data_to_hash.extend(msg.to_bytes());
    }
    data_to_hash.extend(domain.to_bytes_be());
    if let Some(ph) = ph {
        data_to_hash.extend(i2osp_with_data(
            ph.as_ref(),
            NON_NEGATIVE_INTEGER_ENCODING_LENGTH,
        )?);
    }

    // c = hash_to_scalar(c_for_hash, 1)
    Ok(Challenge(C::hash_to_scalar(&data_to_hash, 1, None)?[0]))
}

// A convenient wrapper over underlying `hash_to_curve_g1` implementation(from
/// pairing lib) which is used in `Generators` creation.
pub(crate) fn do_create_generators<C, X>(
    count: usize,
    n: &mut u64,
    v: &mut [u8; XOF_NO_OF_BYTES],
    with_fresh_state: bool,
) -> Result<Vec<G1Projective>, Error>
where
    C: BbsCiphersuiteParameters,
    X: ExpandMessage,
{
    let generator_seed_dst = C::generator_seed_dst();

    if with_fresh_state {
        *n = 1;

        //  v = expand_message(generator_seed, seed_dst, seed_len)
        let mut expander = X::init_expand(
            &C::generator_seed(),
            &generator_seed_dst,
            XOF_NO_OF_BYTES,
        );
        expander.read_into(v);
    }

    let mut points = Vec::with_capacity(count);

    let mut i = 0;
    while i < count {
        // v = expand_message(v || I2OSP(n, 4), seed_dst, seed_len)
        let mut expander = X::init_expand(
            &[v.as_ref(), &i2osp(*n, 4)?].concat(),
            &generator_seed_dst,
            XOF_NO_OF_BYTES,
        );
        expander.read_into(v);

        *n += 1;

        // candidate = hash_to_curve_g1(v, generator_dst)
        let candidate = G1Projective::hash_to::<X>(v, &C::generator_dst());

        if (candidate.is_identity().unwrap_u8() == 1)
            || candidate == C::p1()
            || points.iter().any(|e| e == &candidate)
        {
            continue;
        }

        points.push(candidate);
        i += 1;
    }
    Ok(points)
}
