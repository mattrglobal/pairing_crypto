use super::{
    constants::{
        g1_affine_compressed_size,
        BBS_CIPHERSUITE_ID,
        OCTETS_MESSAGE_LENGTH_ENCODING_LENGTH,
    },
    generator::Generators,
    hash_utils::hash_to_scalar,
    public_key::PublicKey,
    types::Message,
};
use crate::{
    common::serialization::{i2osp, i2osp_with_data},
    curves::bls12_381::{G1Affine, G1Projective, Scalar},
    error::Error,
};
use ff::Field;
use group::{Curve, Group};

/// Get the representation of a point G1(in Projective form) to compressed
/// and big-endian octets form.
pub(crate) fn point_to_octets_g1(
    p: &G1Projective,
) -> [u8; g1_affine_compressed_size()] {
    p.to_affine().to_compressed()
}

/// Convert from octets in affine, compressed and big-endian form to
/// `G1Projective` type.
pub(crate) fn octets_to_point_g1(
    octets: &[u8; g1_affine_compressed_size()],
) -> Result<G1Projective, Error> {
    let result = G1Affine::from_compressed(octets).map(G1Projective::from);
    if result.is_some().unwrap_u8() == 1u8 {
        Ok(result.unwrap())
    } else {
        Err(Error::CryptoBadEncoding)
    }
}

/// Computes `domain` value.
/// domain =
///    hash_to_scalar((PK || L || generators || Ciphersuite_ID || header), 1)
#[allow(non_snake_case)]
pub(crate) fn compute_domain<T>(
    PK: &PublicKey,
    header: Option<T>,
    L: usize,
    generators: &Generators,
) -> Result<Scalar, Error>
where
    T: AsRef<[u8]>,
{
    // Error out if length of messages and generators are not equal
    if L != generators.message_blinding_points_length() {
        return Err(Error::CryptoMessageGeneratorsLengthMismatch {
            generators: generators.message_blinding_points_length(),
            messages: L,
        });
    }

    // domain = hash_to_scalar((PK || L || generators || Ciphersuite_ID ||
    // header), 1)
    let mut data_to_hash = vec![];
    data_to_hash.extend(i2osp_with_data(
        PK.point_to_octets().as_ref(),
        OCTETS_MESSAGE_LENGTH_ENCODING_LENGTH,
    )?);
    data_to_hash
        .extend(i2osp(L as u64, OCTETS_MESSAGE_LENGTH_ENCODING_LENGTH)?);
    data_to_hash.extend(i2osp_with_data(
        point_to_octets_g1(&generators.H_s()).as_ref(),
        OCTETS_MESSAGE_LENGTH_ENCODING_LENGTH,
    )?);
    data_to_hash.extend(i2osp_with_data(
        point_to_octets_g1(&generators.H_d()).as_ref(),
        OCTETS_MESSAGE_LENGTH_ENCODING_LENGTH,
    )?);
    for generator in generators.message_blinding_points_iter() {
        data_to_hash.extend(i2osp_with_data(
            point_to_octets_g1(generator).as_ref(),
            OCTETS_MESSAGE_LENGTH_ENCODING_LENGTH,
        )?);
    }
    // As of now we support only BLS12/381 ciphersuite, it's OK to use this
    // constant here. This should be passed as ciphersuite specific const as
    // generic parameter when initializing a curve specific ciphersuite.
    data_to_hash.extend(i2osp_with_data(
        BBS_CIPHERSUITE_ID,
        OCTETS_MESSAGE_LENGTH_ENCODING_LENGTH,
    )?);
    if let Some(header) = header {
        data_to_hash.extend(i2osp_with_data(
            header.as_ref(),
            OCTETS_MESSAGE_LENGTH_ENCODING_LENGTH,
        )?);
    }

    Ok(hash_to_scalar(data_to_hash, 1)?[0])
}

/// Computes `B` value.
/// B = P1 + H_s * s + H_d * domain + H_1 * msg_1 + ... + H_L * msg_L
#[allow(non_snake_case)]
pub(crate) fn compute_B(
    s: &Scalar,
    domain: &Scalar,
    messages: &[Message],
    generators: &Generators,
) -> Result<G1Projective, Error> {
    // Input params check
    // Error out if length of generators and messages are not equal
    if messages.len() != generators.message_blinding_points_length() {
        return Err(Error::CryptoMessageGeneratorsLengthMismatch {
            generators: generators.message_blinding_points_length(),
            messages: messages.len(),
        });
    }

    // Spec doesn't define P1, using G1Projective::generator() as P1
    let mut points: Vec<_> = vec![
        G1Projective::generator(),
        generators.H_s(),
        generators.H_d(),
    ];
    points.extend(generators.message_blinding_points_iter());
    let scalars: Vec<_> = [Scalar::one(), *s, *domain]
        .iter()
        .copied()
        .chain(messages.iter().map(|c| c.0))
        .collect();

    Ok(G1Projective::multi_exp(&points, &scalars))
}
