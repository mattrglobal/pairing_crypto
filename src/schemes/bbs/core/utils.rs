use super::{
    constants::{
        g1_affine_compressed_size,
        BBS_CIPHERSUITE_ID,
        XOF_NO_OF_BYTES,
    },
    generator::Generators,
    public_key::PublicKey,
    types::Message,
};
use crate::{
    curves::bls12_381::{G1Affine, G1Projective, Scalar},
    error::Error,
};
use digest::{ExtendableOutput, Update, XofReader};
use ff::Field;
use group::{Curve, Group};
use sha3::Shake256;

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
    header: T,
    generators: &Generators,
) -> Scalar
where
    T: AsRef<[u8]>,
{
    let mut res = [0u8; XOF_NO_OF_BYTES];

    let mut hasher = Shake256::default();

    // domain = hash_to_scalar((PK || L || generators || Ciphersuite_ID ||
    // header), 1)

    hasher.update(PK.point_to_octets());

    let L: usize = generators.message_blinding_points_length();
    hasher.update(L.to_be_bytes());

    hasher.update(point_to_octets_g1(&generators.H_s()));
    hasher.update(point_to_octets_g1(&generators.H_d()));
    for generator in generators.message_blinding_points_iter() {
        hasher.update(point_to_octets_g1(generator));
    }
    // As of now we support only BLS12/381 ciphersuite, it's OK to use this
    // constant here. This should be passed as ciphersuite specific const as
    // generic parameter when initializing a curve specific ciphersuite.
    hasher.update(BBS_CIPHERSUITE_ID);
    hasher.update(header);

    let mut reader = hasher.finalize_xof();
    loop {
        reader.read(&mut res);

        let domain = Scalar::from_bytes_wide(&res);
        if domain.is_none().unwrap_u8() == 1u8 {
            continue;
        } else {
            return domain.unwrap();
        }
    }
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
    if messages.len() != generators.message_blinding_points_length() {
        return Err(Error::BadParams {
            cause: format!(
                "mismatched length: number of messages {}, number of \
                 generators {}",
                messages.len(),
                generators.message_blinding_points_length()
            ),
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
