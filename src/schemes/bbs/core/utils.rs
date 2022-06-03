use super::{
    constants::XOF_NO_OF_BYTES,
    generator::Generators,
    public_key::PublicKey,
    types::Message,
};
use crate::{
    curves::bls12_381::{G1Projective, Scalar},
    error::Error,
};
use digest::{ExtendableOutput, Update, XofReader};
use ff::Field;
use group::{Curve, Group};
use sha3::Shake256;

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
    hasher.update(PK.to_bytes());
    let L: usize = generators.message_blinding_points_length();
    hasher.update(L.to_be_bytes());
    hasher.update(generators.H_s().to_affine().to_uncompressed());
    hasher.update(generators.H_d().to_affine().to_uncompressed());
    for generator in generators.message_blinding_points_iter() {
        hasher.update(generator.to_uncompressed());
    }
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
