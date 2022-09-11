use group::Curve;

use crate::{
    curves::bls12_381::{
        G1Affine,
        G1Projective,
        G2Affine,
        G2Projective,
        OCTET_POINT_G1_LENGTH,
        OCTET_POINT_G2_LENGTH,
    },
    error::Error,
};

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

/// Get the representation of a point G2(in Projective form) to compressed
/// and big-endian octets form.
pub(crate) fn point_to_octets_g2(
    p: &G2Projective,
) -> [u8; OCTET_POINT_G2_LENGTH] {
    p.to_affine().to_compressed()
}

/// Convert from octets in affine, compressed and big-endian form to
/// `G2Projective` type.
pub(crate) fn octets_to_point_g2(
    octets: &[u8; OCTET_POINT_G2_LENGTH],
) -> Result<G2Projective, Error> {
    let result = G2Affine::from_compressed(octets).map(G2Projective::from);
    if result.is_some().unwrap_u8() == 1u8 {
        Ok(result.unwrap())
    } else {
        Err(Error::BadEncoding)
    }
}
