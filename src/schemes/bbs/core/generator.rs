use super::hash_utils::create_generators;
use crate::{curves::bls12_381::G1Projective, error::Error};

/// The generators that are used to sign a vector of commitments for a BBS
/// signature. These must be the same generators used by sign, verify, prove,
/// and verify proof.
#[allow(non_snake_case)]
#[derive(Debug, Clone)]
pub struct Generators {
    H_s: G1Projective,
    H_d: G1Projective,
    message_generators: Vec<G1Projective>,
}

#[allow(non_snake_case)]
impl Generators {
    /// Construct `Generators` from the given `seed` values.
    /// The implementation follows `CreateGenerators` section as defined in <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-creategenerators>.
    pub fn new<T: AsRef<[u8]>>(
        blind_value_generator_seed: T,
        sig_domain_generator_seed: T,
        message_generator_seed: T,
        no_of_message_generators: usize,
    ) -> Result<Self, Error> {
        Ok(Self {
            H_s: create_generators(blind_value_generator_seed, 1)?[0],
            H_d: create_generators(sig_domain_generator_seed, 1)?[0],
            message_generators: create_generators(
                message_generator_seed,
                no_of_message_generators,
            )?,
        })
    }

    /// Get `H_s`, the generator point for the blinding value (s) of the
    /// signature.
    pub fn H_s(&self) -> G1Projective {
        self.H_s
    }

    /// Get `H_d`, the generator point for the domain of the signature.
    pub fn H_d(&self) -> G1Projective {
        self.H_d
    }

    /// The number of message blinding generators this `Generators` instance
    /// holds.
    pub fn message_blinding_points_length(&self) -> usize {
        self.message_generators.len()
    }

    /// Get the message blinding generator at `index`.
    /// Note `MessageGenerators` is zero indexed, so passed `index` value should
    /// be in [0, `length`) range. In case of invalid `index`, `None` value
    /// is returned.
    pub fn get_message_blinding_point(
        &self,
        index: usize,
    ) -> Option<G1Projective> {
        if index >= self.message_generators.len() {
            return None;
        }
        Some(self.message_generators[index])
    }

    /// Get a `core::slice::Iter` for message blinding generators.
    pub fn message_blinding_points_iter(
        &self,
    ) -> core::slice::Iter<'_, G1Projective> {
        self.message_generators.iter()
    }
}
