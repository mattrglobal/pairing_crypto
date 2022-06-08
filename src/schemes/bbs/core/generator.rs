use super::constants::{HASH_TO_CURVE_G1_DST, XOF_NO_OF_BYTES};
use crate::curves::bls12_381::G1Projective;
use group::Group;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Sha3XofReader,
    Shake256,
};

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
    ) -> Self {
        // Generate H_s
        let H_s = Self::generate_single_point(blind_value_generator_seed);

        // Generate H_d
        let H_d = Self::generate_single_point(sig_domain_generator_seed);

        // Generate H

        // Return early if requsted message blinding generators are zero
        if no_of_message_generators == 0 {
            return Self {
                H_s,
                H_d,
                message_generators: vec![],
            };
        }

        let mut message_blinding_points =
            Vec::with_capacity(no_of_message_generators);

        let mut hasher = Shake256::default();
        hasher.update(message_generator_seed);
        hasher.update(HASH_TO_CURVE_G1_DST);

        let mut xof_reader = hasher.finalize_xof();

        for _ in 0..no_of_message_generators {
            message_blinding_points
                .push(Self::generate_single_point_helper(&mut xof_reader));
        }

        Self {
            H_s,
            H_d,
            message_generators: message_blinding_points,
        }
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

    fn generate_single_point<T: AsRef<[u8]>>(seed: T) -> G1Projective {
        let mut hasher = Shake256::default();
        hasher.update(seed);
        let mut xof_reader = hasher.finalize_xof();

        Self::generate_single_point_helper(&mut xof_reader)
    }

    fn generate_single_point_helper(
        xof_reader: &mut Sha3XofReader,
    ) -> G1Projective {
        let mut data_to_hash = [0u8; XOF_NO_OF_BYTES];

        // Note: If underlying H2C conversion from hashed data is returing
        // Identity or base Generator P1 continuously, this loop will iterate
        // infinetly.
        loop {
            xof_reader.read(&mut data_to_hash);
            let candidate = G1Projective::hash_to_curve(
                &data_to_hash,
                HASH_TO_CURVE_G1_DST,
                &[],
            );
            // Spec doesn't define P1
            let P1 = G1Projective::generator();
            if (candidate.is_identity().unwrap_u8() == 1) || candidate == P1 {
                continue;
            }
            return candidate;
        }
    }
}

#[test]
fn basic() {
    let generators = Generators::new(&[], &[], &[], 32);
    assert_eq!(generators.message_blinding_points_length(), 32);
}
