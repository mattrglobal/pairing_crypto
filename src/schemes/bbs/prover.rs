use super::{MessageGenerators, PokSignature, Signature};
use crate::schemes::core::*;

/// A Prover is whomever receives signatures or uses them to generate proofs.
/// Provided are methods for 2PC where some are only known to the prover and a blind signature
/// is created, unblinding signatures, verifying signatures, and creating signature proofs of knowledge
/// with selective disclosure proofs
pub struct Prover;

impl Prover {
    /// Create a new signature proof of knowledge and selective disclosure proof
    /// from a verifier's request
    pub fn commit_signature_pok(
        signature: Signature,
        generators: &MessageGenerators,
        messages: &[ProofMessage],
    ) -> Result<PokSignature, Error> {
        PokSignature::init(signature, generators, messages)
    }
}
