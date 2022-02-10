use super::{MessageGenerators, PokSignature, PokSignatureProof, Signature};
use crate::schemes::core::*;
use digest::{ExtendableOutput, Update, XofReader};

/// A Prover is whomever receives signatures or uses them to generate proofs.
/// Provided are methods for 2PC where some are only known to the prover and a blind signature
/// is created, unblinding signatures, verifying signatures, and creating signature proofs of knowledge
/// with selective disclosure proofs
pub struct Prover;

impl Prover {
    /// Derives a signature proof of knowledge
    pub fn derive_signature_pok(
        signature: Signature,
        generators: &MessageGenerators,
        presentation_message: PresentationMessage,
        messages: &[ProofMessage],
    ) -> Result<PokSignatureProof, Error> {
        let mut pok = PokSignature::init(signature, generators, messages).unwrap();

        let mut data = [0u8; COMMITMENT_G1_BYTES];
        let mut hasher = sha3::Shake256::default();
        pok.add_proof_contribution(&mut hasher);
        hasher.update(presentation_message.to_bytes());
        let mut reader = hasher.finalize_xof();
        reader.read(&mut data[..]);
        let challenge = Challenge::from_okm(&data);

        Ok(pok.generate_proof(challenge).unwrap())
    }
}
