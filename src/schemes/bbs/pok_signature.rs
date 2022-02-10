use super::{MessageGenerators, PokSignatureProof, Signature};
use crate::curves::bls12_381::{G1Affine, G1Projective, Scalar};
use crate::schemes::core::*;
use digest::Update;
use ff::Field;
use group::Curve;
use rand_core::{CryptoRng, RngCore};

/// Proof of Knowledge of a Signature that is used by the prover
/// to construct `PoKOfSignatureProof`.
pub struct PokSignature {
    /// A' in section 4.5
    a_prime: G1Projective,
    /// \overline{A} in section 4.5
    a_bar: G1Projective,
    /// d in section 4.5
    d: G1Projective,
    /// For proving relation a_bar / d == a_prime^{-e} * h_0^r2
    proof1: ProofCommittedBuilder<G1Projective, G1Affine>,
    /// The messages
    secrets1: [Scalar; 2],
    /// For proving relation g1 * h1^m1 * h2^m2.... for all disclosed messages m_i == d^r3 * h_0^{-s_prime} * h1^-m1 * h2^-m2.... for all undisclosed messages m_i
    proof2: ProofCommittedBuilder<G1Projective, G1Affine>,
    /// The blinding factors
    secrets2: Vec<Scalar>,
}

impl PokSignature {
    /// Creates the initial proof data before a Fiat-Shamir calculation
    pub fn init(
        signature: Signature,
        generators: &MessageGenerators,
        messages: &[ProofMessage],
    ) -> Result<Self, Error> {
        Self::init_with_rng(
            signature,
            generators,
            messages,
            rand::rngs::OsRng::default(),
        )
    }

    /// Creates the initial proof data before a Fiat-Shamir calculation
    #[allow(clippy::needless_range_loop)]
    pub fn init_with_rng(
        signature: Signature,
        generators: &MessageGenerators,
        messages: &[ProofMessage],
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<Self, Error> {
        if messages.len() != generators.len() {
            return Err(Error::new(1, "mismatched messages with and generators"));
        }
        let r1 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);
        let r3 = r1.invert().unwrap();

        // Set the secret values associated to the proof
        let secrets1 = [signature.e, r2];
        let mut secrets2 = Vec::new();
        let m: Vec<_> = messages.iter().map(|m| m.get_message()).collect();

        // b = commitment + h0 \* s + h\[1\] \* msg\[1\] + ... + h\[L\] \* msg\[L\]
        let b = Signature::compute_b(signature.s, m.as_ref(), generators);

        // A' = A \* r1
        let a_prime = signature.a * r1;
        // a_bar = A' \* -e + b \* r1
        let a_bar = b * r1 - a_prime * signature.e;

        // d = b * r1 + h0 * r2
        let d = G1Projective::sum_of_products_in_place(&[b, generators.h0], [r1, r2].as_mut());

        // s' = s - r2 r3
        let s_prime = signature.s + r2 * r3;

        secrets2.push(r3);
        secrets2.push(s_prime);

        // For proving relation a_bar / d == a_prime^{-e} * h_0^r2
        let mut proof1 = ProofCommittedBuilder::<G1Projective, G1Affine>::new(
            G1Projective::sum_of_products_in_place,
        );

        // Compute the components of C1 = A' * e~ + h0 * r2~
        // For A' * -e
        proof1.commit_random(a_prime, &mut rng);
        // For h0 * r2
        proof1.commit_random(generators.h0, &mut rng);

        // Compute the components of C2 = ...
        let mut proof2 = ProofCommittedBuilder::<G1Projective, G1Affine>::new(
            G1Projective::sum_of_products_in_place,
        );

        // for d * -r3
        proof2.commit_random(-d, &mut rng);
        // for h0 * s_prime
        proof2.commit_random(generators.h0, &mut rng);

        for i in 0..generators.len() {
            match messages[i] {
                ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(m)) => {
                    proof2.commit_random(generators.get(i), &mut rng);
                    secrets2.push(m.0);
                }
                ProofMessage::Hidden(HiddenMessage::ExternalBlinding(m, e)) => {
                    proof2.commit(generators.get(i), e.0);
                    secrets2.push(m.0);
                }
                _ => {}
            }
        }

        Ok(Self {
            a_prime,
            a_bar,
            d,
            proof1,
            secrets1,
            proof2,
            secrets2,
        })
    }

    /// Convert the committed values to bytes for the fiat-shamir challenge
    pub fn add_proof_contribution(&mut self, hasher: &mut impl Update) {
        hasher.update(self.a_prime.to_affine().to_uncompressed());
        hasher.update(self.a_bar.to_affine().to_uncompressed()); // TODO this is different from the spec
        hasher.update(self.d.to_affine().to_uncompressed());
        self.proof1.add_challenge_contribution(hasher);
        self.proof2.add_challenge_contribution(hasher);
    }

    /// Generate the Schnorr challenges for the selective disclosure proofs
    pub fn generate_proof(self, challenge: Challenge) -> Result<PokSignatureProof, Error> {
        let proof1 = self
            .proof1
            .generate_proof(challenge.0, self.secrets1.as_ref())?;
        let proofs1 = [Challenge(proof1[0]), Challenge(proof1[1])];
        let proofs2: Vec<_> = self
            .proof2
            .generate_proof(challenge.0, self.secrets2.as_ref())?
            .iter()
            .map(|s| Challenge(*s))
            .collect();
        Ok(PokSignatureProof {
            a_prime: self.a_prime,
            a_bar: self.a_bar,
            d: self.d,
            proofs1,
            proofs2,
        })
    }
}
