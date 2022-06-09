#![allow(non_snake_case)]

use super::{
    constants::OCTETS_MESSAGE_LENGTH_ENCODING_LENGTH,
    generator::Generators,
    hash_utils::hash_to_scalar,
    pok_signature_proof::PokSignatureProof,
    proof_committed_builder::ProofCommittedBuilder,
    public_key::PublicKey,
    signature::Signature,
    types::{Challenge, HiddenMessage, ProofMessage},
    utils::{compute_B, compute_domain, point_to_octets_g1},
};
use crate::{
    common::serialization::i2osp_with_data,
    curves::bls12_381::{G1Affine, G1Projective, Scalar},
    error::Error,
};
use ff::Field;
use rand_core::{CryptoRng, RngCore};

/// Proof of Knowledge of a Signature that is used by the prover
/// to construct `PoKOfSignatureProof`.
pub struct PokSignature {
    /// A'
    A_prime: G1Projective,
    /// \overline{A}
    A_bar: G1Projective,
    /// D
    D: G1Projective,
    /// For proving relation `(A_bar - D) == A' * -e + H_s * r2`
    proof1: ProofCommittedBuilder<G1Projective, G1Affine>,
    /// Secrets of `e` and `r2` associated to proof1
    secrets1: [Scalar; 2],
    /// For proving relation
    /// g1 + h1*m1 + h2*m2.... for all disclosed messages m_i
    ///   == D*r3 + H_s*{-s'} + h1*m1 + h2*m2.... for all undisclosed msgs m_j
    proof2: ProofCommittedBuilder<G1Projective, G1Affine>,
    /// The blinding factors: r3, s' and for msg_j1...msg_jU
    secrets2: Vec<Scalar>,
}

impl PokSignature {
    // Number of fixed secret points in proof2 or commitment2 vector are `r3`
    // and `s'`.
    const NUM_PROOF2_FIXED_POINTS: usize = 2;
    /// Creates the initial proof data before a Fiat-Shamir calculation.
    /// This method follows `ProofGen` API as defined in BBS Signature spec
    /// <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#section-3.3.6>
    pub fn init<T>(
        PK: &PublicKey,
        signature: &Signature,
        header: Option<T>,
        generators: &Generators,
        messages: &[ProofMessage],
    ) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
    {
        Self::init_with_rng(
            PK,
            signature,
            header,
            generators,
            messages,
            rand::rngs::OsRng::default(),
        )
    }

    /// Creates the initial proof data before a Fiat-Shamir calculation as
    /// defined in `ProofGen` API in BBS Signature spec <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#section-3.3.6>
    #[allow(clippy::needless_range_loop)]
    pub fn init_with_rng<T>(
        PK: &PublicKey,
        signature: &Signature,
        header: Option<T>,
        generators: &Generators,
        messages: &[ProofMessage],
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
    {
        // Error out if length of messages and generators are not equal
        if messages.len() != generators.message_blinding_points_length() {
            return Err(Error::CryptoMessageGeneratorsLengthMismatch {
                generators: generators.message_blinding_points_length(),
                messages: messages.len(),
            });
        }

        // (r1, r2, e~, r2~, r3~, s~) = hash_to_scalar(PRF(8*ceil(log2(r))), 6)
        // generate r1 and r2 here, rest of the random scalars will be generated
        // further below using ProofCommittedBuilder::commit_random(...)
        // in `proof1` variable
        let r1 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);

        // (m~_j1, ..., m~_jU) =  hash_to_scalar(PRF(8*ceil(log2(r))), U)
        // these random scalars will be generated further below using
        // ProofCommittedBuilder::commit_random(...) in `proof2` variable

        // domain
        //  = hash_to_scalar((PK||L||generators||Ciphersuite_ID||header), 1)
        let domain = compute_domain(PK, header, messages.len(), generators)?;

        let m: Vec<_> = messages.iter().map(|m| m.get_message()).collect();
        // B = P1 + H_s * s + H_d * domain + H_1 * msg_1 + ... + H_L * msg_L
        let B = compute_B(&signature.s, &domain, m.as_ref(), generators)?;

        // r3 = r1 ^ -1 mod r
        let r3 = r1.invert();
        if r3.is_none().unwrap_u8() == 1u8 {
            return Err(Error::CryptoOps {
                cause: "Failed to invert `r3`".to_owned(),
            });
        };
        let r3 = r3.unwrap();

        // A' = A * r1
        let A_prime = signature.A * r1;

        // Abar = A' * (-e) + B * r1
        let A_bar = B * r1 - A_prime * signature.e;

        // D = B * r1 + H_s * r2
        let D = G1Projective::multi_exp(&[B, generators.H_s()], &[r1, r2]);

        // s' = s + r2 * r3
        let s_prime = signature.s + r2 * r3;

        // Commit the components of
        // C1 = A' * e~ + H_s * r2~
        let mut C1_builder =
            ProofCommittedBuilder::<G1Projective, G1Affine>::new(
                G1Projective::multi_exp,
            );
        // Set the secret values associated to the proof
        let C1_secrets = [signature.e, r2];
        // For A' * e~
        C1_builder.commit_random(A_prime, &mut rng);
        // For H_s * r2~
        C1_builder.commit_random(generators.H_s(), &mut rng);

        // Commit the components of
        //  C2 = D * (-r3~) + H_s * s~ + H_j1 * m~_j1 + ... + H_jU * m~_jU
        let mut C2_builder =
            ProofCommittedBuilder::<G1Projective, G1Affine>::new(
                G1Projective::multi_exp,
            );
        let mut C2_secrets = Vec::new();
        C2_secrets.push(r3);
        C2_secrets.push(s_prime);
        // For D * (-r3~)
        C2_builder.commit_random(-D, &mut rng);
        // For H_s * s~
        C2_builder.commit_random(generators.H_s(), &mut rng);
        for (i, generator) in
            generators.message_blinding_points_iter().enumerate()
        {
            match messages[i] {
                ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(
                    m,
                )) => {
                    C2_builder.commit_random(*generator, &mut rng);
                    C2_secrets.push(m.0);
                }
                ProofMessage::Hidden(HiddenMessage::ExternalBlinding(m, e)) => {
                    C2_builder.commit(*generator, e.0);
                    C2_secrets.push(m.0);
                }
                _ => {}
            }
        }

        Ok(Self {
            A_prime,
            A_bar,
            D,
            proof1: C1_builder,
            secrets1: C1_secrets,
            proof2: C2_builder,
            secrets2: C2_secrets,
        })
    }

    /// Convert the committed values to bytes for the fiat-shamir challenge.
    pub fn compute_challenge<T>(
        &mut self,
        PK: &PublicKey,
        ph: Option<T>,
    ) -> Result<Challenge, Error>
    where
        T: AsRef<[u8]>,
    {
        self.proof1.add_challenge_contribution();
        self.proof2.add_challenge_contribution();

        // c = hash_to_scalar((PK || Abar || A' || D || C1 || C2 || ph), 1)
        let mut data_to_hash = vec![];
        data_to_hash.extend(i2osp_with_data(
            PK.point_to_octets().as_ref(),
            OCTETS_MESSAGE_LENGTH_ENCODING_LENGTH,
        )?);
        data_to_hash.extend(i2osp_with_data(
            point_to_octets_g1(&self.A_bar).as_ref(),
            OCTETS_MESSAGE_LENGTH_ENCODING_LENGTH,
        )?);
        data_to_hash.extend(i2osp_with_data(
            point_to_octets_g1(&self.A_prime).as_ref(),
            OCTETS_MESSAGE_LENGTH_ENCODING_LENGTH,
        )?);
        data_to_hash.extend(i2osp_with_data(
            point_to_octets_g1(&self.D).as_ref(),
            OCTETS_MESSAGE_LENGTH_ENCODING_LENGTH,
        )?);
        data_to_hash.extend(i2osp_with_data(
            point_to_octets_g1(&self.proof1.cache.commitment).as_ref(),
            OCTETS_MESSAGE_LENGTH_ENCODING_LENGTH,
        )?);
        data_to_hash.extend(i2osp_with_data(
            point_to_octets_g1(&self.proof2.cache.commitment).as_ref(),
            OCTETS_MESSAGE_LENGTH_ENCODING_LENGTH,
        )?);
        if let Some(ph) = ph {
            data_to_hash.extend(i2osp_with_data(
                ph.as_ref(),
                OCTETS_MESSAGE_LENGTH_ENCODING_LENGTH,
            )?);
        }
        Ok(Challenge(hash_to_scalar(data_to_hash, 1)?[0]))
    }

    /// Generate the Schnorr challenges for the selective disclosure proofs as
    /// defined in `ProofGen` API in BBS Signature spec <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#section-3.3.6>
    pub fn generate_proof(
        self,
        challenge: Challenge,
    ) -> Result<PokSignatureProof, Error> {
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
        let hidden_message_count =
            self.secrets2.len() - Self::NUM_PROOF2_FIXED_POINTS;
        Ok(PokSignatureProof {
            A_prime: self.A_prime,
            A_bar: self.A_bar,
            D: self.D,
            proofs1,
            proofs2,
            c: challenge,
            hidden_message_count,
        })
    }
}
