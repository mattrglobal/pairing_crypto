#![allow(non_snake_case)]

use std::collections::BTreeMap;

use blstrs::{G1Projective, Scalar};

use super::pseudonym::Pseudonym;
use crate::{
    bbs::{
        ciphersuites::BbsCiphersuiteParameters,
        core::{
            generator::Generators,
            key_pair::PublicKey,
            proof::{Proof, RandomScalars},
            signature::Signature,
            types::{CommitProofInitResult, Message, ProofMessage},
            utils::compute_challenge,
        },
        interface::BbsInterfaceParameter,
    },
    common::util::create_random_scalar,
    curves::bls12_381::{Bls12, G2Prepared},
    error::Error,
};
use group::{Curve, Group};
use pairing::{MillerLoopResult as _, MultiMillerLoop};
use rand::{CryptoRng, RngCore};
use rand_core::OsRng;

pub(crate) struct ProofWithNym(pub(crate) Proof);

impl core::fmt::Display for ProofWithNym {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl ProofWithNym {
    // TODO: remove the clippy warning de-activation
    #[allow(clippy::too_many_arguments)]
    pub fn new<T, G, I>(
        PK: &PublicKey,
        signature: &Signature,
        pseudonym: &Pseudonym,
        verifier_id: T,
        prover_id: Message,
        header: Option<T>,
        ph: Option<T>,
        generators: &G,
        messages: &[ProofMessage],
    ) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
        G: Generators,
        I: BbsInterfaceParameter,
    {
        Self::new_with_rng::<_, _, _, I>(
            PK,
            signature,
            pseudonym,
            verifier_id,
            prover_id,
            header,
            ph,
            generators,
            messages,
            OsRng,
        )
    }

    // TODO: remove the clippy warning de-activation
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_rng<T, R, G, I>(
        PK: &PublicKey,
        signature: &Signature,
        pseudonym: &Pseudonym,
        verifier_id: T,
        prover_id: Message,
        header: Option<T>,
        ph: Option<T>,
        generators: &G,
        messages: &[ProofMessage],
        mut rng: R,
    ) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
        R: RngCore + CryptoRng,
        G: Generators,
        I: BbsInterfaceParameter,
    {
        // (r1, r2, r3, m~_j1, ..., m~_jU) = calculate_random_scalars(3+U)
        let mut random_scalars = RandomScalars {
            r1: create_random_scalar(&mut rng)?,
            r2_tilde: create_random_scalar(&mut rng)?,
            z_tilde: create_random_scalar(&mut rng)?,
            ..Default::default()
        };

        // Deserialization steps of the `ProofGen` operation defined in https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-proofgen
        // TODO: Update reference
        //
        // Deserialization:
        // ...(implicit steps)...
        // 4. messages.push(prover_id)
        // ...(implicit steps)...
        // 10. undisclosed_indexes = range(1, L) \ disclosed_indexes
        // 11. disclosed_messages = (messages[i1], ..., messages[iR])
        let mut messages_vec = messages.to_vec();
        messages_vec.push(ProofMessage::Hidden(prover_id));

        let message_scalars: Vec<Scalar> =
            messages_vec.iter().map(|m| m.get_message().0).collect();

        let mut undisclosed_indexes = Vec::new();
        let mut disclosed_messages = BTreeMap::new();
        let mut undisclosed_message_scalars = Vec::new();
        for (i, message) in messages_vec.iter().enumerate() {
            match message {
                ProofMessage::Revealed(m) => {
                    disclosed_messages.insert(i, *m);
                }
                ProofMessage::Hidden(m) => {
                    undisclosed_indexes.push(i);
                    undisclosed_message_scalars.push(m.0);

                    // Get the random scalars m~_j1, ..., m~_jU
                    random_scalars
                        .insert_m_tilde(create_random_scalar(&mut rng)?);
                }
            }
        }

        let init_result = Proof::proof_init::<T, G, I>(
            PK,
            signature,
            generators,
            &random_scalars,
            header,
            message_scalars,
            undisclosed_indexes,
        )?;

        // Pseudonym correctness proof init
        let OP = I::hash_to_curve(verifier_id.as_ref())?;

        let pid_tilde = random_scalars.m_tilde_scalars.last().unwrap();
        let pseudonym_proof_init = CommitProofInitResult {
            commit: pseudonym.as_point(),
            commit_base: OP,
            blind_commit: OP * pid_tilde,
        };

        // challenge calculation
        let challenge = compute_challenge::<_, I>(
            &init_result,
            &disclosed_messages,
            ph,
            Some(pseudonym_proof_init),
        )?;

        // finalize proof
        let proof = Proof::proof_finalize(
            challenge,
            signature.e,
            random_scalars,
            init_result,
            undisclosed_message_scalars,
        );

        match proof {
            Ok(proof_val) => Ok(ProofWithNym(proof_val)),
            Err(e) => Err(e),
        }
    }

    // TODO: Remove this clippy warning de-activation
    #[allow(clippy::too_many_arguments)]
    pub fn verify<T, G, I>(
        &self,
        PK: &PublicKey,
        pseudonym: &Pseudonym,
        verifier_id: T,
        header: Option<T>,
        ph: Option<T>,
        generators: &G,
        disclosed_messages: &BTreeMap<usize, Message>,
    ) -> Result<bool, Error>
    where
        T: AsRef<[u8]>,
        G: Generators,
        I: BbsInterfaceParameter,
    {
        // if KeyValidate(PK) is INVALID, return INVALID
        // `PK` should not be an identity and should belong to subgroup G2
        if PK.is_valid().unwrap_u8() == 0u8 {
            return Err(Error::InvalidPublicKey);
        }

        // the pseudonym should be a point of G1 but not any of the constant
        // "reserved" points (i.e., the identity of G1 or the base
        // generator and the base point of G1).
        if pseudonym.is_valid::<I::Ciphersuite>().unwrap_u8() == 0u8 {
            return Err(Error::InvalidPseudonym);
        }

        // Check that the m_hat_list is not empty (the prover_id
        // should always be undisclosed).
        if self.0.m_hat_list.is_empty() {
            return Err(Error::BadParams {
                cause: "At least on message must be undisclosed".to_owned(),
            });
        }

        // Check that the last message (the prover_id) is not revealed
        if let Some(val) = disclosed_messages.last_key_value() {
            if *val.0 == self.0.m_hat_list.len() + disclosed_messages.len() {
                return Err(Error::BadParams {
                    cause: "The last signed message should not be revealed"
                        .to_owned(),
                });
            }
        }

        // initialize the proof verification procedure
        let init_res = self.0.proof_verify_init::<T, G, I>(
            PK,
            header,
            generators,
            disclosed_messages,
        )?;

        // initialize the pseudonym correctness proof verification procedure
        let OP = I::hash_to_curve(verifier_id.as_ref())?;
        let pseudonym_point = pseudonym.as_point();
        let proof_challenge = self.0.c;

        // unwrap() is safe here since we check that m_hat_list is non empty
        let Uv = G1Projective::multi_exp(
            &[OP, pseudonym_point],
            &[self.0.m_hat_list.last().unwrap().0, -proof_challenge.0],
        );

        let pseudonym_proof_verify_init = CommitProofInitResult {
            commit: pseudonym_point,
            commit_base: OP,
            blind_commit: Uv,
        };

        let challenge = compute_challenge::<_, I>(
            &init_res,
            disclosed_messages,
            ph,
            Some(pseudonym_proof_verify_init),
        )?;

        // Check the selective disclosure proof
        // if c != cv, return INVALID
        if proof_challenge != challenge {
            return Ok(false);
        }

        // This check is already done during `Proof` deserialization
        // if Abar == 1, return INVALID
        if self.0.A_bar.is_identity().unwrap_u8() == 1 {
            return Err(Error::PointIsIdentity);
        }

        // Check the signature proof
        // if e(Abar, W) * e(Abar, -P2) != 1, return INVALID
        // else return VALID
        let P2 = I::Ciphersuite::p2().to_affine();
        Ok(Bls12::multi_miller_loop(&[
            (
                &self.0.A_bar.to_affine(),
                &G2Prepared::from(PK.0.to_affine()),
            ),
            (&self.0.B_bar.to_affine(), &G2Prepared::from(-P2)),
        ])
        .final_exponentiation()
        .is_identity()
        .unwrap_u8()
            == 1)
    }

    pub fn to_octets(&self) -> Vec<u8> {
        self.0.to_octets()
    }

    pub fn from_octets<B: AsRef<[u8]>>(bytes: B) -> Result<Self, Error> {
        let proof = Proof::from_octets(bytes);
        match proof {
            Ok(proof_val) => Ok(ProofWithNym(proof_val)),
            Err(e) => Err(e),
        }
    }
}
