#![allow(dead_code)]
#![allow(unused)]
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
    pub fn new<T, G, C>(
        PK: &PublicKey,
        signature: &Signature,
        nym: &Pseudonym,
        verifier_id: T,
        pid: Message,
        header: Option<T>,
        ph: Option<T>,
        generators: &G,
        messages: &[ProofMessage],
        api_id: Option<Vec<u8>>,
    ) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
        G: Generators,
        C: BbsCiphersuiteParameters,
    {
        Self::new_with_rng::<_, _, _, C>(
            PK,
            signature,
            nym,
            verifier_id,
            pid,
            header,
            ph,
            generators,
            messages,
            api_id,
            OsRng,
        )
    }

    // TODO: remove the clippy warning de-activation
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_rng<T, R, G, C>(
        PK: &PublicKey,
        signature: &Signature,
        nym: &Pseudonym,
        verifier_id: T,
        pid: Message,
        header: Option<T>,
        ph: Option<T>,
        generators: &G,
        messages: &[ProofMessage],
        api_id: Option<Vec<u8>>,
        mut rng: R,
    ) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
        R: RngCore + CryptoRng,
        G: Generators,
        C: BbsCiphersuiteParameters,
    {
        if header.is_none() && messages.is_empty() {
            return Err(Error::BadParams {
                cause: "nothing to prove".to_owned(),
            });
        }
        // Error out if length of messages and generators are not equal
        if messages.len() + 1 != generators.message_generators_length() {
            println!("messages.len() + 1 = {:?}", messages.len() + 1);
            println!(
                "generators.message_generators_length() = {:?}",
                generators.message_generators_length()
            );

            return Err(Error::MessageGeneratorsLengthMismatch {
                generators: generators.message_generators_length(),
                messages: messages.len(),
            });
        }
        let api_id = api_id.unwrap_or([].to_vec());

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
        // 4. messages.push(pid)
        // ...(implicit steps)...
        // 10. undisclosed_indexes = range(1, L) \ disclosed_indexes
        // 11. disclosed_messages = (messages[i1], ..., messages[iR])
        let mut messages_vec = messages.to_vec();
        messages_vec.push(ProofMessage::Hidden(pid));

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

        let init_result = Proof::proof_init::<T, G, C>(
            PK,
            signature,
            generators,
            &random_scalars,
            header,
            message_scalars,
            undisclosed_indexes,
            &api_id,
        )?;

        // Pseudonym correctness proof init
        let OP = C::hash_to_curve(verifier_id.as_ref(), &api_id)?;

        let pid_tilde = random_scalars.m_tilde_scalars.last().unwrap();
        let pseudonym_proof_init = CommitProofInitResult {
            commit: nym.as_point(),
            commit_base: OP,
            blind_commit: OP * pid_tilde,
        };

        // challenge calculation
        let challenge = compute_challenge::<_, C>(
            &init_result,
            &disclosed_messages,
            ph,
            api_id,
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
    pub fn verify<T, G, C>(
        &self,
        PK: &PublicKey,
        pseudonym: &Pseudonym,
        verifier_id: T,
        header: Option<T>,
        ph: Option<T>,
        generators: &G,
        disclosed_messages: &BTreeMap<usize, Message>,
        api_id: Option<Vec<u8>>,
    ) -> Result<bool, Error>
    where
        T: AsRef<[u8]>,
        G: Generators,
        C: BbsCiphersuiteParameters,
    {
        // if KeyValidate(PK) is INVALID, return INVALID
        // `PK` should not be an identity and should belong to subgroup G2
        if PK.is_valid().unwrap_u8() == 0u8 {
            return Err(Error::InvalidPublicKey);
        }
        let api_id = api_id.unwrap_or([].to_vec());

        // initialize the proof verification procedure
        // TODO: Check that the last message is not revealed
        // TODO: Check that the m_hat_list is not empty.
        let init_res = self.0.proof_verify_init::<T, G, C>(
            PK,
            header,
            generators,
            disclosed_messages,
            &api_id,
        )?;

        // initialize the pseudonym correctness proof verification procedure
        let OP = C::hash_to_curve(verifier_id.as_ref(), &api_id)?;

        // unwrap() is safe here is we check that m_hat_list is non empty (TODO)
        let pid_hat = self.0.m_hat_list.last().unwrap();
        let pseudonym_point = pseudonym.as_point();
        let proof_challenge = self.0.c;
        let Uv = G1Projective::multi_exp(
            &[OP, pseudonym_point],
            &[pid_hat.0, -proof_challenge.0],
        );

        let pseudonym_proof_verify_init = CommitProofInitResult {
            commit: pseudonym_point,
            commit_base: OP,
            blind_commit: Uv,
        };

        let challenge = compute_challenge::<_, C>(
            &init_res,
            disclosed_messages,
            ph,
            api_id,
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
        let P2 = C::p2().to_affine();
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
