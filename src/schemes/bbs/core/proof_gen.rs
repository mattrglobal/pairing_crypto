#![allow(non_snake_case)]

use super::{
    generator::Generators,
    proof::Proof,
    public_key::PublicKey,
    signature::Signature,
    types::{FiatShamirProof, HiddenMessage, ProofMessage},
    utils::{compute_B, compute_challenge, compute_domain},
};
use crate::{
    curves::bls12_381::{G1Projective, Scalar},
    error::Error,
};
use ff::Field;
use rand_core::{CryptoRng, RngCore};

/// zero-knowledge proof-of-knowledge of a signature, while optionally
/// selectively disclosing from the original set of signed messages as defined in `ProofGen` API in BBS Signature specification <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-proofgen>
pub fn gen_proof_with_rng<T>(
    PK: &PublicKey,
    signature: &Signature,
    header: Option<T>,
    ph: Option<T>,
    generators: &Generators,
    messages: &[ProofMessage],
    mut rng: impl RngCore + CryptoRng,
) -> Result<Proof, Error>
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

    // Following steps from `ProofGen` API in spec are implicit in the
    // implementation
    // signature_result = octets_to_signature(signature)
    // (i1, i2,..., iR) = RevealedIndexes
    // (j1, j2,..., jU) = [L] \ RevealedIndexes
    // if signature_result is INVALID, return INVALID
    // (A, e, s) = signature_result
    // generators =  (H_s || H_d || H_1 || ... || H_L)

    // domain
    //  = hash_to_scalar((PK||L||generators||Ciphersuite_ID||header), 1)
    let domain = compute_domain(PK, header, messages.len(), generators)?;

    // (r1, r2, e~, r2~, r3~, s~) = hash_to_scalar(PRF(8*ceil(log2(r))), 6)
    let r1 = Scalar::random(&mut rng);
    let r2 = Scalar::random(&mut rng);
    let e_tilde = Scalar::random(&mut rng);
    let r2_tilde = Scalar::random(&mut rng);
    let r3_tilde = Scalar::random(&mut rng);
    let s_tilde = Scalar::random(&mut rng);

    // (m~_j1, ..., m~_jU) =  hash_to_scalar(PRF(8*ceil(log2(r))), U)
    // these random scalars will be generated further below using
    // ProofCommittedBuilder::commit_random(...) in `proof2` variable

    let msg: Vec<_> = messages.iter().map(|m| m.get_message()).collect();
    // B = P1 + H_s * s + H_d * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = compute_B(&signature.s, &domain, msg.as_ref(), generators)?;

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
    let A_bar = G1Projective::multi_exp(&[-A_prime, B], &[signature.e, r1]);

    // D = B * r1 + H_s * r2
    let D = G1Projective::multi_exp(&[B, generators.H_s()], &[r1, r2]);

    // s' = s + r2 * r3
    let s_prime = signature.s + r2 * r3;

    // C1 = A' * e~ + H_s * r2~
    let C1 = G1Projective::multi_exp(
        &[A_prime, generators.H_s()],
        &[e_tilde, r2_tilde],
    );

    //  C2 = D * (-r3~) + H_s * s~ + H_j1 * m~_j1 + ... + H_jU * m~_jU
    let mut C2_points = Vec::new();
    let mut C2_scalars = Vec::new();
    // For D * (-r3~)
    C2_points.push(-D);
    C2_scalars.push(r3_tilde);
    // For H_s * s~
    C2_points.push(generators.H_s());
    C2_scalars.push(s_tilde);
    let mut hidden_messages = Vec::new();
    for (i, generator) in generators.message_blinding_points_iter().enumerate()
    {
        match messages[i] {
            ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(m)) => {
                C2_points.push(*generator);
                C2_scalars.push(Scalar::random(&mut rng));
                hidden_messages.push(m.0);
            }
            ProofMessage::Hidden(HiddenMessage::ExternalBlinding(m, e)) => {
                C2_points.push(*generator);
                C2_scalars.push(e.0);
                hidden_messages.push(m.0);
            }
            _ => {}
        }
    }
    let C2 = G1Projective::multi_exp(&C2_points, &C2_scalars);

    // c = hash_to_scalar((PK || Abar || A' || D || C1 || C2 || ph), 1)
    let c = compute_challenge(&PK, &A_bar, &A_prime, &D, &C1, &C2, ph)?;

    // e^ = e~ + c * e
    let e_hat = FiatShamirProof(e_tilde + c.0 * signature.e);

    // r2^ = r2~ + c * r2
    let r2_hat = FiatShamirProof(r2_tilde + c.0 * r2);

    // r3^ = r3~ + c * r3
    let r3_hat = FiatShamirProof(r3_tilde + c.0 * r3);

    // s^ = s~ + c * s'
    let s_hat = FiatShamirProof(s_tilde + c.0 * s_prime);

    // for j in (j1, j2,..., jU): m^_j = m~_j + c * msg_j
    let m_hat_list = C2_scalars
        .iter()
        .skip(2)
        .zip(hidden_messages.iter())
        .map(|(m_tilde, msg)| {
            let m_hat = *m_tilde + c.0 * (*msg);
            FiatShamirProof(m_hat)
        })
        .collect::<Vec<FiatShamirProof>>();

    Ok(Proof {
        A_prime,
        A_bar,
        D,
        c,
        e_hat,
        r2_hat,
        r3_hat,
        s_hat,
        m_hat_list,
    })
}
