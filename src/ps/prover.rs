use super::{BlindSignatureContext, MessageGenerators, PokSignature, PublicKey, Signature};
use crate::core::*;
use bls12_381_plus::{G1Affine, G1Projective, Scalar};
use digest::{ExtendableOutput, Update, XofReader};
use group::Curve;
use sha3::Shake256;

/// A Prover is whomever receives signatures or uses them to generate proofs.
/// Provided are methods for 2PC where some are only known to the prover and a blind signature
/// is created, unblinding signatures, verifying signatures, and creating signature proofs of knowledge
/// with selective disclosure proofs
pub struct Prover;

impl Prover {
    /// Create the structures need to send to an issuer to complete a blinded signature
    /// `messages` is an index to message map where the index corresponds to the index in `generators`
    pub fn new_blind_signature_context(
        messages: &[(usize, Message)],
        generators: &MessageGenerators,
        nonce: Nonce,
    ) -> Result<(BlindSignatureContext, SignatureBlinding), Error> {
        const BYTES: usize = 48;
        let mut rng = rand::thread_rng();

        // Very uncommon to blind more than 1 or 2, so 16 should be plenty
        let mut points = Vec::with_capacity(1 + messages.len());
        let mut secrets = Vec::with_capacity(1 + messages.len());
        let mut committing = ProofCommittedBuilder::<G1Projective, G1Affine>::new(
            G1Projective::sum_of_products_in_place,
        );

        for (i, m) in messages {
            if *i > generators.y.len() {
                return Err(Error::new(*i as u32, "invalid index"));
            }
            secrets.push(m.0);
            points.push(generators.y[*i]);
            committing.commit_random(generators.y[*i], &mut rng);
        }

        let blinding = SignatureBlinding::random(&mut rng);
        secrets.push(blinding.0);
        points.push(G1Projective::generator());
        committing.commit_random(G1Projective::generator(), &mut rng);

        let mut res = [0u8; BYTES];
        let mut hasher = Shake256::default();
        let commitment = G1Projective::sum_of_products_in_place(points.as_ref(), secrets.as_mut());

        committing.add_challenge_contribution(&mut hasher);
        hasher.update(&commitment.to_affine().to_uncompressed());
        hasher.update(&nonce.to_bytes());
        let mut reader = hasher.finalize_xof();
        reader.read(&mut res);
        let challenge = Scalar::from_okm(&res);
        let proofs: Vec<_> = committing
            .generate_proof(challenge, secrets.as_ref())?
            .iter()
            .map(|s| Challenge(*s))
            .collect();
        Ok((
            BlindSignatureContext {
                commitment: Commitment(commitment),
                challenge: Challenge(challenge),
                proofs,
            },
            blinding,
        ))
    }

    /// Create a new signature proof of knowledge and selective disclosure proof
    /// from a verifier's request
    pub fn commit_signature_pok(
        signature: Signature,
        public_key: &PublicKey,
        messages: &[ProofMessage],
    ) -> Result<PokSignature, Error> {
        PokSignature::init(signature, public_key, messages)
    }
}

#[test]
fn blind_signature_context_test() {
    use super::*;
    use crate::MockRng;
    use rand_core::*;

    let seed = [1u8; 16];
    let mut rng = MockRng::from_seed(seed);

    let (pk, sk) = Issuer::new_keys(4).unwrap();
    let generators = MessageGenerators::from(&sk);
    let nonce = Nonce::random(&mut rng);

    // try with zero, just means a blinded signature but issuer knows all messages
    let mut blind_messages = [];

    let res = Prover::new_blind_signature_context(&mut blind_messages[..], &generators, nonce);
    assert!(res.is_ok());

    let (ctx, blinding) = res.unwrap();

    let messages = [
        (0, Message::hash(b"firstname")),
        (1, Message::hash(b"lastname")),
        (2, Message::hash(b"age")),
        (3, Message::hash(b"allowed")),
    ];
    let res = Issuer::blind_sign(&ctx, &sk, &messages[..], nonce);
    assert!(res.is_ok());
    let blind_signature = res.unwrap();
    let signature = blind_signature.to_unblinded(blinding);

    let msgs = [messages[0].1, messages[1].1, messages[2].1, messages[3].1];

    let res = signature.verify(&pk, msgs.as_ref());
    assert_eq!(res.unwrap_u8(), 1);
}
