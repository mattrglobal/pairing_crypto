use super::{MessageGenerators, PokSignatureProof};
use crate::curves::bls12_381::PublicKey;
use crate::schemes::core::*;
use digest::{ExtendableOutput, Update, XofReader};

/// This struct represents a Verifier of signatures.
/// Provided are methods for generating a context to ask for revealed messages
/// and the prover keep all others hidden.
pub struct Verifier;

impl Verifier {
    /// Create a random presentation message used for the proof request context
    pub fn generate_random_presentation_message() -> PresentationMessage {
        PresentationMessage::random(rand::thread_rng())
    }

    /// Check a signature proof of knowledge and selective disclosure proof
    pub fn verify_signature_pok(
        revealed_msgs: &[(usize, Message)],
        public_key: PublicKey,
        proof: PokSignatureProof,
        generators: &MessageGenerators,
        presentation_message: PresentationMessage,
    ) -> Result<bool, String> {
        let mut data = [0u8; COMMITMENT_G1_BYTES];
        let mut hasher = sha3::Shake256::default();

        match proof.add_challenge_contribution(
            generators,
            revealed_msgs,
            proof.challenge,
            &mut hasher,
        ) {
            Err(_) => return Err("Failed to re-compute challenge".to_string()),
            _ => {}
        }

        hasher.update(&presentation_message.to_bytes()[..]);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut data[..]);
        let v_challenge = Challenge::from_okm(&data);

        Ok(proof.verify(public_key) && proof.challenge == v_challenge)
    }
}

#[test]
fn pok_sig_proof_works() {
    use super::{Issuer, PokSignature};
    use crate::MockRng;
    use rand_core::*;

    let seed = [1u8; 16];
    let mut rng = MockRng::from_seed(seed);

    let (pk, sk) = Issuer::new_keys().unwrap();
    let generators = MessageGenerators::from_public_key(pk, 4);
    let messages = [
        Message::random(&mut rng),
        Message::random(&mut rng),
        Message::random(&mut rng),
        Message::random(&mut rng),
    ];

    let res = Issuer::sign(&sk, &generators, &messages);
    assert!(res.is_ok());

    let signature = res.unwrap();

    let proof_messages = [
        ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(messages[0])),
        ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(messages[1])),
        ProofMessage::Revealed(messages[2]),
        ProofMessage::Revealed(messages[3]),
    ];

    let res = PokSignature::init(signature, &generators, &proof_messages);
    assert!(res.is_ok());

    let mut tv = [0u8; 48];
    let mut pok_sig = res.unwrap();
    let presentation_message = Verifier::generate_random_presentation_message();
    let mut hasher = sha3::Shake256::default();
    pok_sig.add_proof_contribution(&mut hasher);
    hasher.update(&presentation_message.to_bytes()[..]);
    let mut reader = hasher.finalize_xof_reset();
    reader.read(&mut tv);
    let challenge = Challenge::from_okm(&tv);
    let res = pok_sig.generate_proof(challenge);
    assert!(res.is_ok());

    let proof = res.unwrap();
    assert!(proof.verify(pk));

    proof
        .add_challenge_contribution(
            &generators,
            &[(2, messages[2]), (3, messages[3])][..],
            challenge,
            &mut hasher,
        )
        .unwrap();
    hasher.update(&presentation_message.to_bytes()[..]);
    reader = hasher.finalize_xof();
    reader.read(&mut tv);
    let challenge2 = Challenge::from_okm(&tv);
    assert_eq!(challenge, challenge2);

    assert!(Verifier::verify_signature_pok(
        &[(2, messages[2]), (3, messages[3])][..],
        pk,
        proof,
        &generators,
        presentation_message
    )
    .unwrap());
}
