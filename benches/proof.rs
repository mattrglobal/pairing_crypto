use std::time::Duration;

use pairing_crypto::bbs::ciphersuites::bls12_381::{
    verify_proof,
    BbsVerifyProofRequest,
    Generators,
    HiddenMessage,
    Message,
    PokSignature,
    ProofMessage,
    PublicKey,
    SecretKey,
    Signature,
    GLOBAL_BLIND_VALUE_GENERATOR_SEED,
    GLOBAL_MESSAGE_GENERATOR_SEED,
    GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
};

#[macro_use]
extern crate criterion;

use criterion::Criterion;
use rand::rngs::OsRng;

const HEADER: &[u8; 16] = b"some_app_context";
const PRESENTATION_MESSAGE: &[u8; 25] = b"test-presentation-message";

fn proof_all_hidden_benchmark(c: &mut Criterion) {
    let sk =
        SecretKey::random(&mut OsRng).expect("secret key generation failed");
    let pk = PublicKey::from(&sk);

    for num_messages in vec![1, 10] {
        let gens = Generators::new(
            GLOBAL_BLIND_VALUE_GENERATOR_SEED,
            GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
            GLOBAL_MESSAGE_GENERATOR_SEED,
            num_messages,
        )
        .expect("generators creation failed");

        let messages: Vec<Message> = (0..num_messages)
            .map(|_| Message::random(&mut OsRng))
            .collect();

        let signature =
            Signature::new(&sk, &pk, Some(&HEADER), &gens, &messages).unwrap();

        assert!(signature
            .verify(&pk, Some(&HEADER), &gens, &messages)
            .unwrap());

        // All hidden
        let proof_msgs: Vec<ProofMessage> = messages
            .iter()
            .map(|a| {
                ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(*a))
            })
            .collect();

        c.bench_function(
            &format!("proof_gen all hidden - total messages {}", num_messages),
            |b| {
                b.iter(|| {
                    let mut pok = PokSignature::init(
                        &pk,
                        &signature,
                        Some(&HEADER),
                        &gens,
                        proof_msgs.as_slice(),
                    )
                    .unwrap();

                    let challenge = pok
                        .compute_challenge(&pk, Some(PRESENTATION_MESSAGE))
                        .unwrap();

                    let _ = pok.generate_proof(challenge).unwrap();
                });
            },
        );

        let mut pok = PokSignature::init(
            &pk,
            &signature,
            Some(&HEADER),
            &gens,
            proof_msgs.as_slice(),
        )
        .unwrap();

        let challenge = pok
            .compute_challenge(&pk, Some(PRESENTATION_MESSAGE))
            .unwrap();

        let proof = pok.generate_proof(challenge).unwrap();

        c.bench_function(
            &format!(
                "proof_verify all hidden - total messages {}",
                num_messages
            ),
            |b| {
                b.iter(|| {
                    assert!(verify_proof(BbsVerifyProofRequest {
                        public_key: pk.point_to_octets().to_vec(),
                        header: Some(HEADER.to_vec()),
                        presentation_message: Some(
                            PRESENTATION_MESSAGE.to_vec()
                        ),
                        proof: proof.to_octets().to_vec(),
                        total_message_count: num_messages,
                        messages: Some(vec![]),
                    })
                    .unwrap());
                });
            },
        );
    }
}

fn proof_50_percent_revealed_benchmark(c: &mut Criterion) {
    let sk =
        SecretKey::random(&mut OsRng).expect("secret key generation failed");
    let pk = PublicKey::from(&sk);

    for num_messages in vec![1, 10, 100, 1000] {
        let num_revealed_messages = num_messages / 2;
        let gens = Generators::new(
            GLOBAL_BLIND_VALUE_GENERATOR_SEED,
            GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
            GLOBAL_MESSAGE_GENERATOR_SEED,
            num_messages,
        )
        .expect("generators creation failed");

        let messages: Vec<Message> = (0..num_messages)
            .map(|_| Message::random(&mut OsRng))
            .collect();

        let signature =
            Signature::new(&sk, &pk, Some(&HEADER), &gens, &messages).unwrap();

        assert!(signature
            .verify(&pk, Some(&HEADER), &gens, &messages)
            .unwrap());

        // All hidden
        let mut proof_msgs: Vec<ProofMessage> = messages
            .iter()
            .map(|a| {
                ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(*a))
            })
            .collect();

        let mut revealed_msgs = Vec::with_capacity(num_revealed_messages);
        // 50% hidden
        for k in 0..num_revealed_messages {
            proof_msgs[k] = ProofMessage::Revealed(messages[k]);
            revealed_msgs.push((k as usize, messages[k]));
        }

        c.bench_function(
            &format!(
                "proof_gen 50 percent hidden - total messages {}",
                num_messages
            ),
            |b| {
                b.iter(|| {
                    let mut pok = PokSignature::init(
                        &pk,
                        &signature,
                        Some(&HEADER),
                        &gens,
                        proof_msgs.as_slice(),
                    )
                    .unwrap();

                    let challenge = pok
                        .compute_challenge(&pk, Some(PRESENTATION_MESSAGE))
                        .unwrap();

                    let _ = pok.generate_proof(challenge).unwrap();
                });
            },
        );

        let mut pok = PokSignature::init(
            &pk,
            &signature,
            Some(&HEADER),
            &gens,
            proof_msgs.as_slice(),
        )
        .unwrap();

        let challenge = pok
            .compute_challenge(&pk, Some(PRESENTATION_MESSAGE))
            .unwrap();

        let proof = pok.generate_proof(challenge).unwrap();

        c.bench_function(
            &format!(
                "proof_verify 50 percent hidden - total messages {}",
                num_messages
            ),
            |b| {
                b.iter(|| {
                    let cv = proof
                        .compute_challenge(
                            &pk,
                            Some(HEADER.as_ref()),
                            &gens,
                            &revealed_msgs,
                            Some(PRESENTATION_MESSAGE.as_ref()),
                            challenge,
                        )
                        .unwrap();

                    assert!(
                        proof.verify_signature_proof(pk).unwrap()
                            && challenge == cv
                    );
                });
            },
        );
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(100));
    targets = proof_all_hidden_benchmark, proof_50_percent_revealed_benchmark
);
criterion_main!(benches);
