use crate::schemes::bbs::ciphersuites::bls12_381::{
    Generators,
    KeyPair,
    Message,
    Proof,
    PublicKey,
    SecretKey,
    Signature,
    MAP_MESSAGE_TO_SCALAR_DST,
};

use crate::error::Error;

use super::core::types::ProofMessage;
use rand::{rngs::OsRng, RngCore};
use std::collections::BTreeMap;

const KEY_INFO: &[u8; 8] = b"key_info";
const HEADER: &[u8; 16] = b"signature_header";
const PRESENTATION_HEADER: &[u8; 19] = b"presentation_header";
// The percentage of the messages to be disclosed by the proof
const REVEALED_MESSAGES_PERSENTAGE: f32 = 0.5;

/// A benchmark helper
pub struct BenchHelper {
    generators: Generators,
    messages: Vec<Message>,
    secret_key: SecretKey,
    public_key: PublicKey,
    signature: Signature,
    proof: Proof,
}

impl BenchHelper {
    /// Precalculate the key pair, the generators, and the random messages.
    pub fn init(max_count: i32) -> Result<Self, Error> {
        // Key pair
        let (sk, pk) = KeyPair::random(&mut OsRng, KEY_INFO.as_ref())
            .map(|key_pair| {
                let sk_bytes = key_pair.secret_key.to_bytes();
                let pk_octets = key_pair.public_key.to_octets();
                (
                    SecretKey::from_bytes(&sk_bytes).unwrap(),
                    PublicKey::from_octets(&pk_octets).unwrap(),
                )
            })
            .expect("Key generation failed");

        // Create all the generators.
        let gens = Generators::new(max_count as usize)?;

        // Create all the messages.
        let mut messages = vec![[0u8; 100]; max_count as usize];
        for m in messages.iter_mut() {
            rand::thread_rng().fill_bytes(m);
        }

        let msgs: Vec<Message> = messages
            .iter()
            .map(|m| {
                Message::from_arbitrary_data(
                    m.as_ref(),
                    MAP_MESSAGE_TO_SCALAR_DST.as_ref(),
                )
                .unwrap()
            })
            .collect();

        Ok(Self {
            generators: gens,
            messages: msgs,
            secret_key: sk,
            public_key: pk,
            signature: Signature::default(),
            proof: Proof::default(),
        })
    }

    /// Get the "count" first generators.
    fn get_generators(&self, count: i32) -> Generators {
        Generators {
            Q_1: self.generators.Q_1,
            Q_2: self.generators.Q_2,
            H_list: self.generators.H_list[0..count as usize].to_vec(),
        }
    }

    /// Get the proof and disclosed messages.
    fn get_proof_revealed_messages(
        &self,
        count: i32,
    ) -> (Vec<ProofMessage>, BTreeMap<usize, Message>) {
        let mut proof_msgs: Vec<ProofMessage> = Vec::new();
        let mut revealed_msgs: BTreeMap<usize, Message> = BTreeMap::new();

        // Calculate the number of messages that will be revealed.
        let threshold =
            (count as f32 * REVEALED_MESSAGES_PERSENTAGE).floor() as usize;

        for (i, &msg) in self.messages[0..count as usize].iter().enumerate() {
            if i < threshold {
                proof_msgs.push(ProofMessage::Revealed(msg));
                revealed_msgs.insert(i, msg);
            } else {
                proof_msgs.push(ProofMessage::Hidden(msg));
            }
        }
        (proof_msgs, revealed_msgs)
    }

    /// Generate and return a signature on "count" messages.
    fn sign_gen(&self, count: i32) -> Signature {
        // Get the "count" first generators.
        let gens = self.get_generators(count);

        Signature::new(
            &self.secret_key,
            &self.public_key,
            Some(HEADER),
            &gens,
            &self.messages[0..count as usize],
        )
        .unwrap()
    }

    /// Generate and return a proof on "count" messages.
    fn proof_gen(&self, count: i32) -> Proof {
        // Get the "count" first generators.
        let gens = self.get_generators(count);

        // Get the proof messages.
        let (proof_messages, _) = self.get_proof_revealed_messages(count);

        Proof::new(
            &self.public_key,
            &self.signature,
            Some(HEADER.as_ref()),
            Some(PRESENTATION_HEADER.as_ref()),
            &gens,
            &proof_messages,
        )
        .unwrap()
    }

    /// Setting the signature value. Used to benchmark the signature
    /// verify operation and for the proof generation.
    pub fn set_signature(&mut self, count: i32) {
        self.signature = self.sign_gen(count);
    }

    /// Setting the proof value. Used to benchmark the proof verify operation.
    pub fn set_proof(&mut self, count: i32) {
        self.proof = self.proof_gen(count);
    }

    /// Sign a subset of the total messages.
    pub fn sign_bench_helper(&self, count: i32) {
        self.sign_gen(count);
    }

    /// Verify a signature on a subset of the total messages.
    pub fn sig_verify_bench_helper(&self, count: i32) {
        // Get the "count" first generators.
        let gens = self.get_generators(count);

        assert!(self
            .signature
            .verify(
                &self.public_key,
                Some(HEADER),
                &gens,
                &self.messages[0..count as usize]
            )
            .unwrap());
    }

    /// Create a proof on a subset of the total messages with 50% of the
    /// messages disclosed.
    pub fn proof_gen_bench_helper(&self, count: i32) {
        self.proof_gen(count);
    }

    /// Verify a proof on a subset of the total messages.
    pub fn proof_verify_bench_helper(&self, count: i32) {
        // Get the "count" first generators.
        let gens = self.get_generators(count);

        // Get the disclosed messages.
        let (_, revealed_messages) = self.get_proof_revealed_messages(count);

        assert!(self
            .proof
            .verify(
                &self.public_key,
                Some(HEADER.as_ref()),
                Some(PRESENTATION_HEADER.as_ref()),
                &gens,
                &revealed_messages
            )
            .unwrap());
    }
}
