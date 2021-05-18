use super::{BlindSignature, BlindSignatureContext, MessageGenerators, Signature};
use crate::schemes::bls::{PublicKey, SecretKey};
use crate::schemes::core::*;
use rand_core::{CryptoRng, RngCore};

/// This struct represents an Issuer of signatures or Signer.
/// Provided are methods for signing regularly where all messages are known
/// and 2PC where some are only known to the holder and a blind signature
/// is created.
///
/// The issuer generates keys and uses those to sign
/// credentials.
pub struct Issuer;

impl Issuer {
    /// Create a keypair
    pub fn new_keys(rng: impl RngCore + CryptoRng) -> Result<(PublicKey, SecretKey), Error> {
        SecretKey::random(rng)
            .map(|sk| {
                let pk = PublicKey::from(&sk);
                (pk, sk)
            })
            .ok_or_else(|| Error::new(1, "invalid length to generate keys"))
    }

    /// Create a signature with no hidden messages
    pub fn sign<M>(
        sk: &SecretKey,
        generators: &MessageGenerators,
        msgs: M,
    ) -> Result<Signature, Error>
    where
        M: AsRef<[Message]>,
    {
        Signature::new(sk, generators, msgs)
    }

    /// Verify a proof of committed messages and generate a blind signature
    pub fn blind_sign(
        ctx: &BlindSignatureContext,
        sk: &SecretKey,
        generators: &MessageGenerators,
        msgs: &[(usize, Message)],
        nonce: Nonce,
    ) -> Result<BlindSignature, Error> {
        // Known messages are less than total, max at 128
        let tv1 = msgs.iter().map(|(i, _)| *i).collect::<Vec<usize>>();
        if ctx.verify(tv1.as_ref(), generators, nonce)? {
            BlindSignature::new(ctx.commitment, sk, generators, msgs)
        } else {
            Err(Error::new(1, "invalid proof of committed messages"))
        }
    }

    /// Create a nonce used for the blind signing context
    pub fn generate_signing_nonce() -> Nonce {
        Nonce::random(rand::thread_rng())
    }
}

#[test]
fn blind_sign_test() {
    use crate::curves::bls12_381::G1Projective;
    use crate::MockRng;
    use rand_core::SeedableRng;

    let n = Issuer::generate_signing_nonce();
    let sk = SecretKey::default();
    let generators = MessageGenerators::from_secret_key(&sk, 3);
    let ctx = BlindSignatureContext {
        commitment: Commitment(G1Projective::generator()),
        challenge: Challenge::default(),
        proofs: vec![Challenge::default()],
    };
    let res = Issuer::blind_sign(
        &ctx,
        &sk,
        &generators,
        &[(2, Message::default()), (3, Message::default())],
        n,
    );
    assert!(res.is_err());

    let sk = SecretKey::hash(b"").unwrap();
    let generators = MessageGenerators::from_secret_key(&sk, 3);
    let messages = [
        Message::hash(b"1"),
        Message::hash(b"2"),
        Message::hash(b"3"),
    ];

    let mut rng = MockRng::from_seed([7u8; 16]);

    let res = crate::schemes::bbs::Prover::new_blind_signature_context(
        &[(0, messages[0])],
        &generators,
        n,
        &mut rng,
    );
    assert!(res.is_ok());
    let (ctx, _) = res.unwrap();
    let res = Issuer::blind_sign(
        &ctx,
        &sk,
        &generators,
        &[(0, messages[0]), (1, messages[1])],
        n,
    );
    assert!(res.is_err());
    let res = Issuer::blind_sign(
        &ctx,
        &sk,
        &generators,
        &[(1, messages[1]), (2, messages[2])],
        n,
    );
    assert!(res.is_ok());
}
