use super::*;
use crate::schemes::core::*;

/// This struct represents an Issuer of signatures or Signer.
/// Provided are methods for signing regularly where all messages are known
/// and 2PC where some are only known to the holder and a blind signature
/// is created.
///
/// The issuer generates keys and uses those to sign
/// credentials. There are two types of public keys and a secret key.
/// `PublicKey` is used for verification and `MessageGenerators` are purely
/// for creating blind signatures.
pub struct Issuer;

impl Issuer {
    /// Create a keypair capable of signing up to `count` messages
    pub fn new_keys(count: usize) -> Result<(PublicKey, SecretKey), Error> {
        SecretKey::random(count, rand::thread_rng())
            .map(|sk| {
                let pk = PublicKey::from(&sk);
                (pk, sk)
            })
            .ok_or_else(|| Error::new(1, "invalid length to generate keys"))
    }

    /// Create a signature with no hidden messages
    pub fn sign<M>(sk: &SecretKey, msgs: M) -> Result<Signature, Error>
    where
        M: AsRef<[Message]>,
    {
        Signature::new(sk, msgs)
    }

    /// Verify a proof of committed messages and generate a blind signature
    pub fn blind_sign(
        ctx: &BlindSignatureContext,
        sk: &SecretKey,
        msgs: &[(usize, Message)],
        nonce: Nonce,
    ) -> Result<BlindSignature, Error> {
        // Known messages are less than total, max at 128
        let tv1: Vec<_> = msgs.iter().map(|(i, _)| *i).collect();
        if ctx.verify(tv1.as_ref(), sk, nonce)? {
            BlindSignature::new(ctx.commitment, sk, msgs)
        } else {
            Err(Error::new(1, "invalid proof of committed messages"))
        }
    }

    /// Create a nonce used for the blind signing context
    pub fn generate_signing_nonce() -> Nonce {
        Nonce::random(rand::thread_rng())
    }
}
