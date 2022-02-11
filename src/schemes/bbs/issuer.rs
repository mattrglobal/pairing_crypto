use super::{MessageGenerators, PublicKey, SecretKey, Signature};
use crate::schemes::core::*;

/// This struct represents an Issuer of signatures or Signer.
/// Provided are methods for signing regularly where all messages are known
///
/// The issuer generates keys and uses those to sign
/// credentials.
pub struct Issuer;

impl Issuer {
    /// Create a keypair
    pub fn new_keys() -> Result<(PublicKey, SecretKey), Error> {
        SecretKey::random()
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
}
