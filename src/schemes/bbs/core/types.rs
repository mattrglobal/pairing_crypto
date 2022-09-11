use crate::{
    bbs::ciphersuites::BbsCiphersuiteParameters,
    common::h2s::map_message_to_scalar_as_hash,
    curves::bls12_381::{Scalar, OCTET_SCALAR_LENGTH},
    error::Error,
    scalar_wrapper,
};
use serde::{Deserialize, Serialize};
use subtle::CtOption;

scalar_wrapper!(
    /// A challenge generated by Fiat-Shamir heuristic.
    Challenge
);

scalar_wrapper!(
    /// A Proof generated by Fiat-Shamir heuristic.
    FiatShamirProof
);

scalar_wrapper!(
    /// A message to be signed.
    Message
);

impl Message {
    /// Generate a random `Message`.
    #[cfg(test)]
    pub fn random<R: rand_core::RngCore>(rng: &mut R) -> Self {
        use ff::Field;
        Self(Scalar::random(rng))
    }

    /// Map arbitrary data to `Message`.
    pub fn from_arbitrary_data<C>(
        message: &[u8],
        dst: Option<&[u8]>,
    ) -> Result<Self, Error>
    where
        C: BbsCiphersuiteParameters<'static>,
    {
        Ok(Self(map_message_to_scalar_as_hash::<C>(message, dst)?))
    }
}

/// A message classification by the prover.
#[derive(Copy, Clone, Debug)]
pub(crate) enum ProofMessage {
    /// Message will be revealed to a verifier.
    Revealed(Message),
    /// Message will be hidden from a verifier.
    Hidden(Message),
}

impl ProofMessage {
    /// Extract the internal message.
    pub fn get_message(&self) -> Message {
        match *self {
            ProofMessage::Revealed(r) => r,
            ProofMessage::Hidden(h) => h,
        }
    }
}
