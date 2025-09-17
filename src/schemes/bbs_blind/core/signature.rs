use blstrs::G1Affine;

use crate::bbs::core::{
    signature::Signature,
    key_pair::{PublicKey, SecretKey},
    generator::Generators,
    types::Message
};

use crate::bbs::ciphersuites::BbsCiphersuiteParameters;
use crate::error::Error;

impl Signature {
    pub fn new_blind<T, M, G, C>(
        SK: &SecretKey,
        PK: &PublicKey,
        header: Option<T>,
        generators: &G,
        messages: M,
        commit: G1Affine
    ) // c-> Result<Self, Error>
    where
        T: AsRef<[u8]>,
        M: AsRef<[Message]>,
        G: Generators,
        C: BbsCiphersuiteParameters,
    {
        // Verify the commitment

        // Generate the signature
    }
}