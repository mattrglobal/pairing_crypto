use crate::{
    common::ciphersuite::CipherSuiteId,
    curves::bls12_381::Scalar,
    Error,
};
use core::fmt::Debug;

pub(crate) trait HashToScalarParameter: Debug + Clone {
    /// Ciphersuite ID.
    const ID: CipherSuiteId;

    /// Default domain separation tag for `hash_to_scalar` operation.
    fn default_hash_to_scalar_dst() -> Vec<u8> {
        [Self::ID.as_octets(), b"H2S_"].concat()
    }

    /// Default domain separation tag to be used in [MapMessageToScalarAsHash](https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-mapmessagetoscalarashash).
    fn default_map_message_to_scalar_as_hash_dst() -> Vec<u8> {
        [Self::ID.as_octets(), b"MAP_MESSAGE_TO_SCALAR_AS_HASH_"].concat()
    }

    /// Hash arbitrary data to `n` number of scalars as specified in BBS
    /// specification.
    fn hash_to_scalar(
        msg_octets: &[u8],
        count: usize,
        dst: Option<&[u8]>,
    ) -> Result<Vec<Scalar>, Error>;
}
