use super::ciphersuites::BbsCiphersuiteParameters;
use crate::{
    bbs::generator::GeneratorsParameters,
    common::{
        ciphersuite::CipherSuiteParameter,
        hash_param::{
            constant::{
                DEFAULT_DST_SUFFIX_MESSAGE_TO_SCALAR,
                MAX_DST_SIZE,
                MAX_MESSAGE_SIZE,
                XOF_NO_OF_BYTES,
            },
            h2s::HashToScalarParameter,
        },
        interface::InterfaceParameter,
    },
    curves::bls12_381::{G1Projective, Scalar},
    Error,
};

pub(crate) trait BbsInterfaceParameter: InterfaceParameter {
    // Each Interface needs to be defined over a specific BBS ciphersuite.
    type Ciphersuite: BbsCiphersuiteParameters;

    fn api_id() -> Vec<u8> {
        [
            Self::Ciphersuite::ID.as_octets(),
            <Self as InterfaceParameter>::ID.as_octets(),
        ]
        .concat()
    }

    fn generators_parameter() -> GeneratorsParameters {
        GeneratorsParameters {
            generator_seed: [
                Self::api_id(),
                b"MESSAGE_GENERATOR_SEED".to_vec(),
            ]
            .concat(),
            generator_dst: [Self::api_id(), b"SIG_GENERATOR_DST_".to_vec()]
                .concat(),
            seed_dst: [Self::api_id(), b"SIG_GENERATOR_SEED_".to_vec()]
                .concat(),
            hash_to_curve: Self::Ciphersuite::hash_to_curve,
            expand_message: Self::Ciphersuite::expand_message,
        }
    }

    fn create_generators(
        count: usize,
        n: &mut u64,
        v: &mut [u8; XOF_NO_OF_BYTES],
        with_fresh_state: bool,
    ) -> Result<Vec<G1Projective>, Error> {
        let generators: GeneratorsParameters = Self::generators_parameter();
        generators.create_generators(count, n, v, with_fresh_state)
    }

    /// Default domain separation tag to be used in [MapMessageToScalarAsHash](https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-mapmessagetoscalarashash).
    fn default_map_message_to_scalar_as_hash_dst() -> Vec<u8> {
        [
            &Self::api_id(),
            DEFAULT_DST_SUFFIX_MESSAGE_TO_SCALAR.as_bytes(),
        ]
        .concat()
    }

    // map messages to scalars
    fn map_message_to_scalar_as_hash(
        message: &[u8],
        dst: Option<&[u8]>,
    ) -> Result<Scalar, Error> {
        let default_map_message_to_scalar_as_hash_dst =
            Self::default_map_message_to_scalar_as_hash_dst();
        let dst = dst.unwrap_or(&default_map_message_to_scalar_as_hash_dst);

        if !dst.is_ascii() {
            return Err(Error::BadParams {
                cause: "non-ascii dst".to_owned(),
            });
        }

        // If len(dst) > 2^8 - 1 or len(msg) > 2^64 - 1, abort
        if message.len() as u64 > MAX_MESSAGE_SIZE {
            return Err(Error::MessageIsTooLarge);
        }
        if dst.len() > MAX_DST_SIZE as usize {
            return Err(Error::DstIsTooLarge);
        }

        // hash_to_scalar(message || dst_prime, 1)
        Self::Ciphersuite::hash_to_scalar(message, Some(dst))
    }
}
