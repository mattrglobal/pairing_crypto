use crate::{
    bbs::ciphersuites::BbsCipherSuiteParameter,
    curves::bls12_381::G1Projective,
    error::Error,
};

/// The generators that are used to sign a vector of commitments for a BBS
/// signature. These must be the same generators used by sign, verify, prove,
/// and verify proof.
#[allow(non_snake_case)]
#[derive(Debug, Clone)]
pub(crate) struct Generators {
    pub(crate) Q_1: G1Projective,
    pub(crate) Q_2: G1Projective,
    pub(crate) H_list: Vec<G1Projective>,
}

#[allow(non_snake_case)]
impl Generators {
    /// Construct `Generators` from the given `seed` values.
    /// The implementation follows `CreateGenerators` section as defined in <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-creategenerators>.
    pub fn new<C>(count: usize) -> Result<Self, Error>
    where
        C: BbsCipherSuiteParameter<'static>,
    {
        let generators = C::create_generators(count + 2)?;
        Ok(Self {
            Q_1: generators[0],
            Q_2: generators[1],
            H_list: generators[2..].to_vec(),
        })
    }

    /// Get `Q_1`, the generator point for the blinding value (s) of the
    /// signature.
    pub fn Q_1(&self) -> G1Projective {
        self.Q_1
    }

    /// Get `Q_2`, the generator point for the domain of the signature.
    pub fn Q_2(&self) -> G1Projective {
        self.Q_2
    }

    /// The number of message generators this `Generators` instance
    /// holds.
    pub fn message_generators_length(&self) -> usize {
        self.H_list.len()
    }

    /// Get the message generator at `index`.
    /// Note `MessageGenerators` is zero indexed, so passed `index` value should
    /// be in [0, `length`) range. In case of invalid `index`, `None` value
    /// is returned.
    pub fn get_message_generators_at_index(
        &self,
        index: usize,
    ) -> Option<G1Projective> {
        if index >= self.H_list.len() {
            return None;
        }
        Some(self.H_list[index])
    }

    /// Get a `core::slice::Iter` for message generators.
    pub fn message_generators_iter(
        &self,
    ) -> core::slice::Iter<'_, G1Projective> {
        self.H_list.iter()
    }
}
