use super::Generators;
use crate::{
    bbs::ciphersuites::BbsCiphersuiteParameters,
    common::h2s::constant::XOF_NO_OF_BYTES,
    curves::bls12_381::G1Projective,
    error::Error,
};
use core::{fmt::Debug, marker::PhantomData};

/// A `Generators` implementation where generators are computed in advance
/// during instantiation of `struct` and stored in RAM. Later when these
/// generators can be directly accessed using APIs such as
/// `get_message_generator_at_index` or `message_generators_iter` etc., no
/// computation to calculate generator value is performed.
#[allow(non_snake_case)]
#[derive(Debug, Clone)]
pub(crate) struct MemoryCachedGenerators<
    C: BbsCiphersuiteParameters + Debug + Clone,
> {
    pub(crate) Q_1: G1Projective,
    pub(crate) Q_2: G1Projective,
    pub(crate) H_list: Vec<G1Projective>,
    pub(crate) extension_list: Vec<G1Projective>,
    _phantom_data: PhantomData<C>,
}

#[allow(non_snake_case)]
impl<C: BbsCiphersuiteParameters + Debug + Clone> MemoryCachedGenerators<C> {
    /// Construct `Generators`.
    /// The implementation follows `CreateGenerators` section as defined in <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-creategenerators>.
    pub fn new(count: usize, extension_count: usize) -> Result<Self, Error>
    where
        C: BbsCiphersuiteParameters,
    {
        let mut n = 1;
        let mut v = [0u8; XOF_NO_OF_BYTES];
        let generators = C::create_generators(
            count + extension_count + 2,
            &mut n,
            &mut v,
            true,
        )?;
        Ok(Self {
            Q_1: generators[0],
            Q_2: generators[1],
            H_list: generators[2..2 + count].to_vec(),
            extension_list: generators[2 + count..].to_vec(),
            _phantom_data: PhantomData,
        })
    }
}

impl<C: BbsCiphersuiteParameters + Debug + Clone> Generators
    for MemoryCachedGenerators<C>
{
    /// Get `Q_1`, the generator point for the blinding value (s) of the
    /// signature.
    fn Q_1(&self) -> G1Projective {
        self.Q_1
    }

    /// Get `Q_2`, the generator point for the domain of the signature.
    fn Q_2(&self) -> G1Projective {
        self.Q_2
    }

    /// The number of message generators this `Generators` instance
    /// holds.
    fn message_generators_length(&self) -> usize {
        self.H_list.len()
    }

    /// Get the message generator at `index`.
    /// Note `MessageGenerators` is zero indexed, so passed `index` value should
    /// be in [0, `length`) range. In case of invalid `index`, `None` value
    /// is returned.
    fn get_message_generator(&mut self, index: usize) -> Option<G1Projective> {
        if index >= self.H_list.len() {
            return None;
        }
        Some(self.H_list[index])
    }

    /// The number of BBS variant protocol extension generators this
    /// `Generators` instance holds.
    fn extension_generators_length(&self) -> usize {
        self.extension_list.len()
    }

    /// Get the BBS variant protocol extension generator at `index`.
    /// Note - `MessageGenerators` is zero indexed, so passed `index` value
    /// should be in [0, `length`) range. In case of invalid `index`, `None`
    /// value is returned.
    fn get_extension_generator(
        &mut self,
        index: usize,
    ) -> Option<G1Projective> {
        if index >= self.extension_list.len() {
            return None;
        }
        Some(self.extension_list[index])
    }
}
