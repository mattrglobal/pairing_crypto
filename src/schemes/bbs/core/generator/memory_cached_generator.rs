use super::Generators;
use crate::{
    bbs::ciphersuites::BbsCiphersuiteParameters,
    common::hash_param::constant::XOF_NO_OF_BYTES,
    curves::bls12_381::G1Projective,
    error::Error,
};
use core::{fmt::Debug, marker::PhantomData};
use group::Group;

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
    pub(crate) Q: G1Projective,
    pub(crate) H_list: Vec<G1Projective>,
    _phantom_data: PhantomData<C>,
}

#[allow(non_snake_case)]
impl<C: BbsCiphersuiteParameters + Debug + Clone> MemoryCachedGenerators<C> {
    /// Construct `Generators`.
    /// The implementation follows `CreateGenerators` section as defined in <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-creategenerators>.
    pub fn new(
        count: usize,
        private_holder_binding: Option<bool>,
    ) -> Result<Self, Error>
    where
        C: BbsCiphersuiteParameters,
    {
        let mut n = 1;
        let mut v = [0u8; XOF_NO_OF_BYTES];
        let generators = C::create_generators(
            &C::generator_seed(),
            count + 1,
            &mut n,
            &mut v,
            true,
        )?;
        let mut H_list = generators[1..1 + count].to_vec();
        if let Some(bound_bbs) = private_holder_binding {
            if bound_bbs {
                H_list.push(G1Projective::generator());
            }
        }

        Ok(Self {
            Q: generators[0],
            H_list,
            _phantom_data: PhantomData,
        })
    }
}

impl<C: BbsCiphersuiteParameters + Debug + Clone> Generators
    for MemoryCachedGenerators<C>
{
    /// Get `Q`, the generator point for the domain of the signature.
    fn Q(&self) -> G1Projective {
        self.Q
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
    fn get_message_generator(&self, index: usize) -> Option<G1Projective> {
        if index >= self.H_list.len() {
            return None;
        }
        Some(self.H_list[index])
    }
}
