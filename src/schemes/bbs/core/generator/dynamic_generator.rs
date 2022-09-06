use super::Generators;
use crate::{
    bbs::{
        ciphersuites::BbsCiphersuiteParameters,
        core::constants::XOF_NO_OF_BYTES,
    },
    curves::bls12_381::G1Projective,
    error::Error,
};
use core::{fmt::Debug, marker::PhantomData};

/// A `Generators` implementation where generators are computed on fly. The
/// internal state(`n`, `v`) is saved and used to compute a single generator
/// when `get_message_generator_at_index` is called to get a generator.
#[allow(non_snake_case)]
#[derive(Debug, Clone)]
pub(crate) struct DynamicGenerators<
    C: BbsCiphersuiteParameters<'static> + Debug + Clone,
> {
    pub(crate) Q_1: G1Projective,
    pub(crate) Q_2: G1Projective,
    pub(crate) count: usize,
    pub(crate) index: usize,
    pub(crate) n: u64,
    pub(crate) v: [u8; XOF_NO_OF_BYTES],
    _phantom_data: PhantomData<C>,
}

#[allow(non_snake_case)]
impl<C: BbsCiphersuiteParameters<'static> + Debug + Clone>
    DynamicGenerators<C>
{
    /// Construct `Generators`.
    #[allow(unused)]
    pub fn new(count: usize) -> Result<Self, Error> {
        let mut n = 1;
        let mut v = [0u8; XOF_NO_OF_BYTES];
        let generators = C::create_generators(2, &mut n, &mut v, true)?;
        Ok(Self {
            Q_1: generators[0],
            Q_2: generators[1],
            count,
            index: 0,
            n,
            v,
            _phantom_data: PhantomData,
        })
    }
}

impl<C: BbsCiphersuiteParameters<'static> + Debug + Clone> Generators
    for DynamicGenerators<C>
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
        self.count
    }

    /// Get the next message generator. `index` argument is ignored.
    fn get_message_generator(&mut self, _index: usize) -> Option<G1Projective> {
        if self.index >= self.count {
            return None;
        }
        match C::create_generators(1, &mut self.n, &mut self.v, false) {
            Ok(g) => {
                self.index += 1;
                Some(g[0])
            }
            Err(_) => None,
        }
    }
}
