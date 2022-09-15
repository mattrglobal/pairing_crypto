use crate::curves::bls12_381::G1Projective;
use core::fmt::Debug;

/// A `Generators` implementation where generators are computed in advance
/// during instantiation of `struct` and stored in RAM.
pub(crate) mod memory_cached_generator;

/// The generators that are used to sign a vector of commitments for a BBS
/// signature. Same set of generators must be used in all BBS scheme operations
/// - `Sign`, `Verify`, `ProofGen`, and `ProofVerify`.
#[allow(non_snake_case)]
pub(crate) trait Generators: Debug + Clone {
    /// Get `Q_1`, the generator point for the blinding value (s) of the
    /// signature.
    fn Q_1(&self) -> G1Projective;

    /// Get `Q_2`, the generator point for the domain of the signature.
    fn Q_2(&self) -> G1Projective;

    /// The number of message generators this `Generators` instance
    /// holds.
    fn message_generators_length(&self) -> usize;

    /// Get the message generator at `index`.
    /// Note - `MessageGenerators` is zero indexed, so passed `index` value
    /// should be in [0, `length`) range. In case of invalid `index`, `None`
    /// value is returned.
    /// For a Non-index based generators, like DynamicGenerator, `index`
    /// argument is ignored.
    fn get_message_generator(&mut self, index: usize) -> Option<G1Projective>;

    /// Get a `Iterator` for message generators.
    fn message_generators_iter(&self) -> GeneratorsIter<Self> {
        GeneratorsIter {
            index: 0,
            count: self.message_generators_length(),
            generators: self.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct GeneratorsIter<G: Generators> {
    index: usize,
    count: usize,
    generators: G,
}

impl<G: Generators> Iterator for GeneratorsIter<G> {
    type Item = G1Projective;

    fn size_hint(&self) -> (usize, Option<usize>) {
        let length = self.count - self.index;
        (length, Some(length))
    }

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.index;
        if index >= self.count {
            None
        } else {
            self.index += 1;
            self.generators.get_message_generator(index)
        }
    }
}
