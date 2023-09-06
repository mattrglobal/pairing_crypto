use crate::{
    common::{hash_param::constant::XOF_NO_OF_BYTES, serialization::i2osp},
    curves::bls12_381::G1Projective,
    Error,
};

/// Parameters of the create_generators operation as defined in [BBS draft](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-hash-to-generators).
pub struct GeneratorsParameters {
    /// Seed from which all generators are created.
    pub generator_seed: Vec<u8>,
    /// A dst to domain separate the generator points.
    pub generator_dst: Vec<u8>,
    /// A dst to domain separate the seeds that create all the generators.
    pub seed_dst: Vec<u8>,
    /// The hash to curve operation that on hashes a message and a dst on a
    /// point of G1.
    pub hash_to_curve:
        fn(message: &[u8], dst: &[u8]) -> Result<G1Projective, Error>,
    /// A operation that hashes a message and a dst, abd outs the result of
    /// length XOF_NO_OF_BYTES, to the destination (dest).
    pub expand_message:
        fn(message: &[u8], dst: &[u8], dest: &mut [u8; XOF_NO_OF_BYTES]),
}

impl GeneratorsParameters {
    /// Create `count` generators from some new or supplied state (n, v).
    pub fn create_generators(
        self,
        count: usize,
        n: &mut u64,
        v: &mut [u8; XOF_NO_OF_BYTES],
        with_fresh_state: bool,
    ) -> Result<Vec<G1Projective>, Error> {
        let generator_dst = self.generator_dst;
        let generator_seed = self.generator_seed;
        let seed_dst = self.seed_dst;
        let expand_message_fn = self.expand_message;
        let hash_to_curve_fn = self.hash_to_curve;

        if with_fresh_state {
            *n = 1;
            expand_message_fn(&generator_seed, &seed_dst, v)
        }

        let mut points = Vec::with_capacity(count);

        while *n <= count.try_into().unwrap() {
            expand_message_fn(
                &[v.as_ref(), &i2osp(*n, 8)?].concat(),
                &seed_dst,
                v,
            );

            *n += 1;

            // generator_i = hash_to_curve_g1(v, generator_dst)
            let generator_i = hash_to_curve_fn(v, &generator_dst)?;
            points.push(generator_i);
        }
        Ok(points)
    }
}
