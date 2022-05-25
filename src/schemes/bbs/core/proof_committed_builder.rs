use crate::common::error::Error;
use crate::curves::bls12_381::Scalar;
use core::fmt::Debug;
use digest::Update;
use ff::Field;
use group::{Curve, GroupEncoding};
use rand_core::RngCore;
use subtle::ConstantTimeEq;

struct ProofCommittedBuilderCache<B, C>
where
    B: Clone
        + Copy
        + Debug
        + Default
        + ConstantTimeEq
        + PartialEq
        + Eq
        + Curve<AffineRepr = C>,
    C: GroupEncoding + Debug,
{
    commitment: B,
    points: Vec<B>,
    scalars: Vec<Scalar>,
}

impl<B, C> Default for ProofCommittedBuilderCache<B, C>
where
    B: Clone
        + Copy
        + Debug
        + Default
        + ConstantTimeEq
        + PartialEq
        + Eq
        + Curve<AffineRepr = C>,
    C: GroupEncoding + Debug,
{
    fn default() -> Self {
        Self {
            commitment: B::default(),
            points: Vec::new(),
            scalars: Vec::new(),
        }
    }
}

impl<B, C> PartialEq<ProofCommittedBuilder<B, C>>
    for ProofCommittedBuilderCache<B, C>
where
    B: Clone
        + Copy
        + Debug
        + Default
        + ConstantTimeEq
        + PartialEq
        + Eq
        + Curve<AffineRepr = C>,
    C: GroupEncoding + Debug,
{
    fn eq(&self, other: &ProofCommittedBuilder<B, C>) -> bool {
        if self.points.len() != other.points.len() {
            return false;
        }
        let mut res = 1u8;
        for i in 0..self.points.len() {
            res &= self.points[i].ct_eq(&other.points[i]).unwrap_u8();
        }
        res == 1
    }
}

/// A builder struct for creating a proof of knowledge
/// of messages in a vector commitment
/// each message has a blinding factor
pub struct ProofCommittedBuilder<B, C>
where
    B: Clone
        + Copy
        + Debug
        + Default
        + ConstantTimeEq
        + PartialEq
        + Eq
        + Curve<AffineRepr = C>,
    C: GroupEncoding + Debug,
{
    cache: ProofCommittedBuilderCache<B, C>,
    points: Vec<B>,
    scalars: Vec<Scalar>,
    sum_of_products: fn(&[B], &[Scalar]) -> B,
}

impl<B, C> Default for ProofCommittedBuilder<B, C>
where
    B: Clone
        + Copy
        + Debug
        + Default
        + ConstantTimeEq
        + PartialEq
        + Eq
        + Curve<AffineRepr = C>,
    C: GroupEncoding + Debug,
{
    fn default() -> Self {
        Self::new(|_, _| B::default())
    }
}

impl<B, C> ProofCommittedBuilder<B, C>
where
    B: Clone
        + Copy
        + Debug
        + Default
        + ConstantTimeEq
        + PartialEq
        + Eq
        + Curve<AffineRepr = C>,
    C: GroupEncoding + Debug,
{
    /// Create a new builder
    pub fn new(sum_of_products: fn(&[B], &[Scalar]) -> B) -> Self {
        Self {
            cache: ProofCommittedBuilderCache::default(),
            points: Vec::new(),
            scalars: Vec::new(),
            sum_of_products,
        }
    }

    /// Add a specified point and generate a random blinding factor
    pub fn commit_random(&mut self, point: B, rng: impl RngCore) {
        let r = Scalar::random(rng);
        self.points.push(point);
        self.scalars.push(r);
    }

    /// Commit a specified point with the specified scalar
    pub fn commit(&mut self, point: B, scalar: Scalar) {
        self.points.push(point);
        self.scalars.push(scalar);
    }

    /// Convert the committed values to bytes for the fiat-shamir challenge
    pub fn add_challenge_contribution(&mut self, hasher: &mut impl Update) {
        if !self.cache.eq(self) {
            let mut scalars = self.scalars.clone();
            let commitment =
                (self.sum_of_products)(self.points.as_ref(), scalars.as_mut());
            self.cache = ProofCommittedBuilderCache {
                points: self.points.clone(),
                scalars,
                commitment,
            }
        }

        hasher.update(self.cache.commitment.to_affine().to_bytes());
    }

    /// Generate the Schnorr challenges given the specified secrets
    /// by computing p = r + c * s
    #[allow(clippy::needless_range_loop)]
    pub fn generate_proof(
        mut self,
        challenge: Scalar,
        secrets: &[Scalar],
    ) -> Result<Vec<Scalar>, Error> {
        if secrets.len() != self.cache.points.len() {
            return Err(Error::CryptoSchnorrChallengeComputation {
                cause: format!(
                    "secrets length {} is not equal to blinding factors length {}", secrets.len(), self.cache.points.len()
                ),
            });
        }
        for i in 0..self.cache.scalars.len() {
            self.cache.scalars[i] += secrets[i] * challenge;
        }
        Ok(self.cache.scalars)
    }
}
