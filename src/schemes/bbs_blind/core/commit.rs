use blstrs::{G1Projective, Scalar};
use rand_core::OsRng;

use crate::bbs::ciphersuites::BbsCiphersuiteParameters;
use crate::bbs::core::generator::Generators;
use crate::bbs::core::types::{Challenge, FiatShamirProof, Message};
use crate::common::util::create_random_scalar;
use crate::curves::bls12_381::OCTET_SCALAR_LENGTH;
use crate::curves::point_serde::point_to_octets_g1;
use crate::common::hash_param::constant::NON_NEGATIVE_INTEGER_ENCODING_LENGTH;
use crate::common::serialization::i2osp;


use crate::error::Error;
use rand::{CryptoRng, RngCore};
use ff::Field;

#[derive(Debug)]
pub(crate) struct CommitProof{
    pub(crate) commit: G1Projective,
    pub(crate) s_hat: FiatShamirProof,
    pub(crate) m_hat_list: Vec<FiatShamirProof>,
    pub(crate) c: Challenge,
}

#[derive(Debug)]
pub(crate) struct SecretProverBlind(pub(crate) Box<Scalar>);

impl SecretProverBlind {

    pub const SIZE_BYTES: usize = OCTET_SCALAR_LENGTH;

    pub(super) fn new_random<R>(rng: &mut R) -> Option<Self>
    where
        R: RngCore + CryptoRng,
    {
        if let Ok(out) = create_random_scalar(rng) {
            return Some(SecretProverBlind(Box::new(out)))
        }

        None
    }

    pub(super) fn as_scalar(&self) -> Scalar {
        *self.0
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE_BYTES] {
        self.0.to_bytes_be()
    }

    pub fn from_bytes(
        bytes: &[u8; Self::SIZE_BYTES]
    ) -> Result<Self, Error> {
        let s = Scalar::from_bytes_be(bytes);

        if s.is_some().unwrap_u8() == 1u8 {
            let s = s.unwrap();
            // Zero check as Scalar::from_bytes_be() can result in zero
            // value
            if s.is_zero().unwrap_u8() == 1u8 {
                return Err(Error::InvalidSecretKey);
            }
            Ok(SecretProverBlind(Box::new(s)))
        } else {
            Err(Error::BadParams {
                cause: "can't built a valid `SecretProverBlind` from \
                input data".to_owned(),
            })
        }
    }


    // TODO: Impl Zeroize and Drop
}

impl CommitProof {

    pub fn new<M, G, C>(
        committed_messages: M,
        generators: &G,
    ) -> Result<(Self, SecretProverBlind), Error>
    where
        M: AsRef<[Message]>,
        G: Generators,
        C: BbsCiphersuiteParameters,
    {
        Self::new_with_rng::<_, _, _, C>(
            committed_messages, generators, OsRng
        )
    }

    // new
    pub fn new_with_rng<M, G, R, C>(
        committed_messages: M,
        generators: &G,
        mut rng: R
    ) -> Result<(Self, SecretProverBlind), Error>
    where
        M: AsRef<[Message]>,
        G: Generators,
        R: RngCore + CryptoRng,
        C: BbsCiphersuiteParameters,
    {
        let messages = committed_messages.as_ref();
        let M = messages.len();

        // Input parameter checks
        if M != generators.message_generators_length() {
            return Err(Error::MessageGeneratorsLengthMismatch {
                generators: generators.message_generators_length(), 
                messages: messages.len()
            });
        }

        // generate rng
        let mut random_scalars = Vec::with_capacity(M+1);
        let s_tilde = create_random_scalar(&mut rng)?;
        random_scalars.push(s_tilde);
        
        for _ in 0..M {
            random_scalars.push(create_random_scalar(&mut rng)?);
        };


        let secret_prover_blind = SecretProverBlind::new_random(&mut rng).unwrap();

        let mut points = vec![generators.Q()];
        points.extend(generators.message_generators_iter());

        let scalars: Vec<_> = [secret_prover_blind.as_scalar()]
            .iter()
            .copied()
            .chain(messages.iter().map(|m| m.0))
            .collect();

        let Commit = G1Projective::multi_exp(&points, &scalars);
        let C_bar = G1Projective::multi_exp(&points, &random_scalars);

        let challenge: Challenge = compute_blind_challenge::<_, C>(
            &Commit, &C_bar, generators
        )?;

        let s_hat = FiatShamirProof(
            s_tilde + challenge.0 * secret_prover_blind.as_scalar()
        );

        let m_hat_list = random_scalars[1..]
            .iter()
            .zip(messages.iter())
            .map(|(m_tilde, msg)| {
                let m_hat = *m_tilde + challenge.0 * (msg.0);
                FiatShamirProof(m_hat)
            })
            .collect::<Vec<FiatShamirProof>>();

        Ok((CommitProof { commit: Commit, s_hat, m_hat_list, c: challenge }, secret_prover_blind))
    }

    // verify
    pub fn verify<G, C>(
        &self, generators: &G
    ) -> Result<bool, Error>
    where
        G: Generators,
        C: BbsCiphersuiteParameters
    {
        if self.m_hat_list.len() != generators.message_generators_length() {
            return Err(Error::MessageGeneratorsLengthMismatch {
                generators: generators.message_generators_length(), 
                messages:  self.m_hat_list.len()
            });
        };

        let scalars: Vec<_> = [self.s_hat.0]
            .iter()
            .copied()
            .chain(self.m_hat_list.iter().map(|m_hat| m_hat.0))
            .collect();

        let mut points = vec![generators.Q()];
        points.extend(generators.message_generators_iter());

        let C_bar = G1Projective::multi_exp(&points, &scalars) + self.commit * (- self.c.0);

        let cv = compute_blind_challenge::<_, C>(
            &self.commit, &C_bar, generators
        )?;

        if self.c != cv {
            return Ok(false);
        }

        return Ok(true)
    }
    

    // to octets

    // from octets
}

pub(crate) fn compute_blind_challenge<G, C>(
    C: &G1Projective,
    C_bar: &G1Projective,
    generators: &G
) -> Result<Challenge, Error>
where
    G: Generators,
    C: BbsCiphersuiteParameters,
{
    let mut data_to_hash = vec![];

    data_to_hash.extend(i2osp(
        generators.message_generators_length() as u64,
        NON_NEGATIVE_INTEGER_ENCODING_LENGTH,
    )?);

    for generator in generators.message_generators_iter() {
        data_to_hash.extend(point_to_octets_g1(&generator));
    }

    data_to_hash.extend(point_to_octets_g1(C).as_ref());
    data_to_hash.extend(point_to_octets_g1(C_bar).as_ref());

    Ok(Challenge(C::hash_to_scalar(&data_to_hash, None)?))
}


mod tests {
    use rand::RngCore;
    use rand_core::OsRng;

    use crate::{bbs::{
            ciphersuites::bls12_381_g1_shake_256::Bls12381Shake256CipherSuiteParameter,
            core::generator::memory_cached_generator::MemoryCachedGenerators
        }, 
        bbs_blind::core::commit::CommitProof
    };
    use crate::bbs::core::types::Message;
    use crate::common::hash_param::h2s::HashToScalarParameter;

    const M: usize = 100; // nym secrets

    #[test]
    fn generate_verify() {
        let mut rand_seeds = vec![[0u8; 9]; M];

        for i in 0..M {
            let _ = OsRng.try_fill_bytes(&mut rand_seeds[i]);
        }

        let committed_messages = rand_seeds.iter().map(
            |b: &[u8; 9]| {
                Message::from_arbitrary_data::<Bls12381Shake256CipherSuiteParameter>(
                    b.as_ref(),
                    Some(&Bls12381Shake256CipherSuiteParameter::default_map_message_to_scalar_as_hash_dst())
                )
        })
        .collect::<Result<Vec<Message>, _>>()
        .expect("claims to `Message` conversion failed");

        let generators = MemoryCachedGenerators::<
            Bls12381Shake256CipherSuiteParameter
        >::new(
        M,
        None,
        ).expect("generators creation failed");

        let (commit_with_proof, secret_prover_blind) = CommitProof::new::<_, _, Bls12381Shake256CipherSuiteParameter>(
            committed_messages, &generators
        ).unwrap();

        let res = commit_with_proof.verify::<_, Bls12381Shake256CipherSuiteParameter>(&generators).unwrap();

        assert!(res)
    }
}