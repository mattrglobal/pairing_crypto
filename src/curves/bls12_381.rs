use super::{KeyGen, KeyPair};

use ff::Field;
use hkdf::Hkdf;
use pairing_plus::{
    bls12_381::{Fr, G1, G2},
    hash_to_field::BaseFromRO,
    CurveProjective,
};
use rand::prelude::*;
use sha2::{
    digest::generic_array::{typenum::U48, GenericArray},
    Sha256,
};

macro_rules! keygen_impl {
    ($type:ident) => {
        impl KeyGen for $type {
            type PKType = $type;

            /// generate a keypair
            fn generate_key_pair(seed: Option<&[u8]>) -> Result<KeyPair<Self::PKType, Self>, String> {
                let mut sk = secret_keygen(seed)?;
                while sk.is_zero() {
                    sk = secret_keygen(None)?;
                }
                let mut pk = Self::PKType::one();
                pk.mul_assign(sk);
                Ok(KeyPair {
                    secret_key: sk,
                    public_key: pk,
                    _signature: std::marker::PhantomData
                })
            }
        }
    };
}

keygen_impl!(G1);
keygen_impl!(G2);

/// Generates the secret key in accordance with section 2.3 in
/// <https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/?include_text=1>
fn secret_keygen(ikm: Option<&[u8]>) -> Result<Fr, String> {
    const SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";
    let mut s = ikm.map(|s| s.to_vec()).unwrap_or_else(random_seed);
    if s.len() < 32 {
        return Err(format!(
            "Seed must be at least 32 characters, found: {}",
            s.len()
        ));
    }
    s.push(0u8);
    let mut m = GenericArray::<u8, U48>::default();
    let _ = Hkdf::<Sha256>::new(Some(SALT), &s).expand(&[0, 48], &mut m);
    Ok(Fr::from_okm(&m))
}

fn random_seed() -> Vec<u8> {
    let mut seed = vec![0u8; 32];
    thread_rng().fill_bytes(&mut seed);
    seed
}
