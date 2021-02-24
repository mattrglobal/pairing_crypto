use super::{KeyGen, KeyPair};

use ff::Field;
use hkdf::Hkdf;
use pairings::{
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
    ($ty1:ident, $ty2:ident) => {
        impl KeyGen for $ty1 {
            type PKType = $ty2;

            /// generate a keypair
            fn generate_key_pair(seed: Option<&[u8]>) -> Result<KeyPair<Self, Self::PKType>, String> {
                let mut sk = secret_keygen(seed)?;
                while sk.is_zero() {
                    sk = secret_keygen(None)?;
                }
                Ok(KeyPair {
                    secret_key: sk,
                    _public_key: std::marker::PhantomData,
                    _signature: std::marker::PhantomData
                })
            }
        }
    };
}

keygen_impl!(G1, G2);
keygen_impl!(G2, G1);

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

fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    thread_rng().fill_bytes(&mut seed.as_mut());
    seed
}
