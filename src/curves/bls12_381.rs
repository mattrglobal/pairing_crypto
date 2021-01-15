use super::{KeyPair, KeyGen};

use hkdf::Hkdf;
use pairing_plus::{
    CurveProjective,
    hash_to_field::BaseFromRO,
    bls12_381::{Fr, G1, G2},
};
use rand::prelude::*;
use sha2::{
    Sha256,
    digest::generic_array::{GenericArray, typenum::U48}
};

macro_rules! keygen_impl {
    ($type:ident) => {
        impl KeyGen for $type {
            type PKType = $type;

            fn keygen(seed: Option<&[u8]>) -> KeyPair<Self::PKType> {
                let sk = secret_keygen(seed);
                let mut pk = Self::PKType::one();
                pk.mul_assign(sk);
                KeyPair {
                    secret_key: sk,
                    public_key: pk,
                }
            }
        }
    };
}

keygen_impl!(G1);
keygen_impl!(G2);

fn secret_keygen(ikm: Option<&[u8]>) -> Fr {
    const SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";
    let mut s = ikm.map(|s| s.to_vec()).unwrap_or_else(random_seed);
    s.push(0u8);
    let mut m = GenericArray::<u8, U48>::default();
    let _ = Hkdf::<Sha256>::new(Some(SALT), &s).expand(&[0, 48], &mut m);
    Fr::from_okm(&m)
}

fn random_seed() -> Vec<u8> {
    let mut seed = vec![0u8; 32];
    thread_rng().fill_bytes(&mut seed);
    seed
}