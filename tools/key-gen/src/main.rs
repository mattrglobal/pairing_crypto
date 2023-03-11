use base64::URL_SAFE_NO_PAD;
use ciborium::cbor;
use clap::{Parser, ValueEnum};
#[allow(unused)]
use mcore::bls48581::{
    big::{BIG, NLEN},
    bls256,
    ecp::ECP,
    ecp8::ECP8,
    pair8::{g1mul, g2mul},
    rom,
};
use pairing_crypto::{
    bbs::ciphersuites::bls12_381::KeyPair as Bls12381G2KeyPair,
    bls::core::key_pair::KeyPair as Bls12381G1KeyPair,
};
use rand::{self, Rng};
use rand_chacha::ChaCha8Rng;
use rand_seeder::Seeder;
use serde::Serialize;
use serde_bytes::Bytes;
use strum::IntoStaticStr;

macro_rules! bls48581_key_pair {
    (
        $seed:ident,
        $generator:ident,
        $field_size:ident,
        $group_size:ident,
        $mul_fun:ident
    ) => {{
        // random secret key generation from seed
        // TODO: use a secure KDF.
        let mut rng: ChaCha8Rng = Seeder::from($seed).make_rng();
        let mut sk = [0u8; $field_size];
        rng.fill(&mut sk[..]);

        // secret key to scalar
        let sk_scalar = BIG::frombytes(&sk);

        // public key calculation
        let pk = $mul_fun(&$generator, &sk_scalar);

        // public key to bytes
        let mut pk_bytes = [0u8; $group_size];
        pk.tobytes(&mut pk_bytes, true); // true for compressed

        (sk.to_vec(), pk_bytes.to_vec())
    }};
}

fn bls48581_g2_key_pair(seed: &str) -> (Vec<u8>, Vec<u8>) {
    const BFS: usize = bls256::BFS;
    const G2S: usize = 8 * BFS + 1; // Group 2 Size  - compressed

    let g = ECP8::generator();
    bls48581_key_pair!(seed, g, BFS, G2S, g2mul)
}

fn bls48581_g1_key_pair(seed: &str) -> (Vec<u8>, Vec<u8>) {
    const BFS: usize = bls256::BFS;
    const G1S: usize = BFS + 1; // Group 1 Size  - compressed

    let g = ECP::generator();
    bls48581_key_pair!(seed, g, BFS, G1S, g1mul)
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, IntoStaticStr,
)]
enum Curve {
    Bls12381G1,
    Bls12381G2,
    Bls48581G1,
    Bls48581G2,
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, IntoStaticStr,
)]
enum OutputType {
    Json,
    Cbor,
}

#[derive(Parser)]
#[command(author, version, about = "Key Generator CLI", long_about = None)]
struct Cli {
    // IKM.
    #[arg(
        short,
        long,
        value_parser,
        default_value = "test-ikm-aa-bb-cc-dd-ee-ff-12345678"
    )]
    ikm: String,
    // Key Info.
    #[arg(short, long, value_parser, default_value = "test-key-info")]
    key_info: String,
    // Curve.
    #[arg(short, long, value_parser, default_value = "bls12381-g1")]
    curve: Curve,
    // Output type.
    #[arg(short, long, value_parser, default_value = "json")]
    output_type: OutputType,
}

#[derive(Default, Debug, Serialize)]
struct KeyReprsentation<'a> {
    kty: String,
    crv: &'a str,
    x: String,
    d: String,
}

fn main() {
    let Cli {
        ikm,
        key_info,
        curve,
        output_type,
    } = Cli::parse();

    let (mut priv_key, pub_key) = match curve {
        Curve::Bls12381G1 => {
            Bls12381G1KeyPair::new(ikm.clone(), Some(key_info.as_bytes()))
                .map(|key_pair| {
                    (
                        key_pair.secret_key.to_bytes().to_vec(),
                        key_pair.public_key.to_octets().to_vec(),
                    )
                })
                .expect("key generation failed")
        }
        Curve::Bls12381G2 => {
            Bls12381G2KeyPair::new(ikm.clone(), Some(key_info.as_bytes()))
                .map(|key_pair| {
                    (
                        key_pair.secret_key.to_bytes().to_vec(),
                        key_pair.public_key.to_octets().to_vec(),
                    )
                })
                .unwrap()
        }
        Curve::Bls48581G1 => {
            println!(
                "Note: the created secret key is NOT cryptographically secure \
                 and is only used for testing purposes"
            );
            // TODO: Include key_info to the seed
            bls48581_g1_key_pair(&ikm)
        }
        Curve::Bls48581G2 => {
            println!(
                "Note: the created secret key is NOT cryptographically secure \
                 and is only used for testing purposes"
            );
            // TODO: Include key_info to the seed
            bls48581_g2_key_pair(&ikm)
        }
    };

    // pairing crypto outputs `KeyPair::secret_key` in big-endian format
    // reverst the vector to make representation little endian
    priv_key.reverse();
    println!("IKM={ikm}");
    println!("Key-Info={key_info}");
    println!("d={:?}", hex::encode(&priv_key));
    println!("x={:?}", hex::encode(&pub_key));

    match output_type {
        OutputType::Json => {
            println!("\nJSON Encoded Output\n");
            let priv_key = base64::encode_config(priv_key, URL_SAFE_NO_PAD);
            let pub_key = base64::encode_config(pub_key, URL_SAFE_NO_PAD);
            let key_repr = KeyReprsentation {
                kty: "OKP".to_owned(),
                crv: curve.into(),
                x: pub_key,
                d: priv_key,
            };
            println!("{}", serde_json::to_string_pretty(&key_repr).unwrap());
        }

        OutputType::Cbor => {
            println!("\nCBOR Encoded Output\n");
            let val = cbor!(
                {
                    1 => 1,
                    -1 => match curve {
                        Curve::Bls12381G1 => 13,
                        Curve::Bls12381G2 => 14,
                        Curve::Bls48581G1 => 15,
                        Curve::Bls48581G2 => 16
                    },
                    -2 => &Bytes::new(&pub_key[..]),
                    -4 => &Bytes::new(&priv_key[..]),
                }
            )
            .unwrap();

            let mut bytes = Vec::new();
            ciborium::ser::into_writer(&val, &mut bytes).unwrap();

            println!("{:?}", hex::encode(&bytes));
        }
    }
}
