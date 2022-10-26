use base64::URL_SAFE_NO_PAD;
use ciborium::cbor;
use clap::{Parser, ValueEnum};
use pairing_crypto::{
    bbs::ciphersuites::bls12_381::KeyPair as Bls12381G2KeyPair,
    bls::core::key_pair::KeyPair as Bls12381G1KeyPair,
};
use serde::Serialize;
use serde_bytes::Bytes;
use strum::IntoStaticStr;

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, IntoStaticStr,
)]
enum Curve {
    Bls12381G1,
    Bls12381G2,
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, IntoStaticStr,
)]
enum OutputType {
    JSON,
    CBOR,
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
    };

    // pairing crypto outputs `KeyPair::secret_key` in big-endian format
    // reverst the vector to make representation little endian
    priv_key.reverse();
    println!("IKM={}", ikm);
    println!("Key-Info={}", key_info);
    println!("d={:?}", hex::encode(&priv_key));
    println!("x={:?}", hex::encode(&pub_key));

    match output_type {
        OutputType::JSON => {
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

        OutputType::CBOR => {
            println!("\nCBOR Encoded Output\n");
            let val = cbor!(
                {
                    1 => 1,
                    -1 => match curve {
                        Curve::Bls12381G1 => 13,
                        Curve::Bls12381G2 => 14,
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
