use base64::URL_SAFE_NO_PAD;
use clap::{Parser, ValueEnum};
use pairing_crypto::{
    bbs::ciphersuites::bls12_381::KeyPair as Bls12381G2KeyPair,
    bls::core::key_pair::KeyPair as Bls12381G1KeyPair,
};
use serde::Serialize;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Curve {
    Bls12381G1,
    Bls12381G2,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
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
struct KeyReprsentation {
    kty: String,
    crv: String,
    d: String,
    x: String,
}

fn main() {
    let Cli {
        ikm,
        key_info,
        curve,
        output_type,
    } = Cli::parse();

    let (mut priv_key, pub_key, curve_type) = match curve {
        Curve::Bls12381G1 => {
            Bls12381G1KeyPair::new(ikm, Some(key_info.as_bytes()))
                .map(|key_pair| {
                    (
                        key_pair.secret_key.to_bytes().to_vec(),
                        key_pair.public_key.to_octets().to_vec(),
                        "BLS12381G1",
                    )
                })
                .expect("key generation failed")
        }
        Curve::Bls12381G2 => {
            Bls12381G2KeyPair::new(ikm, Some(key_info.as_bytes()))
                .map(|key_pair| {
                    (
                        key_pair.secret_key.to_bytes().to_vec(),
                        key_pair.public_key.to_octets().to_vec(),
                        "BLS12381G2",
                    )
                })
                .unwrap()
        }
    };

    // pairing crypto outputs `KeyPair::secret_key` in big-endian format
    // reverst the vector to make representation little endian
    priv_key.reverse();
    let priv_key = base64::encode_config(priv_key, URL_SAFE_NO_PAD);
    let pub_key = base64::encode_config(pub_key, URL_SAFE_NO_PAD);
    let key_repr = KeyReprsentation {
        kty: "OKP".to_owned(),
        crv: curve_type.to_owned(),
        d: priv_key,
        x: pub_key,
    };

    match output_type {
        OutputType::JSON => {
            println!("{}", serde_json::to_string_pretty(&key_repr).unwrap());
        }

        OutputType::CBOR => {
            println!(
                "{:?}",
                hex::encode(&serde_cbor::to_vec(&key_repr).unwrap())
            );
        }
    }
}
