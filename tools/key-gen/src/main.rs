use base64::URL_SAFE_NO_PAD;
use ciborium::cbor;
use clap::{Parser, ValueEnum};
use mcore::bls48581::{
    big::BIG,
    bls256,
    ecp::ECP,
    ecp8::ECP8,
    pair8::{g1mul, g2mul},
};
use pairing_crypto::{
    bbs::ciphersuites::bls12_381::KeyPair as Bls12381G2KeyPair,
    bls::core::key_pair::KeyPair as Bls12381G1KeyPair
};
use rand::{self, Rng};
use rand_chacha::ChaCha8Rng;
use rand_seeder::Seeder;
use serde::Serialize;
use serde_bytes::Bytes;
use strum::IntoStaticStr;
use group::Curve;
use blstrs::{G2Affine};

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

        // secret key is 65 bytes long. However, MIRACL interface expects a 73 be byte array.
        // Populate the 65 last bytes of the 
        rng.fill(&mut sk[$field_size-65..]);

        // secret key to scalar
        let sk_scalar = BIG::frombytes(&sk);

        let mut sk_scalar_bytes = [0u8; $field_size];
        sk_scalar.tobytes(&mut sk_scalar_bytes);

        // public key calculation
        let pk = $mul_fun(&$generator, &sk_scalar);

        // public key coordinates to bytes
        let x = pk.getx();
        let y = pk.gety();

        let mut x_bytes = [0u8; $group_size];
        x.tobytes(&mut x_bytes);

        let mut y_bytes = [0u8; $group_size];
        y.tobytes(&mut y_bytes);

        // keep the 65 bytes of the private key
        let sk_vec = sk.to_vec();
        let priv_key = sk_vec[$field_size-65..].to_vec();

        (priv_key.to_vec(), x_bytes.to_vec(), y_bytes.to_vec())
    }};
}

fn bls48581_g2_key_pair(seed: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    const BFS: usize = bls256::BFS;
    const G2S: usize = 8 * BFS;

    let g = ECP8::generator();
    // let (sk, mut x, mut y) = bls48581_key_pair!(seed, g, BFS, G2S, g2mul);

    let mut rng: ChaCha8Rng = Seeder::from(seed).make_rng();
    let mut sk = [0u8; BFS];

    // secret key is 65 bytes long. However, MIRACL interface expects a 73 be byte array.
    // Populate the 65 last bytes of the 
    rng.fill(&mut sk[BFS-65..]);

    // secret key to scalar
    let sk_scalar = BIG::frombytes(&sk);

    let mut sk_scalar_bytes = [0u8; BFS];
    sk_scalar.tobytes(&mut sk_scalar_bytes);

    // public key calculation
    let pk = g2mul(&g, &sk_scalar);

    // public key coordinates to bytes
    let x = pk.getx();
    let y = pk.gety();

    let mut x_bytes = [0u8; G2S];
    x.tobytes(&mut x_bytes);

    let mut y_bytes = [0u8; G2S];
    y.tobytes(&mut y_bytes);

    // keep the 65 bytes of the private key
    let sk_vec = sk.to_vec();
    let priv_key = sk_vec[BFS-65..].to_vec();

    (priv_key, x_bytes.to_vec(), y_bytes.to_vec())
}

fn bls48581_g1_key_pair(seed: &str) -> (Vec<u8>,  Vec<u8>, Vec<u8>) {
    const BFS: usize = bls256::BFS;
    const G1S: usize = BFS;

    let g = ECP::generator();
    bls48581_key_pair!(seed, g, BFS, G1S, g1mul)
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, IntoStaticStr,
)]
enum Curves {
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
    curve: Curves,
    // Output type.
    #[arg(short, long, value_parser, default_value = "json")]
    output_type: OutputType,
}

#[derive(Default, Debug, Serialize)]
struct KeyReprsentation<'a> {
    kty: String,
    crv: &'a str,
    x: String,
    y: String,
    d: String,
}

// test loading the point in MIRACL
use mcore::bls12381::{
    big::BIG as big_bls12381,
    bls,
    ecp::ECP as ecp_bls12381,
    ecp2::ECP2,
    fp2::FP2,
};

fn get_bls12381_g2_key_pair(seed: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>){
    let mut bls12381_seed = seed.clone().to_owned();
    bls12381_seed.push_str("BLS12381-G2");
    let key_pair = Bls12381G2KeyPair::new(&bls12381_seed.as_bytes(), Some("test-key-info".as_bytes())).unwrap();

    let pk = key_pair.public_key.0;
    let pk_affine = pk.to_affine();

    let bls12381_pk_x_c0 = pk_affine.x().c0().to_bytes_be();
    let bls12381_pk_x_c1 = pk_affine.x().c1().to_bytes_be();
    let bls12381_pk_x = [bls12381_pk_x_c1, bls12381_pk_x_c0].concat();

    let bls12381_pk_y_c0 = pk_affine.y().c0().to_bytes_be();
    let bls12381_pk_y_c1 = pk_affine.y().c1().to_bytes_be();
    let bls12381_pk_y= [bls12381_pk_y_c1, bls12381_pk_y_c0].concat();

    let x_fp2s = FP2::frombytes(&bls12381_pk_x);
    let y_fp2s = FP2::frombytes(&bls12381_pk_y);

    let miracl_point = ECP2::new_fp2s(&x_fp2s, &y_fp2s);
    
    // miracl to bytes
    let mut miracl_point_bf = [0u8; 97];
    miracl_point.tobytes(&mut miracl_point_bf, true);

    // getting the coordinates from the miracl point
    let miracl_point_x = miracl_point.getx();
    let miracl_point_y = miracl_point.gety();

    let mut miracl_point_x_bytes = [0u8; 2*48];
    miracl_point_x.tobytes(&mut miracl_point_x_bytes);

    let mut miracl_point_y_bytes = [0u8; 2*48];
    miracl_point_y.tobytes(&mut miracl_point_y_bytes);

    let blstrs_uncompressed: [u8; 192] = [miracl_point_x_bytes, miracl_point_y_bytes].concat().try_into().unwrap();

    let blstrs_g2_affine = G2Affine::from_uncompressed(&blstrs_uncompressed).unwrap();

    (key_pair.secret_key.to_bytes().to_vec(), bls12381_pk_x.to_vec(), bls12381_pk_y.to_vec())
}

fn get_bls12381_g1_key_pair(seed: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>){
    let mut bls12381_seed = seed.clone().to_owned();
    bls12381_seed.push_str("BLS12381-G1");
    let key_pairs = Bls12381G1KeyPair::new(&bls12381_seed.as_bytes(), Some("test-key-info".as_bytes()));

    let key_pair = key_pairs.unwrap();

    let pk = key_pair.public_key.0;
    let pk_affine = pk.to_affine();
    let bls12381_pk_x = pk_affine.x().to_bytes_be();
    let bls12381_pk_y = pk_affine.y().to_bytes_be();

    let x_fp2s = big_bls12381::frombytes(&bls12381_pk_x);
    let y_fp2s = big_bls12381::frombytes(&bls12381_pk_y);
    let miracl_point = ecp_bls12381::new_bigs(&x_fp2s, &y_fp2s);
    
    // miracl to bytes
    let mut miracl_point_bf = [0u8; 97];
    miracl_point.tobytes(&mut miracl_point_bf, true);

    (key_pair.secret_key.to_bytes().to_vec(), bls12381_pk_x.to_vec(), bls12381_pk_y.to_vec())
}

fn main() {
    let Cli {
        ikm,
        key_info,
        curve,
        output_type,
    } = Cli::parse();

    let (mut priv_key, pub_key_x, pub_key_y) = match curve {
        Curves::Bls12381G1 => {
            get_bls12381_g1_key_pair(&ikm)
        }
        Curves::Bls12381G2 => {
            get_bls12381_g2_key_pair(&ikm)
        }
        Curves::Bls48581G1 => {
            println!(
                "Note: the created secret key is NOT cryptographically secure \
                 and is only used for testing purposes"
            );
            // TODO: Include key_info to the seed
            bls48581_g1_key_pair(&ikm)
        }
        Curves::Bls48581G2 => {
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
    println!("x={:?}", hex::encode(&pub_key_x));
    println!("y={:?}", hex::encode(&pub_key_y));

    match output_type {
        OutputType::Json => {
            println!("\nJSON Encoded Output\n");
            let priv_key = base64::encode_config(priv_key, URL_SAFE_NO_PAD);
            let pub_key_x_encoded = base64::encode_config(pub_key_x, URL_SAFE_NO_PAD);
            let pub_key_y_encoded = base64::encode_config(pub_key_y, URL_SAFE_NO_PAD);
            let key_repr = KeyReprsentation {
                kty: "OKP".to_owned(),
                crv: curve.into(),
                x: pub_key_x_encoded,
                y: pub_key_y_encoded,
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
                        Curves::Bls12381G1 => 13,
                        Curves::Bls12381G2 => 14,
                        Curves::Bls48581G1 => 15,
                        Curves::Bls48581G2 => 16
                    },
                    -2 => &Bytes::new(&pub_key_x[..]),
                    -3 => &Bytes::new(&pub_key_y[..]),
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
