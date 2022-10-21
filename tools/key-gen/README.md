# BBS Key-Pair Generator CLI

This project contains a CLI tool to generate asymmetric cryptography key pairs supported by `pairing_crypto` library and output these in JSON or CBOR format as specified in the [Barreto-Lynn-Scott Elliptic Curve Key Representations for JOSE and COSE specification](https://tplooker.github.io/draft-ietf-cose-bls-key-representations/draft-ietf-cose-bls-key-representations.html).

## Usage

```
Key Generator CLI

Usage: key-gen [OPTIONS]

Options:
  -i, --ikm <IKM>                  [default: test-ikm-aa-bb-cc-dd-ee-ff-12345678]
  -k, --key-info <KEY_INFO>        [default: test-key-info]
  -c, --curve <CURVE>              [default: bls12381-g1] [possible values: bls12381-g1, bls12381-g2]
  -o, --output-type <OUTPUT_TYPE>  [default: json] [possible values: json, cbor]
  -h, --help                       Print help information
  -V, --version                    Print version information

```

## Build

```sh
cargo build
```

## Sample Run

1. Following command will use default values of the CLI arguments and prints generated BLS12381G1 curve key pair in JSON format.
```sh
cargo run
```
Output:
```json
{
  "kty": "OKP",
  "crv": "BLS12381G1",
  "x": "_nmYLctt4EA3jtzM_DoO72zOgJtk_7pDqXoFCfpizFE",
  "d": "olbufORO-VTYtXkD2k7hXc45KJONpCudrOAeIpOH3Wqu2tJ9MNUNcTze3Eqkr5dp"
}
```

2. Following command will use default values of the CLI arguments and prints generated BLS12381G2 curve key pair in JSON format.
```sh
cargo run -- -c bls12381-g2
```
Output:
```json
{
  "kty": "OKP",
  "crv": "BLS12381G2",
  "x": "_nmYLctt4EA3jtzM_DoO72zOgJtk_7pDqXoFCfpizFE",
  "d": "tTbCV2ztXdPBQOf5ksrhZ3l2KoCBdwDk6x8hih6IWdyD3A_e1p3Yt-Vp8gt1DD8uCQO_0lntjLQ_2PAGpd5Q-ks6UgkedMroobcrt0l9RUq4__GsDzJMSQJ1bQOCC0co"
}

3. Following command will use default values of the CLI arguments and prints generated BLS12381G1 curve key pair in CBOR format.
```sh
cargo run -- -o cbor
```
Output:
```sh
a4636b7479634f4b50636372766a424c53313233383147316178782b5f6e6d594c637474344541336a747a4d5f446f4f37327a4f674a746b5f37704471586f46436670697a4645616478406f6c6275664f524f2d56545974586b44326b3768586334354b4a4f4e70437564724f416549704f483357717532744a394d4e554e63547a653345716b72356470
```

4. Following command will use default values of the CLI arguments and prints generated BLS12381G2 curve key pair in CBOR format.
```sh
cargo run -- -c bls12381-g2 -o cbor
```
Output:
```sh
a4636b7479634f4b50636372766a424c53313233383147326178782b5f6e6d594c637474344541336a747a4d5f446f4f37327a4f674a746b5f37704471586f46436670697a4645616478807454624356327a7458645042514f66356b7372685a336c324b6f43426477446b36783868696836495764794433415f6531703359742d5670386774314444387543514f5f306c6e746a4c515f32504147706435512d6b733655676b65644d726f6f62637274306c39525571345f5f4773447a4a4d53514a3162514f434330636f
```

**Note**  
We can use https://cbor.me/ to decode CBOR values(just paste in right pan input-field of website and click green button above it) and test if the decoded values match that of corresponding JSON encoded values.
