# BBS Key-Pair Generator CLI

This project contains a CLI tool to generate asymmetric cryptography key pairs supported by `pairing_crypto` library and output these in JSON or CBOR format as specified in the [Barreto-Lynn-Scott Elliptic Curve Key Representations for JOSE and COSE specification](https://tplooker.github.io/draft-ietf-cose-bls-key-representations/draft-ietf-cose-bls-key-representations.html).

## Usage

```
Key Generator CLI

Usage: key-gen [OPTIONS]

Options:
  -i, --ikm <IKM>                  [default: test-ikm-aa-bb-cc-dd-ee-ff-12345678]
  -k, --key-info <KEY_INFO>        [default: test-key-info]
  -c, --curve <CURVE>              [default: bls12381g1] [possible values: bls12381g1, bls12381g2, bls48581g1, bls48581g2]
  -o, --output-type <OUTPUT_TYPE>  [default: json] [possible values: json, cbor]
  -h, --help                       Print help information
  -V, --version                    Print version information

```

## Build

This tool makes use of the [MIRACL](https://github.com/miracl/core) library to generate key pairs in the Bls48581 curve. Make sure you build the [Rust package of MIRACL](https://github.com/miracl/core/tree/master/rust) and that you add the path to the package to the cargo.toml file of this tool. See the MIRACL Rust package [README](https://github.com/miracl/core/blob/master/rust/readme.md) for more details.

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
  "crv": "Bls12381G1",
  "x": "olbufORO-VTYtXkD2k7hXc45KJONpCudrOAeIpOH3Wqu2tJ9MNUNcTze3Eqkr5dp",
  "d": "_nmYLctt4EA3jtzM_DoO72zOgJtk_7pDqXoFCfpizFE"
}
```

2. Following command will use default values of the CLI arguments and prints generated BLS12381G2 curve key pair in JSON format.
```sh
cargo run -- -c bls12381-g2 -i test-ikm-aa-bb-cc-dd-ee-ff-ABCD-ABCD
```
Output:
```json
{
  "kty": "OKP",
  "crv": "Bls12381G2",
  "x": "iTZxTRJ_kIn6RUZ-M3y6n4gpDKUMnTkK89tXoIxOg4ZAgn7wtaNjd5sgiBiO2Pm-B3xZdNY1hroHLKa5kgwyErnnbOwYIJ2RvhCI-66SEfjOuFkVR3DtEgdduX-WP2n-",
  "d": "cHeieSss5qFsy7PmhAqPBNlq-38rAoooWOCTh_oaUHA"
}
```

3. Following command will use default values of the CLI arguments and prints generated BLS12381G1 curve key pair in CBOR format.
```sh
cargo run -- -o cbor
```
Output:
```sh
a40101200d215830a256ee7ce44ef954d8b57903da4ee15dce3928938da42b9dace01e229387dd6aaedad27d30d50d713cdedc4aa4af9769235820fe79982dcb6de040378edcccfc3a0eef6cce809b64ffba43a97a0509fa62cc51
```

4. Following command will use default values of the CLI arguments and prints generated BLS12381G2 curve key pair in CBOR format.
```sh
cargo run -- -c bls12381-g2 -i test-ikm-aa-bb-cc-dd-ee-ff-ABCD-ABCD -o cbor
```
Output:
```sh
a40101200e2158608936714d127f9089fa45467e337cba9f88290ca50c9d390af3db57a08c4e838640827ef0b5a363779b2088188ed8f9be077c5974d63586ba072ca6b9920c3212b9e76cec18209d91be1088fbae9211f8ceb859154770ed12075db97f963f69fe2358207077a2792b2ce6a16ccbb3e6840a8f04d96afb7f2b028a2858e09387fa1a5070
```

**Note** 
We can use https://cbor.me/ to decode CBOR values(just paste in right pan input-field of website and click green button above it) and test if the decoded values match that of corresponding JSON encoded values.
