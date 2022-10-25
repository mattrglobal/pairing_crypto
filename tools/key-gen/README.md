# BBS Key-Pair Generator CLI

This project contains a CLI tool to generate asymmetric cryptography key pairs supported by `pairing_crypto` library and output these in JSON or CBOR format as specified in the [Barreto-Lynn-Scott Elliptic Curve Key Representations for JOSE and COSE specification](https://tplooker.github.io/draft-ietf-cose-bls-key-representations/draft-ietf-cose-bls-key-representations.html).

## Usage

```
Key Generator CLI

Usage: key-gen [OPTIONS]

Options:
  -i, --ikm <IKM>                  [default: test-ikm-aa-bb-cc-dd-ee-ff-12345678]
  -k, --key-info <KEY_INFO>        [default: test-key-info]
  -c, --curve <CURVE>              [default: bls12381g1] [possible values: bls12381g1, bls12381g2]
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
  "d": "_nmYLctt4EA3jtzM_DoO72zOgJtk_7pDqXoFCfpizFE",
  "x": "olbufORO-VTYtXkD2k7hXc45KJONpCudrOAeIpOH3Wqu2tJ9MNUNcTze3Eqkr5dp"
}
```

2. Following command will use default values of the CLI arguments and prints generated BLS12381G2 curve key pair in JSON format.
```sh
cargo run -- -c bls12381g2 -i test-ikm-aa-bb-cc-dd-ee-ff-ABCD-ABCD
```
Output:
```json
{
  "kty": "OKP",
  "crv": "BLS12381G2",
  "d": "cHeieSss5qFsy7PmhAqPBNlq-38rAoooWOCTh_oaUHA",
  "x": "iTZxTRJ_kIn6RUZ-M3y6n4gpDKUMnTkK89tXoIxOg4ZAgn7wtaNjd5sgiBiO2Pm-B3xZdNY1hroHLKa5kgwyErnnbOwYIJ2RvhCI-66SEfjOuFkVR3DtEgdduX-WP2n-"
}
```

3. Following command will use default values of the CLI arguments and prints generated BLS12381G1 curve key pair in CBOR format.
```sh
cargo run -- -o cbor
```
Output:
```sh
a40101200d21982018fe18791898182d18cb186d18e018401837188e18dc18cc18fc183a0e18ef186c18ce1880189b186418ff18ba184318a9187a050918fa186218cc185123983018a2185618ee187c18e4184e18f9185418d818b518790318da184e18e1185d18ce183918281893188d18a4182b189d18ac18e0181e18221893188718dd186a18ae18da18d2187d183018d50d1871183c18de18dc184a18a418af18971869
```

4. Following command will use default values of the CLI arguments and prints generated BLS12381G2 curve key pair in CBOR format.
```sh
cargo run -- -c bls12381g2 -i test-ikm-aa-bb-cc-dd-ee-ff-ABCD-ABCD -o cbor
```
Output:
```sh
a40101200e2198201870187718a21879182b182c18e618a1186c18cb18b318e618840a188f0418d9186a18fb187f182b02188a1828185818e01893188718fa181a18501870239860188918361871184d12187f1890188918fa18451846187e1833187c18ba189f188818290c18a50c189d18390a18f318db185718a0188c184e1883188618401882187e18f018b518a318631877189b182018881818188e18d818f918be07187c1859187418d61835188618ba07182c18a618b918920c18321218b918e7186c18ec18181820189d189118be10188818fb18ae18921118f818ce18b81859151847187018ed1207185d18b9187f1896183f186918fe
```

**Note** 
We can use https://cbor.me/ to decode CBOR values(just paste in right pan input-field of website and click green button above it) and test if the decoded values match that of corresponding JSON encoded values.
