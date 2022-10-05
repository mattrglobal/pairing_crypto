# BBS Generators CLI

This project contains a CLI tool to generate `Generatos` as described in BBS specification.

## Usage

```

USAGE:
    bbs-generators [OPTIONS]

OPTIONS:
    -c, --ciphersuite <CIPHERSUITE>
            [default: bls12381-shake256] [possible values: bls12381-sha256, bls12381-shake256]

    -f, --file-name <FILE_NAME>
            [default: generators.json]

    -h, --help
            Print help information

    -n, --num-of-generators <NUM_OF_GENERATORS>
            [default: 12]

    -o, --output-type <OUTPUT_TYPE>
            [default: print] [possible values: print, file]

```


## Build and Run

To build and run with default argument values: the following command will print value of 10 Bls12-381-shake-256 generators.
```sh
cargo run
```

The following command will store value of 10 Bls12-381-shake-256 generators in `generators.json` file in current directory.
```sh
cargo run -- -ofile
```

The following command will store value of 10 Bls12-381-sha-256 generators in `bls12381_sha256_generators.json` file in current directory.
```sh
cargo run -- -n=12 -c=bls12381-sha256 -o=file -f="bls12381_sha256_generators.json"
```
