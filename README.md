# Pairing Cryptography

This library is a simple and easy to use one stop shop for [pairing-based cryptography](https://en.wikipedia.org/wiki/Pairing-based_cryptography) written in [Rust](rust-lang.org).

## Supported Curves

- [BLS 12-381](https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-09#section-4.2.1)

For a more exhaustive list of those published by the [CFRG](https://irtf.org/cfrg) please refer to [here](https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-09)

## Supported Signature Algorithms

- [Basic BLS Signatures](https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.1)

## API Design

See [here](./docs/API.md) for details on the APIs design

## Contribution Guide

To get started contributing to this project be sure to check out our [contribution guide](./docs/CONTRIBUTING.md)

## Repository Structure

Below is an outline of the repositories structure

```
├── src - Main source code folder
│   ├ lib.rs - Controls the exposed public API
│   ├ curves - Defines the different pairing based elliptic curves supported by the library
│   │   ├── bls_12381.rs
│   │   └── bls_12381
│   └ schemes - Defines the different cryptographic schemes (e.g signatures) supported by the library
│       ├── bls.rs
│       ├── bls
│       ├── bbs.rs
│       └── bbs
│       ├── ps.rs
│       └── ps
├── tests - Integration Tests
├── benches - Benchmarks
├── Cargo.toml
├── Cargo.lock
├── README.md
└── CONTRIBUTING.md
```
