# Pairing Cryptography

This library is a simple and easy to use one stop shop for [pairing-based cryptography](https://en.wikipedia.org/wiki/Pairing-based_cryptography) written in [Rust](rust-lang.org).

## Supported Curves

- [BLS 12-381](https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-09#section-4.2.1)

For a more exhaustive list of those published by the [CFRG](https://irtf.org/cfrg) please refer to [here](https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-09)

## Supported Signature Algorithms

- [BBS Signatures](https://identity.foundation/bbs-signature/draft-bbs-signatures.html)
- [BLS Signatures](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05)

## API Design

See [here](./docs/API.md) for details on the APIs design

## Contribution Guide

To get started contributing to this project be sure to check out our [contribution guide](./docs/CONTRIBUTING.md)

## Repository Structure

Below is an outline of the repositories structure

```
├── src - Main source code folder
│   ├ common - Common functionality and utilities
│   ├ curves - Defines the different pairing based elliptic curves supported by the library
│   └ schemes - Defines the different cryptographic schemes (e.g. BBS signatures) supported by the library
│   └ tests - Unit tests
├── tests - Integration tests (public APIs of a scheme)
├── wrappers - Bindings to other languages
├── benches - Benchmarks
```
