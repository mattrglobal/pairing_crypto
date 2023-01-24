# Test Fixtures Generator

This crate consists of:
- a library for fixtures generation for the BBS signature scheme
- a CLI tool based upon above library to generate the fixtures

The library `bbs_fixtures_generator` is used in fixture based integration testing of `pairing_crypto` library.

## Build and Run

To build:
```sh
cargo build -p bbs-fixtures-generator
```

To test:
```sh
cargo test -p bbs-fixtures-generator
```

To run:
```sh
cargo run -p bbs-fixtures-generator -i <TEST_ASSET_FILE> -o <FIXTURE_OUTPUT_DIR>
```

To generate fixtures for `pairing_crypto` library integration tests:

- from root project directory,

```sh
cargo run -p bbs-fixtures-generator -- -i  tests/fixtures/bbs/test_asset.json -o tests/fixtures/bbs/
```

- from current directory,

```sh
cargo run -p bbs-fixtures-generator -- -i  ../../tests/fixtures/bbs/test_asset.json -o ../../tests/fixtures/bbs/
```
