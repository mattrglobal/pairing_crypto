# Install and setup the rust tool cbindgen to automate the generation of the c header file through
# parsing the ffi-bbs-signatures library code.

set -e

# We have to use nightly toolchain with cbindgen otherwise compliation does not work
rustup install nightly
rustup default nightly
cargo install cargo-expand

# Force install so we get the latest
cargo install --force cbindgen

# Build the C headers for the crate
cbindgen --config cbindgen.toml --crate pairing_crypto_c --output include/pairing_crypto.h

# Revert toolchain so downstream rustup operations are not affected
rustup default stable
