CC = gcc

build:
	@cargo build --release
generate_headers:
	# @rustup install nightly
	# @rustup default nightly
	@cargo install cargo-expand
	@cargo install --force cbindgen

	@cbindgen --config cbindgen.toml --crate pairing_crypto_c --output include/pairing_crypto.h

	# @rustup default stable
test:
	@${CC} tests/pairing_crypto_test.c -o pairing_crypto_test -Iinclude -Ltarget/release -lpairing_crypto_c
	@chmod +x pairing_crypto_test
	@./pairing_crypto_test
clean:
	@cargo clean
	@rm -rf target
	@rm -f pairing_crypto_test
