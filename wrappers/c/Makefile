CC = gcc

format:
	@cargo fmt --all -- --check
clippy:
	@cargo clippy
check:
	@cargo check
audit:
	@cargo audit
build:
	@cargo build --release
build_ios:
	@./scripts/build-platform-targets.sh IOS out
generate_headers:
	@cargo install cargo-expand
	@cargo install --force cbindgen

	@rustup run nightly cbindgen --config cbindgen.toml --crate pairing_crypto_c --output include/pairing_crypto.h
test:
	@${CC} tests/pairing_crypto_test.c -o pairing_crypto_test -Iinclude -L../../target/release -lpairing_crypto_c
	@chmod +x pairing_crypto_test
	@./pairing_crypto_test
clean:
	@cargo clean
	@rm -rf target
	@rm -f pairing_crypto_test
