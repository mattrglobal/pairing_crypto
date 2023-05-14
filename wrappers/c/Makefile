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
build_debug:
	@cargo build
build_ios:
	@./scripts/build-platform-targets.sh IOS out
generate_headers:
	@cargo install cargo-expand
	@cargo install --force cbindgen

	@rustup run nightly cbindgen --config cbindgen.toml --crate pairing_crypto_c --output include/pairing_crypto.h
test: build
	@${CC} tests/bbs_api_test.c -o bbs_api_test -Iinclude -L../../target/release -lpairing_crypto_c
	@chmod +x bbs_api_test
	@./bbs_api_test
# check memory leaks on MacOS host
check_leaks_macos: build_debug generate_headers
	@${CC} -g -O0 tests/bbs_api_test.c -o bbs_api_test -Iinclude -L../../target/debug -lpairing_crypto_c
	@chmod +x bbs_api_test
	@leaks --atExit -- ./bbs_api_test
# check memory leaks on Linux host
# make sure valgrind is already installed
check_leaks_valgrind: build_debug generate_headers
	@valgrind --error-exitcode=1 --leak-check=full --show-leak-kinds=all ./bbs_api_test
clean:
	@cargo clean
	@rm -rf target
	@rm -f bbs_api_test
