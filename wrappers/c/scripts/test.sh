# Test using the rust lib in other languages on different platforms.
# Currently it only supports testing pairing_crypto c based interface on macos.

set -e

PLATFORM=$1

if [ -z "$PLATFORM" ]
then
  echo "No environment supplied assuming current target"
  PLATFORM="DEFAULT"
fi

case $PLATFORM in
  MACOS)
      echo "Building for Apple Darwin x86_64"
      rustup target add x86_64-apple-darwin
      cargo build --target x86_64-apple-darwin --release
      export RUST_LIBRARY_DIRECTORY="${PWD}/target/x86_64-apple-darwin/release"
      cd $RUST_LIBRARY_DIRECTORY
      cmake ../../../tests
      cmake --build .
      ./pairing_crypto_test
      ;;
  DEFAULT)
    echo "Building for current target"
    cargo build --release
    export RUST_LIBRARY_DIRECTORY="${PWD}/target/release"
    cd $RUST_LIBRARY_DIRECTORY
    cmake ../../tests
    cmake --build .
    ./pairing_crypto_test
    ;;
  *)
    echo "ERROR: PLATFORM unknown: $1"
    exit 1
    ;;
esac
