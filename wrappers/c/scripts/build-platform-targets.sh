# The following script simplifies the complex process of building
# `pairing_crypto_c` for different targets, instead of dealing in 
# individual rust targets e.g x86_64 the script takes the plaform 
# e.g IOS and takes care of all required targets for the target
# platform

# TODO need to check that rust is installed

set -e

PLATFORM=$1
OUTPUT_LOCATION=$2
OUTPUT_FILE="libpairing_crypto_c"

if [ -z "$PLATFORM" ]
then
  echo "ERROR: PLATFORM argument must be supplied and must be one of the following: MACOS"
  exit 1
fi

if [ -z "$OUTPUT_LOCATION" ]
then
  echo "ERROR: OUTPUT_LOCATION argument must be supplied and be a valid directory"
  exit 1
fi

echo "Building for PLATFORM: $1"
echo "To OUTPUT_LOCATION: $2"

case $PLATFORM in
  IOS)
      # TODO check OS as cannot build for IOS on anything other than mac

      # Create the root directory for the IOS release binaries
      mkdir -p $OUTPUT_LOCATION/ios

      # Create the directories at the output location for the release binaries
      mkdir -p $OUTPUT_LOCATION/ios/x86_64
      mkdir -p $OUTPUT_LOCATION/ios/aarch64
      mkdir -p $OUTPUT_LOCATION/ios/universal

      # Install cargo-lipo
      # see https://github.com/TimNN/cargo-lipo
      cargo install cargo-lipo
      rustup target install x86_64-apple-ios aarch64-apple-ios
      cargo lipo --release
      cp ./target/x86_64-apple-ios/release/$OUTPUT_FILE.a $OUTPUT_LOCATION/ios/x86_64
      cp "./target/aarch64-apple-ios/release/$OUTPUT_FILE.a" $OUTPUT_LOCATION/ios/aarch64
      cp "./target/universal/release/$OUTPUT_FILE.a" $OUTPUT_LOCATION/ios/universal
      break
    ;;
  *)
    echo "ERROR: PLATFORM unknown: $1"
    exit 1
    ;;
esac