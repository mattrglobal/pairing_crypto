#!/usr/bin/env bash
# exit if any commands fails
set -e
# print the command
set -x

PROJECT_NAME=pairing-crypto-jni
LIB_NAME=pairing_crypto_jni

PLATFORM=$1
OUTPUT_LOCATION=$2

if [ -z "$PLATFORM" ]
then
  echo "ERROR: PLATFORM argument must be supplied and must be one of the following: WINDOWS, LINUX, MACOS, IOS, ANDROID"
  exit 1
fi

if [ -z "$OUTPUT_LOCATION" ]
then
  echo "ERROR: OUTPUT_LOCATION argument must be supplied and be a valid directory"
  exit 1
fi

echo "Building for PLATFORM: $PLATFORM"
echo "To OUTPUT_LOCATION: $OUTPUT_LOCATION"

# Check for cargo folder
if [ ! -d "${HOME}/.cargo" ]; then
  echo "Installing Rust"

  # install rust
  curl https://sh.rustup.rs -o rustup_init.sh
  sh ./rustup_init.sh --default-toolchain nightly -y
  sh ./rustup_init.sh -y
else
  echo "Previous Rust found"
fi

case $PLATFORM in
  SELF)
      # Create the root directory for the release binaries
      mkdir -p $OUTPUT_LOCATION

      # Current platform build
      cargo build -p $PROJECT_NAME  --target-dir target --release
      cp -r ./target/release $OUTPUT_LOCATION
    ;;
  MACOS)
      # Create the root directory for the MacOS release binaries
      mkdir -p $OUTPUT_LOCATION/macos

      # ARM x86_64 darwin build
      echo "Building for Apple Darwin x86_64"
      rustup target add x86_64-apple-darwin
      mkdir -p $OUTPUT_LOCATION/macos/darwin-x86_64/
      cargo build -p $PROJECT_NAME --target x86_64-apple-darwin --target-dir target --release
      cp ./target/x86_64-apple-darwin/release/lib$LIB_NAME.dylib $OUTPUT_LOCATION/macos/darwin-x86_64/
    ;;
  ANDROID)
      if [ -d "$3" ]
      then
        ANDROID_NDK_HOME=$3
      fi

      if [ ! -d "$ANDROID_NDK_HOME" ]
      then
        ANDROID_NDK_HOME=$NDK_HOME
      fi

      if [ ! -d "$ANDROID_NDK_HOME" ]
      then
        echo "ERROR: ANDROID_NDK_HOME argument must be supplied and be a valid directory pointing to the installation of android ndk"
        exit 1
      fi

      echo "Using NDK home: $ANDROID_NDK_HOME"

      # TODO make this configurable in the environment
      MIN_VERSION=23

      mkdir -p $OUTPUT_LOCATION/android

      # Check for needed cargo utils
      if ! command -v cargo-ndk &>/dev/null; then
           echo "Installing Cargo-NDK"
           cargo install cargo-ndk
      else
           echo "Cargo-NDK found"
      fi

      # Android targets
      rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

      # Build the android aar releases
      cargo ndk --target aarch64-linux-android --platform ${MIN_VERSION} -- build -p $PROJECT_NAME --target-dir target --release
      cargo ndk --target armv7-linux-androideabi --platform ${MIN_VERSION} -- build -p $PROJECT_NAME --target-dir target --release
      cargo ndk --target i686-linux-android --platform ${MIN_VERSION} -- build -p $PROJECT_NAME --target-dir target --release
      cargo ndk --target x86_64-linux-android --platform ${MIN_VERSION} -- build -p $PROJECT_NAME --target-dir target --release

      # Move results into native module directory to be used
      ANDROID_JNI_ROOT=$OUTPUT_LOCATION/android

      rm -rf "${ANDROID_JNI_ROOT}"

      mkdir "${ANDROID_JNI_ROOT}"
      mkdir "${ANDROID_JNI_ROOT}"/arm64-v8a
      mkdir "${ANDROID_JNI_ROOT}"/armeabi-v7a
      mkdir "${ANDROID_JNI_ROOT}"/x86
      mkdir "${ANDROID_JNI_ROOT}"/x86_64

      cp ./target/aarch64-linux-android/release/lib${LIB_NAME}.so "${ANDROID_JNI_ROOT}"/arm64-v8a/lib${LIB_NAME}.so
      cp ./target/armv7-linux-androideabi/release/lib${LIB_NAME}.so "${ANDROID_JNI_ROOT}"/armeabi-v7a/lib${LIB_NAME}.so
      cp ./target/i686-linux-android/release/lib${LIB_NAME}.so "${ANDROID_JNI_ROOT}"/x86/lib${LIB_NAME}.so
      cp ./target/x86_64-linux-android/release/lib${LIB_NAME}.so "${ANDROID_JNI_ROOT}"/x86_64/lib${LIB_NAME}.so
    ;;
  *)
    echo "ERROR: PLATFORM unknown: $PLATFORM"
    exit 1
    ;;
esac
