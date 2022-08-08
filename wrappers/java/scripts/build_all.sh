
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
  WINDOWS)
      rustup target install i686-pc-windows-gnu x86_64-pc-windows-gnu
      mkdir -p $OUTPUT_LOCATION\\windows
      cargo build -p $PROJECT_NAME --target-dir target --release
      cp \\target\\release\\$LIB_NAME.dll $OUTPUT_LOCATION\\windows
    ;;
  LINUX)
      mkdir -p $OUTPUT_LOCATION/linux
      cargo build -p $PROJECT_NAME  --target-dir target --release
      cp ./target/release/lib$LIB_NAME.so $OUTPUT_LOCATION/linux
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
  IOS)
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
      cargo lipo -p $PROJECT_NAME --release
      cp "./target/x86_64-apple-ios/release/lib$LIB_NAME.a" $OUTPUT_LOCATION/ios/x86_64
      cp "./target/aarch64-apple-ios/release/lib$LIB_NAME.a" $OUTPUT_LOCATION/ios/aarch64
      cp "./target/universal/release/lib$LIB_NAME.a" $OUTPUT_LOCATION/ios/universal
      break
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
        cargo ndk --target aarch64-linux-android --android-platform ${MIN_VERSION} -- build --target-dir target --release
        cargo ndk --target armv7-linux-androideabi --android-platform ${MIN_VERSION} -- build --target-dir target --release
        cargo ndk --target i686-linux-android --android-platform ${MIN_VERSION} -- build --target-dir target --release
        cargo ndk --target x86_64-linux-android --android-platform ${MIN_VERSION} -- build --target-dir target --release

        # Move results into native module directory to be used
        ANDROID_JNI_ROOT=$OUTPUT_LOCATION/android

        rm -rf "${ANDROID_JNI_ROOT}"

        mkdir "${ANDROID_JNI_ROOT}"
        mkdir "${ANDROID_JNI_ROOT}"/arm64-v8a
        mkdir "${ANDROID_JNI_ROOT}"/armeabi-v7a
        mkdir "${ANDROID_JNI_ROOT}"/x86
        mkdir "${ANDROID_JNI_ROOT}"/x86_64

        cp ./target/aarch64-linux-android/release/${LIB_NAME} "${ANDROID_JNI_ROOT}"/arm64-v8a/${LIB_NAME}
        cp ./target/armv7-linux-androideabi/release/${LIB_NAME} "${ANDROID_JNI_ROOT}"/armeabi-v7a/${LIB_NAME}
        cp ./target/i686-linux-android/release/${LIB_NAME} "${ANDROID_JNI_ROOT}"/x86/${LIB_NAME}
        cp ./target/x86_64-linux-android/release/${LIB_NAME} "${ANDROID_JNI_ROOT}"/x86_64/${LIB_NAME}
      ;;
  *)
    echo "ERROR: PLATFORM unknown: $PLATFORM"
    exit 1
    ;;
esac
