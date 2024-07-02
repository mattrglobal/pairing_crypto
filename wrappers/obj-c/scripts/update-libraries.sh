#!/usr/bin/env bash

set -e

LIBRARY_FILE="libpairing_crypto_c"

# set the script directory
CURRENT_SCRIPT_DIRECTORY="$(dirname -- "${BASH_SOURCE}")"

# set the directory for the c wrapper
C_WRAPPER_DIRECTORY="$CURRENT_SCRIPT_DIRECTORY/../../c"

echo "----------------------------------------------"
echo
echo "CURRENT_SCRIPT_DIRECTORY=$CURRENT_SCRIPT_DIRECTORY"
echo "     C_WRAPPER_DIRECTORY=$C_WRAPPER_DIRECTORY"
echo
echo "----------------------------------------------"

# Build the c wrapper for the IOS platform target
source $C_WRAPPER_DIRECTORY/scripts/build-platform-targets.sh IOS $C_WRAPPER_DIRECTORY/out

# Copy to the external libraries folder specified in podspec
mkdir -p "$CURRENT_SCRIPT_DIRECTORY/../libraries"
# mkdir -p "$CURRENT_SCRIPT_DIRECTORY/../libraries/sim"
# cp "$C_WRAPPER_DIRECTORY/out/ios/aarch64-sim/$LIBRARY_FILE.a" \
#   "$CURRENT_SCRIPT_DIRECTORY/../libraries/sim/$LIBRARY_FILE.a"
# cp "$C_WRAPPER_DIRECTORY/out/ios/universal/$LIBRARY_FILE.a" \
#   "$CURRENT_SCRIPT_DIRECTORY/../libraries/$LIBRARY_FILE.a"

rm -r $CURRENT_SCRIPT_DIRECTORY/../libraries/*
xcodebuild -create-xcframework -library $C_WRAPPER_DIRECTORY/out/ios/universal-sim/$LIBRARY_FILE.a -library $C_WRAPPER_DIRECTORY/out/ios/aarch64/$LIBRARY_FILE.a -output $CURRENT_SCRIPT_DIRECTORY/../libraries/$LIBRARY_FILE.xcframework 
