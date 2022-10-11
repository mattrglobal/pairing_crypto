#!/usr/bin/env bash
# exit if any commands fails
set -e

LIBRARY_FILE="libpairing_crypto_c"

# set the script directory
CURRENT_SCRIPT_DIRECTORY="$(dirname -- "${BASH_SOURCE}")"

echo $CURRENT_SCRIPT_DIRECTORY

# set the directory for the c wrapper
C_WRAPPER_DIRECTORY="$CURRENT_SCRIPT_DIRECTORY/../../c"

# Build the c wrapper for the IOS platform target
source $C_WRAPPER_DIRECTORY/scripts/build-platform-targets.sh IOS $C_WRAPPER_DIRECTORY/out

# source $C_WRAPPER_DIRECTORY/scripts/build-platform-targets.sh MACOS $C_WRAPPER_DIRECTORY/out

echo $CURRENT_SCRIPT_DIRECTORY

# Copy to the external libraries folder specified in podspec
cp "$C_WRAPPER_DIRECTORY/out/ios/universal/$LIBRARY_FILE.a" "$CURRENT_SCRIPT_DIRECTORY/../libraries/$LIBRARY_FILE.a"
