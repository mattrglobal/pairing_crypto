#!/usr/bin/env bash

set -e

LIBRARY_FILE="libpairing_crypto_c"

ROOT_DIRECTORY=$(cd "$(dirname "${BASH_SOURCE[0]}")" && cd ../../.. && pwd)

# set the directory for the c wrapper
C_WRAPPER_DIRECTORY="$ROOT_DIRECTORY/wrappers/c"

# set the directory for the obj-c wrapper
OBJC_WRAPPER_DIRECTORY="$ROOT_DIRECTORY/wrappers/obj-c"

# set the output directory
OUTPUT_DIRECTORY="$ROOT_DIRECTORY/wrappers/react-native/ios/lib"

echo "----------------------------------------------"
echo
echo "     C_WRAPPER_DIRECTORY=$C_WRAPPER_DIRECTORY"
echo "  OBJC_WRAPPER_DIRECTORY=$OBJC_WRAPPER_DIRECTORY"
echo "        OUTPUT_DIRECTORY=$OUTPUT_DIRECTORY"
echo
echo "----------------------------------------------"

if [ -d $OUTPUT_DIRECTORY ]; then
    rm -rf $OUTPUT_DIRECTORY/*
fi

mkdir -p $OUTPUT_DIRECTORY

# Build the c wrapper for the IOS platform target
source $C_WRAPPER_DIRECTORY/scripts/build-platform-targets.sh IOS $C_WRAPPER_DIRECTORY/out

# Copy to the external libraries to the subspec folder
cp $C_WRAPPER_DIRECTORY/out/ios/universal/$LIBRARY_FILE.a \
   $OUTPUT_DIRECTORY/$LIBRARY_FILE.a

# Copy to the obj-c wrapper source code to the subspec folder
cp $OBJC_WRAPPER_DIRECTORY/pairing_crypto/* $OUTPUT_DIRECTORY
