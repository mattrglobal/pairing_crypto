#!/usr/bin/env bash

set -e

LIBRARY_FILE="PairingCryptoJava"

ROOT_DIRECTORY=$(cd "$(dirname "${BASH_SOURCE[0]}")" && cd ../../.. && pwd)

# set the directory for the c wrapper
JAVA_WRAPPER_DIRECTORY="$ROOT_DIRECTORY/wrappers/java"

# set the output directory
OUTPUT_DIRECTORY="$ROOT_DIRECTORY/wrappers/react-native/android/lib"

echo "----------------------------------------------"
echo
echo " JAVA_WRAPPER_DIRECTORY=$JAVA_WRAPPER_DIRECTORY"
echo "       OUTPUT_DIRECTORY=$OUTPUT_DIRECTORY"
echo
echo "----------------------------------------------"

if [ -d $OUTPUT_DIRECTORY ]; then
    rm -rf $OUTPUT_DIRECTORY/*
fi

mkdir -p $OUTPUT_DIRECTORY
mkdir -p $OUTPUT_DIRECTORY/native

# Build the Java wrapper for the IOS platform target
cd $JAVA_WRAPPER_DIRECTORY && ./gradlew clean buildAndCopyJniLibrariesAndroid jar

# Extract artifact version
PROJECT_PROPERTIES=$(./gradlew properties --no-daemon --console=plain -q)
VERSION=$(echo "$PROJECT_PROPERTIES" | grep '^version:' | awk '{printf $2}')
BUILD_DIRECTORY=$(echo "$PROJECT_PROPERTIES" | grep '^buildDir:' | awk '{printf $2}')

# Copy class files to the external libraries folder
cp $JAVA_WRAPPER_DIRECTORY/build/libs/$LIBRARY_FILE-$VERSION.jar \
   $OUTPUT_DIRECTORY/$LIBRARY_FILE.jar

# Copy native libraries to the external libraries folder
cp -r $BUILD_DIRECTORY/native/android/* $OUTPUT_DIRECTORY/native
