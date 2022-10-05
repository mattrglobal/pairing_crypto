#!/usr/bin/env bash

# Prerequisite:
#  Install the llvm-tools or llvm-tools-preview component:
#     rustup component add llvm-tools-preview

set -ex

if !(which grcov > /dev/null)
then
  echo "Install grcov before continuing"
  exit 1
fi

export RUSTFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_FILE="code-coverage-%p-%m.profraw"

echo "Removing old coverage profile data..."
rm -f *.profraw

echo "Building..."
cargo build

echo "Testing..."
cargo test

echo "Generating coverage report..."
grcov . -s . --binary-path ./target/debug/ --ignore="tests/*" --ignore="src/tests/*" -t html --branch --ignore-not-existing -o ./target/debug/coverage/

# Clean the profile data
rm -f *.profraw

echo
echo "Report is generated at path (target/debug/coverage/index.html)."

