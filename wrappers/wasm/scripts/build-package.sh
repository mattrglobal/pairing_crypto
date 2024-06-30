#!/usr/bin/env bash

set -e

BUILD_MODE=$1

SRC_WASM=lib/web/index.js

# Add dev dependencies to current path
export PATH="$PATH:node_modules/.bin"

if [ -z "$BUILD_MODE" ]
then
  echo "BUILD_MODE not specified defaulting to RELEASE"
  BUILD_MODE="RELEASE"
fi

# Build based on input parameter
if [ "$BUILD_MODE" = "RELEASE" ]; 
then
    echo "Building WASM Output in RELEASE MODE"
    rustup run stable wasm-pack build --release --out-dir lib/node --out-name index --target nodejs
    rustup run stable wasm-pack build --release --out-dir lib/web --out-name index --target web
elif [ "$BUILD_MODE" = "DEBUG" ]; 
then
    echo "Building WASM Output in DEBUG MODE"
    rustup run stable wasm-pack build --out-dir lib/node --out-name index --target nodejs -- --features="console_error"
    rustup run stable wasm-pack build --out-dir lib/web --out-name index --target web -- --features="console_error"
else
    echo "Unrecognized value for parameter BUILD_MODE value must be either RELEASE or DEBUG"
    exit 1
fi

# Copy over package sources
cp -r src/js/* lib/

# # Delete the un-necessary files automatically created by wasm-pack
rm lib/node/package.json lib/node/.gitignore lib/node/index_bg.wasm.d.ts lib/node/index.d.ts
rm lib/web/package.json lib/web/.gitignore lib/web/index_bg.wasm.d.ts lib/web/index.d.ts

# Delete the un-necessary files automatically created by wasm-pack
rm lib/package.json