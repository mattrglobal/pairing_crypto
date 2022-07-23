# WASM Wrapper

The following directory contains a WASM based compilation of the "pairing crypto" crate and a javascript API for interfacing in web and Node.js based environments

## Note

If you are developing on macOS, you may need to install [emcc](https://emscripten.org/) and run with the `CC` environment variable set to `emcc` during build (e.g `CC=emcc yarn build`) to avoid a compilation error.