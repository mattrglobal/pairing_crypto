# pairing-crypto library Objective-C FFI Implementation

- This wrapper implementation uses C-FFI implementation available in [c](../c/) directory.
- Before building this for any platform, C-FFI library should be built for that platform. Script [update-libraries.sh](./scripts/update-libraries.sh) can be used to build the library for IOS and MacOS.

## Memory Leak Analysis

To detect memory leaks in this wrapper implementation, **leaks** tool is used from XCode-Build-Tools. **leaks** is invoked on a simple CLI program which is built using directly [wrappers source files](pairing_crypto) along with an end-to-end simple [example](example/main.m).

** This works only on MacOS build machine.

### Steps

1. Build `pairing_crypto` and `pairing_crypto_c` from root of the repository,
```sh
    cargo build
```

2. Run
```bash
    make leaks
```

## Known Build Issues

### xcrun: error: SDK "iphoneos" cannot be located

It might be the case that XCode-Build-Tools are used from some location other than `/Applications/Xcode.app`.

Switch to correct set of tools as below,
```bash
    sudo xcode-select --print-path
    sudo xcode-select --switch /Applications/Xcode.app
```
