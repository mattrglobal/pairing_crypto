# BBS Signatures for Java

This is a Java wrapper for the C callable BBS Signatures package. The library depends on the native platform implementations of the BBS FFI C wrapper.

# Build Rust Library

In order to build rust wrapper for the all available architectures, execute the following command:

```bash
./gradlew buildAndCopyJniLibraries
```

Gradle tasks will execute build scripts for rust compilation and then copy binaries to the specific jniLibs directories for Java wrapper to consume.

In situation when Rust wrapper methods were updated, update Java native methods to match the rust method signatures and generate new headers by running

```bash
cd ./wrappers/java/src/main/java/pairing_crypto
javac -h . Bbs.java
```

Compiler will create `pairing_crypto_Bbs.h` with new JNI Methods matching Rust methods signature.

# Unit testing

```bash
./gradlew test
```