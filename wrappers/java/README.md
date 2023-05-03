# Java Wrapper

The following directory contains an FFI based compilation of the "pairing crypto" crate for usage in the java ecosystem.

# Build

In order to build for the all available architectures, execute the following command:

```bash
./gradlew buildAndCopyJniLibraries
```

Gradle tasks will execute build scripts for rust compilation and then copy binaries to the specific jniLibs directories for Java wrapper to consume.

In situation when wrapper methods were updated, update Java native methods to match the rust method signatures and generate new headers by running

```bash
cd ./wrappers/java/src/main/java/pairing_crypto
javac -h . Bbs.java
```

Compiler will create `pairing_crypto_Bbs.h` with new JNI Methods matching Rust methods signature.

# Unit testing

```bash
./gradlew test
```

Test with output garbage collection info, useful in detecting memory leaks,

```bash
./gradlew test -Dorg.gradle.jvmargs=-Xlog:gc+heap=trace:stderr
```
