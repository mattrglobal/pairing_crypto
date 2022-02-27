cmake_minimum_required(VERSION 3.10)

project(pairing_crypto_test LANGUAGES C)

add_executable(pairing_crypto_test pairing_crypto_test.c)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY $ENV{RUST_LIBRARY_DIRECTORY})

target_include_directories(pairing_crypto_test PUBLIC "../include")

file(GLOB LIBRARIES "$ENV{RUST_LIBRARY_DIRECTORY}/*.dylib")

target_link_libraries(pairing_crypto_test PUBLIC "${LIBRARIES}")
