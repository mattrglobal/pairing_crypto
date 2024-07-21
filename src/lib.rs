// Copyright 2020
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ------------------------------------------------------------------------------
//! This library is a simple and easy to use one stop shop
//! for some of the [pairing-based cryptography](https://en.wikipedia.org/wiki/Pairing-based_cryptography) primitives
//! written in [Rust](rust-lang.org).
//!
//! This example shows a quick way to get started with BBS Signature from
//! Pairing Crypto Library.
//!
//! ```toml
//! [dependencies]
//! pairing_crypto = { version = "0.2.0", default-features = false }
//! ```
//!
//! ```rust
#![doc = include_str!("../examples/bbs_simple.rs")]
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rustdoc::missing_crate_level_docs, rust_2018_idioms)]
#![deny(dead_code, redundant_semicolons, unused, unsafe_code, while_true)]

#[cfg(feature = "alloc")]
extern crate alloc;

/// Error types
mod error;

/// Common types and utilities
pub mod common;

// Supported Curves
mod curves;

/// Supported schemes from pairing crypto
mod schemes;

pub use error::Error;

/// Supported constructs for the BLS12-381 curve.
pub use schemes::*;

// Unit test cases
#[cfg(test)]
mod tests;
