/*
 * Copyright 2020
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ------------------------------------------------------------------------------
 */
//!
//!
//!
//!
#![warn(missing_docs, rustdoc::missing_crate_level_docs, rust_2018_idioms)]
#![deny(dead_code, redundant_semicolons, unused, unsafe_code, while_true)]

/// Error types
mod error;

/// Common types and utilities
mod common;

/// Supported Curves
mod curves;

/// Supported schemes from pairing crypto
mod schemes;

/// Supported constructs for the BLS12-381 curve
pub mod bls12_381 {
    pub use super::schemes::bbs;
}

/// A testable RNG
#[cfg(any(test, feature = "test"))]
pub struct MockRng(rand_xorshift::XorShiftRng);

#[cfg(any(test, feature = "test"))]
impl rand_core::SeedableRng for MockRng {
    type Seed = [u8; 16];

    fn from_seed(seed: Self::Seed) -> Self {
        Self(rand_xorshift::XorShiftRng::from_seed(seed))
    }
}

#[cfg(any(test, feature = "test"))]
impl rand_core::CryptoRng for MockRng {}

#[cfg(any(test, feature = "test"))]
impl rand_core::RngCore for MockRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}
