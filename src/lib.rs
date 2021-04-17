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
#![warn(missing_docs, missing_crate_level_docs, rust_2018_idioms)]
#![deny(dead_code, redundant_semicolons, unused, unsafe_code, while_true)]

#[macro_use]
mod core;
mod bbs_plus;
mod ps;

/// Supported constructs for the BLS12-381 curve
pub mod bls12_381 {
    pub use super::core::{
        Challenge, Commitment, Error, HiddenMessage, Message, Nonce, ProofMessage,
        SignatureBlinding, COMMITMENT_G1_BYTES, COMMITMENT_G2_BYTES, FIELD_BYTES,
    };
    pub use signature_bls::*;
    /// BBS+ signature module
    pub mod bbs {
        pub use crate::bbs_plus::*;
    }
    /// Pointcheval Saunders signature module
    pub mod ps {
        pub use crate::ps::*;
    }
}

#[cfg(test)]
pub struct MockRng(rand_xorshift::XorShiftRng);

#[cfg(test)]
impl rand_core::SeedableRng for MockRng {
    type Seed = [u8; 16];

    fn from_seed(seed: Self::Seed) -> Self {
        Self(rand_xorshift::XorShiftRng::from_seed(seed))
    }
}

#[cfg(test)]
impl rand_core::CryptoRng for MockRng {}

#[cfg(test)]
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

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}
