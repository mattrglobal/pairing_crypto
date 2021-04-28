//! # `bls12_381`
//!
//! This module provides an implementation of the BLS12-381 pairing-friendly elliptic
//! curve construction.
//!
//! * **This implementation has not been reviewed or audited. Use at your own risk.**
//! * This implementation targets Rust `1.36` or later.
//! * This implementation does not require the Rust standard library.
//! * All operations are constant time unless explicitly noted.

#![allow(clippy::too_many_arguments)]
#![allow(clippy::many_single_char_names)]
// This lint is described at
// https://rust-lang.github.io/rust-clippy/master/index.html#suspicious_arithmetic_impl
// In our library, some of the arithmetic involving extension fields will necessarily
// involve various binary operators, and so this lint is triggered unnecessarily.
#![allow(clippy::suspicious_arithmetic_impl)]

// The BLS parameter x for BLS12-381 is -0xd201000000010000
const BLS_X: u64 = 0xd201_0000_0001_0000;
const BLS_X_IS_NEGATIVE: bool = true;

#[macro_use]
mod util;

mod fp;
mod fp12;
mod fp2;
mod fp6;
mod g1;
mod g2;
mod hash_to_field;
mod isogeny;
mod pairings;
mod scalar;
mod signum;

pub use g1::{G1Affine, G1Projective};
pub use g2::{G2Affine, G2Projective};
pub use hash_to_field::*;
pub use pairings::{multi_miller_loop, pairing, Bls12, G2Prepared, Gt, MillerLoopResult};
pub use scalar::Scalar;
