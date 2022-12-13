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
//!
#![warn(missing_docs, missing_crate_level_docs, rust_2018_idioms)]
#![deny(dead_code, redundant_semicolons, unused, while_true)]

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc<'_> = wee_alloc::WeeAlloc::INIT;

#[macro_use]
mod macros;

mod utils;

mod bbs;
mod bbs_bound;

/// Exposed prelude when using wasm
pub mod prelude {
    pub use crate::{bbs::api::*, bbs_bound::api::*};
}
