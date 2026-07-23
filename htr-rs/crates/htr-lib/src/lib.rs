// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

//! Core Rust implementations for Hathor.
//!
//! This crate holds the pure-Rust domain types — bindings to other languages are
//! provided by wrapper crates.

// Prohibit compilation for non-64-bit targets to ensure consistent use of `usize`.
#[cfg(not(target_pointer_width = "64"))]
compile_error!("compilation is only allowed for 64-bit targets");

#[macro_use]
extern crate num_derive;

mod signed_amount;
mod unsigned_amount;

pub use signed_amount::SignedAmount;
pub use unsigned_amount::{TokenAmountVersion, UnsignedAmount};
