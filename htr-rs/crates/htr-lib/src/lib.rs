//! Core Rust implementations for Hathor.
//!
//! This crate holds the pure-Rust domain types — bindings to other languages are
//! provided by wrapper crates.

// Prohibit compilation for non-64-bit targets to ensure consistent use of `usize`.
#[cfg(not(target_pointer_width = "64"))]
compile_error!("compilation is only allowed for 64-bit targets");

#[macro_use]
extern crate num_derive;

mod token_amount;
mod token_balance;

pub use token_amount::{TokenAmount, TokenAmountVersion};
pub use token_balance::TokenBalance;
