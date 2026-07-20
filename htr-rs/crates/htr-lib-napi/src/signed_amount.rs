// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

//! SignedAmount napi wrapper.

use crate::convert::{napi_to_rsbigint, rsbigint_to_napi};
use crate::unsigned_amount::UnsignedAmount;
use htr_lib::SignedAmount as InnerSignedAmount;
use napi::bindgen_prelude::{BigInt, Either};
use napi_derive::napi;
use std::cmp::Ordering;

/// JS-facing wrapper around [`htr_lib::SignedAmount`] — a signed value in the
/// V2-normalized unit.
#[napi]
pub struct SignedAmount {
    inner: InnerSignedAmount,
}

impl SignedAmount {
    pub(crate) fn from_inner(inner: InnerSignedAmount) -> Self {
        Self { inner }
    }
}

// Every method below uses `#[napi(catch_unwind)]` so a Rust panic surfaces as a thrown JS error
// rather than aborting the Node process (matching the PyO3 binding, which catches panics by
// default). This relies on the workspace using `panic = "unwind"` (see the `[profile.*]` blocks in
// the workspace `Cargo.toml`).
#[napi]
impl SignedAmount {
    #[napi(constructor, catch_unwind)]
    pub fn new(amount: Option<BigInt>) -> Self {
        let value = amount.map(|b| napi_to_rsbigint(&b)).unwrap_or_default();
        Self {
            inner: InnerSignedAmount::new(value),
        }
    }

    #[napi(catch_unwind)]
    pub fn raw(&self) -> BigInt {
        rsbigint_to_napi(self.inner.raw())
    }

    #[napi(catch_unwind)]
    pub fn as_bool(&self) -> bool {
        self.inner.as_bool()
    }

    #[napi(catch_unwind)]
    pub fn is_zero(&self) -> bool {
        !self.inner.as_bool()
    }

    /// Identity, mirroring Python's `SignedAmount.to_signed`: returns `self` (the same JS object),
    /// so a value of unknown type (signed or unsigned) can be converted to a signed amount through
    /// a uniform method.
    #[napi(catch_unwind)]
    pub fn to_signed(&self) -> &Self {
        self
    }

    /// Convert to an [`UnsignedAmount`]. Returns an error when the value is negative.
    #[napi(catch_unwind)]
    pub fn to_unsigned(&self) -> napi::Result<UnsignedAmount> {
        self.inner
            .to_unsigned()
            .map(UnsignedAmount::from_inner)
            .ok_or_else(|| {
                napi::Error::from_reason(format!(
                    "cannot convert negative SignedAmount to UnsignedAmount ({:?})",
                    self.inner
                ))
            })
    }

    /// Add another signed amount or an [`UnsignedAmount`]. An unsigned amount is
    /// lifted to the V2-normalized signed unit (via its `to_signed`) before combining.
    #[napi(catch_unwind, js_name = "add", strict)]
    pub fn op_add(&self, other: Either<&SignedAmount, &UnsignedAmount>) -> SignedAmount {
        let result = match other {
            Either::A(signed) => &self.inner + &signed.inner,
            Either::B(amount) => &self.inner + &amount.inner().to_signed(),
        };
        SignedAmount::from_inner(result)
    }

    /// Subtract another signed amount or an [`UnsignedAmount`]. The result is signed
    /// and may be negative; an unsigned amount is lifted to the V2 unit before combining.
    #[napi(catch_unwind, js_name = "sub", strict)]
    pub fn op_sub(&self, other: Either<&SignedAmount, &UnsignedAmount>) -> SignedAmount {
        let result = match other {
            Either::A(signed) => &self.inner - &signed.inner,
            Either::B(amount) => &self.inner - &amount.inner().to_signed(),
        };
        SignedAmount::from_inner(result)
    }

    #[napi(catch_unwind, js_name = "neg")]
    pub fn op_neg(&self) -> SignedAmount {
        SignedAmount::from_inner(-&self.inner)
    }

    /// Identity, mirroring Python's `SignedAmount.__pos__`: returns `self` (the same JS object).
    #[napi(catch_unwind, js_name = "pos")]
    pub fn op_pos(&self) -> &Self {
        self
    }

    #[napi(catch_unwind, js_name = "eq", strict)]
    pub fn op_eq(&self, other: &SignedAmount) -> bool {
        self.inner == other.inner
    }

    #[napi(catch_unwind, js_name = "ne", strict)]
    pub fn op_ne(&self, other: &SignedAmount) -> bool {
        self.inner != other.inner
    }

    #[napi(catch_unwind, js_name = "lt", strict)]
    pub fn op_lt(&self, other: &SignedAmount) -> bool {
        self.inner < other.inner
    }

    #[napi(catch_unwind, js_name = "le", strict)]
    pub fn op_le(&self, other: &SignedAmount) -> bool {
        self.inner <= other.inner
    }

    #[napi(catch_unwind, js_name = "gt", strict)]
    pub fn op_gt(&self, other: &SignedAmount) -> bool {
        self.inner > other.inner
    }

    #[napi(catch_unwind, js_name = "ge", strict)]
    pub fn op_ge(&self, other: &SignedAmount) -> bool {
        self.inner >= other.inner
    }

    #[napi(catch_unwind, strict)]
    pub fn compare(&self, other: &SignedAmount) -> i32 {
        match self.inner.cmp(&other.inner) {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        }
    }

    #[napi(catch_unwind, js_name = "toString")]
    pub fn to_string_js(&self) -> String {
        format!("{:?}", self.inner)
    }
}
