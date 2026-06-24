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

#[napi]
impl SignedAmount {
    #[napi(constructor)]
    pub fn new(amount: Option<BigInt>) -> Self {
        let value = amount.map(|b| napi_to_rsbigint(&b)).unwrap_or_default();
        Self {
            inner: InnerSignedAmount::new(value),
        }
    }

    #[napi]
    pub fn raw(&self) -> BigInt {
        rsbigint_to_napi(self.inner.raw())
    }

    #[napi]
    pub fn as_bool(&self) -> bool {
        self.inner.as_bool()
    }

    #[napi]
    pub fn is_zero(&self) -> bool {
        !self.inner.as_bool()
    }

    /// Identity, mirroring Python's `SignedAmount.to_signed`. Returns an equal
    /// `SignedAmount` (value semantics); unlike Python it is not guaranteed to be
    /// the same reference.
    #[napi]
    pub fn to_signed(&self) -> SignedAmount {
        SignedAmount::from_inner(InnerSignedAmount::new(self.inner.raw().clone()))
    }

    /// Convert to an [`UnsignedAmount`]. Returns an error when the value is negative.
    #[napi]
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
    #[napi(js_name = "add")]
    pub fn op_add(&self, other: Either<&SignedAmount, &UnsignedAmount>) -> SignedAmount {
        let result = match other {
            Either::A(signed) => &self.inner + &signed.inner,
            Either::B(amount) => &self.inner + &amount.inner().to_signed(),
        };
        SignedAmount::from_inner(result)
    }

    /// Subtract another signed amount or an [`UnsignedAmount`]. The result is signed
    /// and may be negative; an unsigned amount is lifted to the V2 unit before combining.
    #[napi(js_name = "sub")]
    pub fn op_sub(&self, other: Either<&SignedAmount, &UnsignedAmount>) -> SignedAmount {
        let result = match other {
            Either::A(signed) => &self.inner - &signed.inner,
            Either::B(amount) => &self.inner - &amount.inner().to_signed(),
        };
        SignedAmount::from_inner(result)
    }

    #[napi(js_name = "neg")]
    pub fn op_neg(&self) -> SignedAmount {
        SignedAmount::from_inner(-&self.inner)
    }

    /// Identity, mirroring Python's `SignedAmount.__pos__`. Returns an equal
    /// `SignedAmount` (value semantics); not guaranteed to be the same reference.
    #[napi(js_name = "pos")]
    pub fn op_pos(&self) -> SignedAmount {
        SignedAmount::from_inner(InnerSignedAmount::new(self.inner.raw().clone()))
    }

    #[napi(js_name = "eq")]
    pub fn op_eq(&self, other: &SignedAmount) -> bool {
        self.inner == other.inner
    }

    #[napi(js_name = "ne")]
    pub fn op_ne(&self, other: &SignedAmount) -> bool {
        self.inner != other.inner
    }

    #[napi(js_name = "lt")]
    pub fn op_lt(&self, other: &SignedAmount) -> bool {
        self.inner < other.inner
    }

    #[napi(js_name = "le")]
    pub fn op_le(&self, other: &SignedAmount) -> bool {
        self.inner <= other.inner
    }

    #[napi(js_name = "gt")]
    pub fn op_gt(&self, other: &SignedAmount) -> bool {
        self.inner > other.inner
    }

    #[napi(js_name = "ge")]
    pub fn op_ge(&self, other: &SignedAmount) -> bool {
        self.inner >= other.inner
    }

    #[napi]
    pub fn compare(&self, other: &SignedAmount) -> i32 {
        match self.inner.cmp(&other.inner) {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        }
    }

    #[napi(js_name = "toString")]
    pub fn to_string_js(&self) -> String {
        format!("{:?}", self.inner)
    }
}
