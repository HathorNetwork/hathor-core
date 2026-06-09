//! TokenBalance napi wrapper.

use crate::convert::{napi_to_rsbigint, rsbigint_to_napi};
use crate::token_amount::TokenAmount;
use htr_lib::TokenBalance as InnerTokenBalance;
use napi::bindgen_prelude::{BigInt, Either};
use napi_derive::napi;
use std::cmp::Ordering;

/// JS-facing wrapper around [`htr_lib::TokenBalance`] — a signed value in the
/// V2-normalized unit.
#[napi]
pub struct TokenBalance {
    inner: InnerTokenBalance,
}

impl TokenBalance {
    pub(crate) fn from_inner(inner: InnerTokenBalance) -> Self {
        Self { inner }
    }
}

#[napi]
impl TokenBalance {
    #[napi(constructor)]
    pub fn new(balance: Option<BigInt>) -> Self {
        let value = balance.map(|b| napi_to_rsbigint(&b)).unwrap_or_default();
        Self {
            inner: InnerTokenBalance::new(value),
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

    /// Identity, mirroring `TokenAmount.toBalance`. Returns an equal `TokenBalance`
    /// (value semantics); unlike Python it is not guaranteed to be the same reference.
    #[napi]
    pub fn to_balance(&self) -> TokenBalance {
        TokenBalance::from_inner(InnerTokenBalance::new(self.inner.raw().clone()))
    }

    /// Convert to a [`TokenAmount`]. Returns an error when the balance is negative.
    #[napi]
    pub fn to_amount(&self) -> napi::Result<TokenAmount> {
        self.inner
            .to_amount()
            .map(TokenAmount::from_inner)
            .ok_or_else(|| {
                napi::Error::from_reason(format!(
                    "cannot convert negative TokenBalance to TokenAmount ({:?})",
                    self.inner
                ))
            })
    }

    /// Add another balance or a [`TokenAmount`]. An amount is normalized to the V2
    /// unit (via its `to_balance`) before combining, so a V1 amount lands correctly.
    #[napi(js_name = "add")]
    pub fn op_add(&self, other: Either<&TokenBalance, &TokenAmount>) -> TokenBalance {
        let result = match other {
            Either::A(balance) => &self.inner + &balance.inner,
            Either::B(amount) => &self.inner + &amount.inner().to_balance(),
        };
        TokenBalance::from_inner(result)
    }

    /// Subtract another balance or a [`TokenAmount`]. The result is signed and may be
    /// negative; an amount is normalized to the V2 unit before combining.
    #[napi(js_name = "sub")]
    pub fn op_sub(&self, other: Either<&TokenBalance, &TokenAmount>) -> TokenBalance {
        let result = match other {
            Either::A(balance) => &self.inner - &balance.inner,
            Either::B(amount) => &self.inner - &amount.inner().to_balance(),
        };
        TokenBalance::from_inner(result)
    }

    #[napi(js_name = "neg")]
    pub fn op_neg(&self) -> TokenBalance {
        TokenBalance::from_inner(-&self.inner)
    }

    #[napi(js_name = "eq")]
    pub fn op_eq(&self, other: &TokenBalance) -> bool {
        self.inner == other.inner
    }

    #[napi(js_name = "ne")]
    pub fn op_ne(&self, other: &TokenBalance) -> bool {
        self.inner != other.inner
    }

    #[napi(js_name = "lt")]
    pub fn op_lt(&self, other: &TokenBalance) -> bool {
        self.inner < other.inner
    }

    #[napi(js_name = "le")]
    pub fn op_le(&self, other: &TokenBalance) -> bool {
        self.inner <= other.inner
    }

    #[napi(js_name = "gt")]
    pub fn op_gt(&self, other: &TokenBalance) -> bool {
        self.inner > other.inner
    }

    #[napi(js_name = "ge")]
    pub fn op_ge(&self, other: &TokenBalance) -> bool {
        self.inner >= other.inner
    }

    #[napi]
    pub fn compare(&self, other: &TokenBalance) -> i32 {
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
