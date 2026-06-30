//! UnsignedAmount napi wrapper and the decimal-places version enum.

use std::cmp::Ordering;

use crate::convert::{biguint_to_napi, try_napi_to_biguint};
use crate::signed_amount::SignedAmount;
use htr_lib::TokenAmountVersion as InnerTokenAmountVersion;
use htr_lib::UnsignedAmount as InnerUnsignedAmount;
use napi::bindgen_prelude::BigInt;
use napi_derive::napi;

/// Decimal-places version under which a token amount is encoded.
///
/// Discriminants match the on-wire version byte and `htr-lib`'s enum.
#[napi]
pub enum TokenAmountVersion {
    V1 = 1,
    V2 = 2,
}

impl TokenAmountVersion {
    /// Convert into the inner `htr-lib` enum, consuming self.
    pub(crate) fn into_inner(self) -> InnerTokenAmountVersion {
        match self {
            TokenAmountVersion::V1 => InnerTokenAmountVersion::V1,
            TokenAmountVersion::V2 => InnerTokenAmountVersion::V2,
        }
    }
}

/// JS-facing wrapper around [`htr_lib::UnsignedAmount`] — a versioned, non-negative amount.
#[napi]
pub struct UnsignedAmount {
    inner: InnerUnsignedAmount,
}

impl UnsignedAmount {
    pub(crate) fn from_inner(inner: InnerUnsignedAmount) -> Self {
        Self { inner }
    }

    /// Borrow the wrapped `htr-lib` value, so sibling wrappers (e.g. `SignedAmount`)
    /// can combine with it across the module boundary.
    pub(crate) fn inner(&self) -> &InnerUnsignedAmount {
        &self.inner
    }
}

#[napi]
impl UnsignedAmount {
    /// Set the global V1->V2 normalization factor. Panics (-> thrown error) on a
    /// conflicting re-set or when `v2_decimal_places < v1_decimal_places`.
    #[napi(catch_unwind)]
    pub fn set_normalization_factor(v1_decimal_places: u32, v2_decimal_places: u32) {
        InnerUnsignedAmount::set_normalization_factor(v1_decimal_places, v2_decimal_places);
    }

    /// Get the global normalization factor. Panics (-> thrown error) if it was never set.
    #[napi(catch_unwind)]
    pub fn get_normalization_factor() -> BigInt {
        biguint_to_napi(InnerUnsignedAmount::get_normalization_factor())
    }

    /// Build a V1 amount from a raw value. `catch_unwind` because reading the global
    /// normalization factor panics in `htr-lib` when it was never set — surface a thrown
    /// JS error rather than aborting Node.
    #[napi(catch_unwind)]
    pub fn from_v1(amount: BigInt) -> napi::Result<UnsignedAmount> {
        Ok(UnsignedAmount::from_inner(InnerUnsignedAmount::from_v1(
            try_napi_to_biguint(&amount)?,
        )))
    }

    /// Build a V2 amount; raw and normalized coincide. No `catch_unwind`: unlike `from_v1`, this
    /// never reads the normalization factor, so it cannot panic.
    #[napi]
    pub fn from_v2(amount: BigInt) -> napi::Result<UnsignedAmount> {
        Ok(UnsignedAmount::from_inner(InnerUnsignedAmount::from_v2(
            try_napi_to_biguint(&amount)?,
        )))
    }

    /// Build an amount under a runtime-known version. `catch_unwind` because the V1 path reads
    /// the normalization factor, which panics in `htr-lib` when it was never set.
    #[napi(catch_unwind)]
    pub fn from_version(
        amount: BigInt,
        version: TokenAmountVersion,
    ) -> napi::Result<UnsignedAmount> {
        Ok(UnsignedAmount::from_inner(
            InnerUnsignedAmount::from_version(try_napi_to_biguint(&amount)?, version.into_inner()),
        ))
    }

    #[napi]
    pub fn zero() -> UnsignedAmount {
        UnsignedAmount::from_inner(InnerUnsignedAmount::ZERO)
    }

    #[napi]
    pub fn is_v1(&self) -> bool {
        self.inner.is_v1()
    }

    #[napi]
    pub fn is_v2(&self) -> bool {
        self.inner.is_v2()
    }

    #[napi]
    pub fn normalized(&self) -> BigInt {
        biguint_to_napi(self.inner.normalized())
    }

    #[napi]
    pub fn raw(&self) -> BigInt {
        biguint_to_napi(self.inner.raw())
    }

    #[napi]
    pub fn as_bool(&self) -> bool {
        self.inner.as_bool()
    }

    #[napi]
    pub fn is_zero(&self) -> bool {
        !self.inner.as_bool()
    }

    #[napi]
    pub fn to_signed(&self) -> SignedAmount {
        SignedAmount::from_inner(self.inner.to_signed())
    }

    /// Convert to V1. `catch_unwind` because a V2 input reads the normalization factor, which
    /// panics in `htr-lib` when it was never set (a thrown JS error, not a Node abort).
    #[napi(catch_unwind)]
    pub fn to_v1(&self) -> napi::Result<UnsignedAmount> {
        self.inner
            .to_v1()
            .map(|cow| UnsignedAmount::from_inner(cow.into_owned()))
            .ok_or_else(|| {
                napi::Error::from_reason(format!(
                    "cannot denormalize value, would truncate ({:?})",
                    self.inner
                ))
            })
    }

    /// Convert to V1, or `null` when the value would truncate. `catch_unwind` because a V2 input
    /// reads the normalization factor, which panics in `htr-lib` when it was never set — an unset
    /// factor is a programming error and must throw, not return `null`.
    #[napi(catch_unwind)]
    pub fn maybe_to_v1(&self) -> Option<UnsignedAmount> {
        self.inner
            .to_v1()
            .map(|cow| UnsignedAmount::from_inner(cow.into_owned()))
    }

    #[napi]
    pub fn to_v2(&self) -> UnsignedAmount {
        UnsignedAmount::from_inner(self.inner.to_v2().into_owned())
    }

    /// Convert to a runtime-known version. `catch_unwind` because the V1 target reads the
    /// normalization factor, which panics in `htr-lib` when it was never set.
    #[napi(catch_unwind)]
    pub fn to_version(&self, version: TokenAmountVersion) -> napi::Result<UnsignedAmount> {
        self.inner
            .to_version(version.into_inner())
            .map(|cow| UnsignedAmount::from_inner(cow.into_owned()))
            .ok_or_else(|| {
                napi::Error::from_reason(format!(
                    "cannot denormalize value, would truncate ({:?})",
                    self.inner
                ))
            })
    }

    #[napi(js_name = "add", strict)]
    pub fn op_add(&self, other: &UnsignedAmount) -> UnsignedAmount {
        UnsignedAmount::from_inner(&self.inner + &other.inner)
    }

    /// Subtraction. Underflow panics in `htr-lib` (the amount is unsigned);
    /// `catch_unwind` turns that into a thrown JS error rather than aborting Node.
    #[napi(catch_unwind, js_name = "sub", strict)]
    pub fn op_sub(&self, other: &UnsignedAmount) -> UnsignedAmount {
        UnsignedAmount::from_inner(&self.inner - &other.inner)
    }

    #[napi(js_name = "eq", strict)]
    pub fn op_eq(&self, other: &UnsignedAmount) -> bool {
        self.inner == other.inner
    }

    #[napi(js_name = "ne", strict)]
    pub fn op_ne(&self, other: &UnsignedAmount) -> bool {
        self.inner != other.inner
    }

    #[napi(js_name = "lt", strict)]
    pub fn op_lt(&self, other: &UnsignedAmount) -> bool {
        self.inner < other.inner
    }

    #[napi(js_name = "le", strict)]
    pub fn op_le(&self, other: &UnsignedAmount) -> bool {
        self.inner <= other.inner
    }

    #[napi(js_name = "gt", strict)]
    pub fn op_gt(&self, other: &UnsignedAmount) -> bool {
        self.inner > other.inner
    }

    #[napi(js_name = "ge", strict)]
    pub fn op_ge(&self, other: &UnsignedAmount) -> bool {
        self.inner >= other.inner
    }

    #[napi(strict)]
    pub fn compare(&self, other: &UnsignedAmount) -> i32 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::ToPrimitive;

    #[test]
    fn to_inner_maps_each_variant() {
        // The inner enum is ToPrimitive; pin the wire byte to prove the mapping.
        assert_eq!(TokenAmountVersion::V1.into_inner().to_u8(), Some(1));
        assert_eq!(TokenAmountVersion::V2.into_inner().to_u8(), Some(2));
    }
}
