//! Conversions between napi's `BigInt` (aliased `NapiBigInt` here, to disambiguate from
//! `num_bigint::BigInt`) and `num-bigint`'s `BigUint` / `BigInt`.
//!
//! napi's `BigInt` stores magnitude as little-endian `u64` limbs in `words` plus a `sign_bit`.
//! `num_bigint::BigUint::to_u64_digits()` yields the same little-endian `u64` limbs, so the
//! magnitude maps across directly.

use napi::bindgen_prelude::BigInt as NapiBigInt;
use num_bigint::{BigInt, BigUint, Sign};

/// Whether the napi `BigInt`'s magnitude is zero, ignoring `sign_bit`.
///
/// napi's `BigInt: PartialEq` also compares `sign_bit`, so `value == NapiBigInt::from(0u64)` would
/// treat a negative-zero (`sign_bit` set, magnitude 0) as non-zero — which we must not do here.
fn napi_magnitude_is_zero(value: &NapiBigInt) -> bool {
    value.words.iter().all(|w| *w == 0)
}

/// `BigUint` -> napi `BigInt` (always non-negative).
pub fn biguint_to_napi(value: &BigUint) -> NapiBigInt {
    NapiBigInt {
        sign_bit: false,
        words: value.to_u64_digits(),
    }
}

/// napi `BigInt` magnitude -> `BigUint`. Ignores `sign_bit`; callers that must reject negatives
/// use [`try_napi_to_biguint`].
pub fn napi_magnitude_to_biguint(value: &NapiBigInt) -> BigUint {
    let digits: Vec<u32> = value
        .words
        .iter()
        .flat_map(|w| [*w as u32, (*w >> 32) as u32])
        .collect();
    BigUint::from_slice(&digits)
}

/// napi `BigInt` -> `BigUint`, rejecting negative inputs with a JS-throwable error.
pub fn try_napi_to_biguint(value: &NapiBigInt) -> napi::Result<BigUint> {
    if value.sign_bit && !napi_magnitude_is_zero(value) {
        return Err(napi::Error::from_reason(
            "expected a non-negative integer".to_owned(),
        ));
    }
    Ok(napi_magnitude_to_biguint(value))
}

/// signed `BigInt` -> napi `BigInt`.
pub fn rsbigint_to_napi(value: &BigInt) -> NapiBigInt {
    let (sign, words) = value.to_u64_digits();
    NapiBigInt {
        sign_bit: sign == Sign::Minus,
        words,
    }
}

/// napi `BigInt` -> signed `BigInt`.
pub fn napi_to_rsbigint(value: &NapiBigInt) -> BigInt {
    // `napi_magnitude_to_biguint` reads only the magnitude (`words`) and ignores `sign_bit`.
    let magnitude = napi_magnitude_to_biguint(value);
    let sign = if napi_magnitude_is_zero(value) {
        Sign::NoSign
    } else if value.sign_bit {
        Sign::Minus
    } else {
        Sign::Plus
    };
    BigInt::from_biguint(sign, magnitude)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn napi(sign_bit: bool, words: Vec<u64>) -> NapiBigInt {
        NapiBigInt { sign_bit, words }
    }

    #[test]
    fn biguint_roundtrips_zero_small_and_large() {
        for v in [
            BigUint::ZERO,
            BigUint::from(42u64),
            // Larger than 2^64 to exercise multi-limb handling.
            BigUint::from(1u64) << 70,
        ] {
            let back = napi_magnitude_to_biguint(&biguint_to_napi(&v));
            assert_eq!(back, v);
        }
    }

    #[test]
    fn rsbigint_roundtrips_negative_zero_and_positive() {
        let large_neg: BigInt = BigInt::from(0i64) - (BigInt::from(1u64) << 80u32);
        for v in [
            BigInt::from(-123456789i64),
            BigInt::ZERO,
            BigInt::from(987654321i64),
            large_neg,
        ] {
            let back = napi_to_rsbigint(&rsbigint_to_napi(&v));
            assert_eq!(back, v);
        }
    }

    #[test]
    fn try_napi_to_biguint_accepts_non_negative() {
        assert_eq!(
            try_napi_to_biguint(&napi(false, vec![5])).unwrap(),
            BigUint::from(5u64)
        );
        // Negative zero (sign_bit set but magnitude zero) is still zero, not an error.
        assert_eq!(
            try_napi_to_biguint(&napi(true, vec![0])).unwrap(),
            BigUint::ZERO
        );
        assert_eq!(
            try_napi_to_biguint(&napi(true, vec![])).unwrap(),
            BigUint::ZERO
        );
    }

    #[test]
    fn try_napi_to_biguint_rejects_negative() {
        let err = try_napi_to_biguint(&napi(true, vec![5])).unwrap_err();
        assert_eq!(err.reason, "expected a non-negative integer");
    }
}
