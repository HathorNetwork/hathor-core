//! Signed token amount type.
//!
//! [`SignedAmount`] is the signed counterpart to [`crate::unsigned_amount::UnsignedAmount`]:
//! it represents a (possibly negative) delta or net balance held in the V2-normalized unit,
//! while `UnsignedAmount` represents a versioned unsigned quantity. Conversions exist in
//! both directions; [`SignedAmount::to_unsigned`] fails on negative values.
//! Multiplication and division are deliberately not implemented.

use crate::decimal::format_fixed_point;
use crate::unsigned_amount::UnsignedAmount;
use num_bigint::{BigInt, Sign};
use std::cmp::Ordering;

/// Signed token amount, stored as a `BigInt` in the V2-normalized unit.
// TODO: In the future we may profile and optimize with a variant for small ints as u64.
#[derive(Debug)]
pub struct SignedAmount(BigInt);

impl SignedAmount {
    /// Wrap a `BigInt` as a signed amount in the V2-normalized unit.
    pub fn new(amount: BigInt) -> Self {
        Self(amount)
    }

    /// Underlying V2-normalized signed value.
    pub fn raw(&self) -> &BigInt {
        &self.0
    }

    pub fn as_bool(&self) -> bool {
        self.0 != BigInt::ZERO
    }

    /// Convert to an [`UnsignedAmount`]; returns `None` when the signed amount is
    /// negative, since `UnsignedAmount` cannot represent negative values.
    pub fn to_unsigned(&self) -> Option<UnsignedAmount> {
        self.0.to_biguint().map(UnsignedAmount::from_v2)
    }
}

/// Renders the V2-normalized value as a fixed-point decimal with the configured V2 decimal
/// places, prefixing `-` for negative amounts.
impl std::fmt::Display for SignedAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.sign() == Sign::Minus {
            f.write_str("-")?;
        }
        f.write_str(&format_fixed_point(
            self.0.magnitude(),
            UnsignedAmount::v2_decimal_places(),
        ))
    }
}

impl Ord for SignedAmount {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for SignedAmount {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for SignedAmount {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for SignedAmount {}

impl std::ops::Add for &SignedAmount {
    type Output = SignedAmount;

    fn add(self, rhs: Self) -> Self::Output {
        SignedAmount(&self.0 + &rhs.0)
    }
}

impl std::ops::Sub for &SignedAmount {
    type Output = SignedAmount;

    fn sub(self, rhs: Self) -> Self::Output {
        SignedAmount(&self.0 - &rhs.0)
    }
}

impl std::ops::Neg for &SignedAmount {
    type Output = SignedAmount;

    fn neg(self) -> Self::Output {
        SignedAmount(-&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    fn ibig(n: i64) -> BigInt {
        BigInt::from(n)
    }

    fn signed(n: i64) -> SignedAmount {
        SignedAmount::new(ibig(n))
    }

    // ---- as_bool ----

    #[test]
    fn as_bool() {
        assert!(!signed(0).as_bool());
        assert!(signed(1).as_bool());
    }

    // ---- to_unsigned ----

    #[test]
    fn to_unsigned_some_for_non_negative() {
        let positive = signed(5).to_unsigned().unwrap();
        assert!(positive.is_v2());
        assert_eq!(positive.normalized(), &BigUint::from(5u32));

        let zero = signed(0).to_unsigned().unwrap();
        assert!(zero.is_v2());
        assert_eq!(zero.normalized(), &BigUint::from(0u32));
    }

    #[test]
    fn to_unsigned_none_for_negative() {
        assert!(signed(-1).to_unsigned().is_none());
    }

    // ---- Display ----

    // Renders the V2-normalized value with the configured V2 decimal places; negatives carry a
    // leading `-`, zero carries no sign.
    #[test]
    fn display_uses_eighteen_decimal_places_with_sign() {
        UnsignedAmount::set_decimal_places(2, 18);
        assert_eq!(signed(0).to_string(), "0.000000000000000000");
        assert_eq!(signed(5).to_string(), "0.000000000000000005");
        assert_eq!(signed(-5).to_string(), "-0.000000000000000005");
        assert_eq!(
            signed(1_500_000_000_000_000_000).to_string(),
            "1.500000000000000000"
        );
        assert_eq!(
            signed(-1_500_000_000_000_000_000).to_string(),
            "-1.500000000000000000"
        );
    }

    // ---- Equality and ordering ----

    #[test]
    fn equality() {
        assert_eq!(signed(5), signed(5));
        assert_eq!(signed(-5), signed(-5));
        assert_ne!(signed(5), signed(-5));
        assert_ne!(signed(5), signed(6));
    }

    #[test]
    fn ord() {
        let neg = signed(-5);
        let zero = signed(0);
        let pos = signed(5);

        assert_eq!(neg.cmp(&zero), Ordering::Less);
        assert_eq!(zero.cmp(&pos), Ordering::Less);
        assert_eq!(pos.cmp(&neg), Ordering::Greater);
        assert_eq!(neg.cmp(&neg), Ordering::Equal);
    }

    // ---- Arithmetic ----

    #[test]
    fn add() {
        assert_eq!(&signed(2) + &signed(3), signed(5));
        assert_eq!(&signed(5) + &signed(-3), signed(2));
        assert_eq!(&signed(-2) + &signed(-3), signed(-5));
    }

    #[test]
    fn sub() {
        assert_eq!(&signed(5) - &signed(3), signed(2));
        // Signed: a smaller minuend yields a negative result without panicking.
        assert_eq!(&signed(3) - &signed(5), signed(-2));
    }

    #[test]
    fn neg() {
        assert_eq!(-&signed(5), signed(-5));
        assert_eq!(-&signed(-5), signed(5));
    }
}
