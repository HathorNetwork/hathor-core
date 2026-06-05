//! Signed token balance type.
//!
//! [`TokenBalance`] is the signed counterpart to [`crate::token_amount::TokenAmount`]:
//! it represents a (possibly negative) delta or net balance held in the V2-normalized unit,
//! while `TokenAmount` represents a versioned non-negative quantity. Conversions exist in
//! both directions; [`TokenBalance::to_amount`] fails on negative values.
//! Multiplication and division are deliberately not implemented.

use crate::token_amount::TokenAmount;
use num_bigint::BigInt;
use std::cmp::Ordering;

/// Signed token balance, stored as a `BigInt` in the V2-normalized unit.
// TODO: In the future we may profile and optimize with a variant for small ints as u64.
#[derive(Debug)]
pub struct TokenBalance(BigInt);

impl TokenBalance {
    /// Wrap a `BigInt` as a balance in the V2-normalized unit.
    pub fn new(balance: BigInt) -> Self {
        Self(balance)
    }

    /// Underlying V2-normalized signed value.
    pub fn raw(&self) -> &BigInt {
        &self.0
    }

    pub fn as_bool(&self) -> bool {
        self.0 != BigInt::ZERO
    }

    /// Convert to a non-negative [`TokenAmount`]; returns `None` when the balance is
    /// negative, since `TokenAmount` cannot represent negative values.
    pub fn to_amount(&self) -> Option<TokenAmount> {
        self.0.to_biguint().map(TokenAmount::from_v2)
    }
}

impl Ord for TokenBalance {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for TokenBalance {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for TokenBalance {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for TokenBalance {}

impl std::ops::Add for &TokenBalance {
    type Output = TokenBalance;

    fn add(self, rhs: Self) -> Self::Output {
        TokenBalance(&self.0 + &rhs.0)
    }
}

impl std::ops::Sub for &TokenBalance {
    type Output = TokenBalance;

    fn sub(self, rhs: Self) -> Self::Output {
        TokenBalance(&self.0 - &rhs.0)
    }
}

impl std::ops::Neg for &TokenBalance {
    type Output = TokenBalance;

    fn neg(self) -> Self::Output {
        TokenBalance(-&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    fn ibig(n: i64) -> BigInt {
        BigInt::from(n)
    }

    fn balance(n: i64) -> TokenBalance {
        TokenBalance::new(ibig(n))
    }

    // ---- as_bool ----

    #[test]
    fn as_bool() {
        assert!(!balance(0).as_bool());
        assert!(balance(1).as_bool());
    }

    // ---- to_amount ----

    #[test]
    fn to_amount_some_for_non_negative() {
        let positive = balance(5).to_amount().unwrap();
        assert!(positive.is_v2());
        assert_eq!(positive.normalized(), &BigUint::from(5u32));

        let zero = balance(0).to_amount().unwrap();
        assert!(zero.is_v2());
        assert_eq!(zero.normalized(), &BigUint::from(0u32));
    }

    #[test]
    fn to_amount_none_for_negative() {
        assert!(balance(-1).to_amount().is_none());
    }

    // ---- Equality and ordering ----

    #[test]
    fn equality() {
        assert_eq!(balance(5), balance(5));
        assert_eq!(balance(-5), balance(-5));
        assert_ne!(balance(5), balance(-5));
        assert_ne!(balance(5), balance(6));
    }

    #[test]
    fn ord() {
        let neg = balance(-5);
        let zero = balance(0);
        let pos = balance(5);

        assert_eq!(neg.cmp(&zero), Ordering::Less);
        assert_eq!(zero.cmp(&pos), Ordering::Less);
        assert_eq!(pos.cmp(&neg), Ordering::Greater);
        assert_eq!(neg.cmp(&neg), Ordering::Equal);
    }

    // ---- Arithmetic ----

    #[test]
    fn add() {
        assert_eq!(&balance(2) + &balance(3), balance(5));
        assert_eq!(&balance(5) + &balance(-3), balance(2));
        assert_eq!(&balance(-2) + &balance(-3), balance(-5));
    }

    #[test]
    fn sub() {
        assert_eq!(&balance(5) - &balance(3), balance(2));
        // Signed: a smaller minuend yields a negative result without panicking.
        assert_eq!(&balance(3) - &balance(5), balance(-2));
    }

    #[test]
    fn neg() {
        assert_eq!(-&balance(5), balance(-5));
        assert_eq!(-&balance(-5), balance(5));
    }
}
