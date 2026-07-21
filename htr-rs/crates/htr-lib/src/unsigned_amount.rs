// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

//! Versioned, unsigned token amount type.
//!
//! [`UnsignedAmount`] carries the decimal-places version (V1 or V2) under which the value was
//! encoded on a vertex. Every variant also stores a `normalized` form scaled to the V2 unit,
//! so ordering, equality, and arithmetic can mix V1 and V2 operands without loss of precision.
//! Multiplication and division are deliberately not implemented.

use crate::decimal::{ParseDecimalError, format_decimal, parse_fixed_point};
use crate::signed_amount::SignedAmount;
use num_bigint::{BigUint, ToBigInt};
use std::borrow::Cow;
use std::cmp::Ordering;
use std::sync::OnceLock;

/// Decimal-place configuration, set once at startup via [`UnsignedAmount::set_decimal_places`]
/// before any amount is constructed, rendered, or parsed.
static DECIMAL_CONFIG: OnceLock<DecimalConfig> = OnceLock::new();

/// The V1 and V2 fractional-digit counts and the V1→V2 scaling factor derived from them. The V2
/// count also governs every [`SignedAmount`].
struct DecimalConfig {
    v1_decimal_places: u32,
    v2_decimal_places: u32,
    /// `10^(v2_decimal_places - v1_decimal_places)`.
    normalization_factor: BigUint,
}

/// Token amount version under which a token amount is encoded.
///
/// The discriminant matches the on-wire version byte and is part of the serialization
/// contract: variants are added, never renumbered.
#[derive(FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum TokenAmountVersion {
    V1 = 1,
    V2 = 2,
}

/// Unsigned token amount tagged with its decimal-places version.
///
/// `V1` keeps both the original `raw` value and its V2-scaled `normalized` form so a V1
/// vertex round-trips through this type without loss. `V2` only needs `normalized` because
/// raw and normalized coincide. Ordering, equality, and arithmetic work on `normalized`,
/// so V1 and V2 can be mixed in those operations; arithmetic always returns a V2 result.
// TODO: In the future we may profile and optimize with a variant for small ints as u64.
#[derive(Debug, Clone)]
pub enum UnsignedAmount {
    V1 { raw: BigUint, normalized: BigUint },
    V2 { normalized: BigUint },
}

impl UnsignedAmount {
    pub const ZERO: Self = Self::V2 {
        normalized: BigUint::ZERO,
    };

    /// Set the fractional-digit counts of the V1 and V2 encodings, the source of truth for
    /// rendering, parsing, and the V1-to-V2 normalization factor.
    ///
    /// Must be set before any [`UnsignedAmount`] is constructed, rendered, or parsed. Idempotent:
    /// a repeated call with the same decimal places is a no-op, so independent initializers can
    /// each set it without coordinating. Panics when `v2_decimal_places < v1_decimal_places`, or
    /// when a later call would change the already-set counts.
    pub fn set_decimal_places(v1_decimal_places: u32, v2_decimal_places: u32) {
        assert!(v2_decimal_places >= v1_decimal_places);
        let config = DECIMAL_CONFIG.get_or_init(|| DecimalConfig {
            v1_decimal_places,
            v2_decimal_places,
            normalization_factor: BigUint::from(10u8).pow(v2_decimal_places - v1_decimal_places),
        });
        assert!(
            config.v1_decimal_places == v1_decimal_places
                && config.v2_decimal_places == v2_decimal_places,
            "decimal places already set to different values"
        );
    }

    /// The decimal-place configuration. Panics when not set.
    fn config() -> &'static DecimalConfig {
        DECIMAL_CONFIG.get().expect("decimal places must be set")
    }

    /// Fractional digits in the V1 encoding. Panics when not set.
    pub(crate) fn v1_decimal_places() -> u32 {
        Self::config().v1_decimal_places
    }

    /// Fractional digits in the V2 encoding. Panics when not set.
    pub(crate) fn v2_decimal_places() -> u32 {
        Self::config().v2_decimal_places
    }

    /// The V1-to-V2 scaling factor, `10^(v2_decimal_places - v1_decimal_places)`, derived from the
    /// configured decimal places. Panics when they have not been set.
    pub fn get_normalization_factor() -> &'static BigUint {
        &Self::config().normalization_factor
    }

    /// Build a V1 amount, computing and storing the V2-scaled `normalized` form alongside
    /// the original V1 `raw` value.
    pub fn from_v1(amount: BigUint) -> Self {
        let factor = Self::get_normalization_factor();
        Self::V1 {
            normalized: &amount * factor,
            raw: amount,
        }
    }

    /// Build a V2 amount; raw and normalized coincide.
    pub fn from_v2(amount: BigUint) -> Self {
        Self::V2 { normalized: amount }
    }

    /// Build a [`UnsignedAmount`] from a raw value and a runtime-known version.
    pub fn from_version(amount: BigUint, version: TokenAmountVersion) -> Self {
        match version {
            TokenAmountVersion::V1 => Self::from_v1(amount),
            TokenAmountVersion::V2 => Self::from_v2(amount),
        }
    }

    /// Parse a decimal string into a V2 amount, the inverse of the V2 [`Display`](std::fmt::Display)
    /// form. The string must carry an explicit decimal point with at least one fractional digit,
    /// and no more fractional digits than the V2 unit can hold.
    pub fn parse(s: &str) -> Result<Self, ParseDecimalError> {
        parse_fixed_point(s, Self::v2_decimal_places()).map(Self::from_v2)
    }

    /// Value scaled to the V2 unit, regardless of variant. This is the form used for
    /// ordering, equality, and arithmetic; use [`raw`](Self::raw) when re-emitting a
    /// vertex in its original encoding, for example.
    pub fn normalized(&self) -> &BigUint {
        match self {
            UnsignedAmount::V1 { normalized, .. } => normalized,
            UnsignedAmount::V2 { normalized } => normalized,
        }
    }

    /// Value in the encoding native to its variant — the un-scaled V1 input for `V1`, and
    /// the same as [`normalized`](Self::normalized) for `V2`.
    pub fn raw(&self) -> &BigUint {
        match self {
            UnsignedAmount::V1 { raw, .. } => raw,
            UnsignedAmount::V2 { normalized } => normalized,
        }
    }

    pub fn as_bool(&self) -> bool {
        self.raw() != &BigUint::ZERO
    }

    /// Lift to a [`SignedAmount`] holding the normalized value.
    pub fn to_signed(&self) -> SignedAmount {
        let normalized = self
            .normalized()
            .to_bigint()
            .expect("converting BigUint to BigInt always succeeds");
        SignedAmount::new(normalized)
    }

    /// UnsignedAmount converted to V1, regardless of variant; returns `None` when a V2 value
    /// would truncate, since it's not representable as V1. Mostly just for tests.
    pub fn to_v1(&self) -> Option<Cow<'_, Self>> {
        match self {
            UnsignedAmount::V1 { .. } => Some(Cow::Borrowed(self)),
            UnsignedAmount::V2 { normalized } => {
                let factor = Self::get_normalization_factor();
                if normalized % factor == BigUint::ZERO {
                    Some(Cow::Owned(Self::V1 {
                        raw: normalized / factor,
                        normalized: normalized.clone(),
                    }))
                } else {
                    None
                }
            }
        }
    }

    /// UnsignedAmount converted to V2, regardless of variant. This is infallible.
    pub fn to_v2(&self) -> Cow<'_, Self> {
        match self {
            UnsignedAmount::V1 { normalized, .. } => Cow::Owned(Self::V2 {
                normalized: normalized.clone(),
            }),
            UnsignedAmount::V2 { .. } => Cow::Borrowed(self),
        }
    }

    /// UnsignedAmount converted to a runtime-known version; returns `None` when a V2 value
    /// would truncate, since it's not representable as V1.
    pub fn to_version(&self, version: TokenAmountVersion) -> Option<Cow<'_, Self>> {
        match version {
            TokenAmountVersion::V1 => self.to_v1(),
            TokenAmountVersion::V2 => Some(self.to_v2()),
        }
    }

    pub fn is_v1(&self) -> bool {
        matches!(self, UnsignedAmount::V1 { .. })
    }

    pub fn is_v2(&self) -> bool {
        matches!(self, UnsignedAmount::V2 { .. })
    }
}

/// Renders the value's native encoding as a decimal — the `raw` V1 value at the configured V1
/// decimal places, or the `normalized` V2 value at the V2 decimal places — always keeping the
/// point and at least one fractional digit while dropping any further trailing zeros. So a V2
/// `1_500_000_000_000_000_000` renders as `1.5` and a whole amount as `1.0`.
impl std::fmt::Display for UnsignedAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (magnitude, decimal_places) = match self {
            UnsignedAmount::V1 { raw, .. } => (raw, Self::v1_decimal_places()),
            UnsignedAmount::V2 { normalized } => (normalized, Self::v2_decimal_places()),
        };
        f.write_str(&format_decimal(magnitude, decimal_places))
    }
}

impl Ord for UnsignedAmount {
    fn cmp(&self, other: &Self) -> Ordering {
        self.normalized().cmp(other.normalized())
    }
}

impl PartialOrd for UnsignedAmount {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for UnsignedAmount {
    fn eq(&self, other: &Self) -> bool {
        self.normalized() == other.normalized()
    }
}

impl Eq for UnsignedAmount {}

impl std::ops::Add for &UnsignedAmount {
    type Output = UnsignedAmount;

    fn add(self, rhs: Self) -> Self::Output {
        UnsignedAmount::from_v2(self.normalized() + rhs.normalized())
    }
}

impl std::ops::Sub for &UnsignedAmount {
    type Output = UnsignedAmount;

    fn sub(self, rhs: Self) -> Self::Output {
        UnsignedAmount::from_v2(self.normalized() - rhs.normalized())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;
    use num_traits::{FromPrimitive, ToPrimitive};

    const TEN_TO_THE_SIXTEENTH: u64 = 10u64.pow(16);

    fn init() {
        UnsignedAmount::set_decimal_places(2, 18)
    }

    fn big(n: u64) -> BigUint {
        BigUint::from(n)
    }

    // ---- set_decimal_places ----
    //
    // These tests rely on nextest's process-per-test isolation so the config
    // `OnceLock` is fresh for each one. They deliberately do not call `init()`,
    // since they exercise the setter directly.

    // A second call with different decimal places panics; the counts are fixed once chosen.
    #[test]
    #[should_panic(expected = "decimal places already set to different values")]
    fn set_decimal_places_conflicting_second_call_panics() {
        UnsignedAmount::set_decimal_places(2, 18);
        UnsignedAmount::set_decimal_places(0, 4);
    }

    // A second call with the same decimal places is a no-op, letting independent initializers
    // each set it without coordinating.
    #[test]
    fn set_decimal_places_equal_second_call_is_noop() {
        UnsignedAmount::set_decimal_places(2, 18);
        UnsignedAmount::set_decimal_places(2, 18);
        let amount = UnsignedAmount::from_v1(big(3));
        assert_eq!(amount.raw(), &big(3));
        assert_eq!(amount.normalized(), &big(3 * TEN_TO_THE_SIXTEENTH));
    }

    #[test]
    #[should_panic]
    fn set_decimal_places_panics_when_v2_smaller_than_v1() {
        UnsignedAmount::set_decimal_places(18, 2);
    }

    // Equal decimal places yield a factor of `10^0 = 1`, so a V1 amount and its
    // normalized form coincide — the V2-only arithmetic path is still correct
    // when the two encodings carry identical precision.
    #[test]
    fn set_decimal_places_equal_v1_v2_yields_identity_factor() {
        UnsignedAmount::set_decimal_places(8, 8);
        let amount = UnsignedAmount::from_v1(big(7));
        assert_eq!(amount.raw(), &big(7));
        assert_eq!(amount.normalized(), &big(7));
    }

    // ---- TokenAmountVersion ----

    #[test]
    fn version_from_u8() {
        init();
        assert!(matches!(
            TokenAmountVersion::from_u8(1),
            Some(TokenAmountVersion::V1)
        ));
        assert!(matches!(
            TokenAmountVersion::from_u8(2),
            Some(TokenAmountVersion::V2)
        ));
        assert!(TokenAmountVersion::from_u8(0).is_none());
    }

    // Pins the wire-byte invariant promised by the doc comment: the discriminant
    // equals the on-wire version byte, so a serializer reading `V1.to_u8()` gets `1`.
    #[test]
    fn version_to_u8_matches_discriminant() {
        init();
        assert_eq!(TokenAmountVersion::V1.to_u8(), Some(1));
        assert_eq!(TokenAmountVersion::V2.to_u8(), Some(2));
    }

    // ---- Constructors ----

    #[test]
    fn from_v1_scales_normalized_by_ten_to_the_sixteenth() {
        init();
        let amount = UnsignedAmount::from_v1(big(5));
        assert!(amount.is_v1());
        assert_eq!(amount.raw(), &big(5));
        assert_eq!(amount.normalized(), &big(5 * TEN_TO_THE_SIXTEENTH));
    }

    #[test]
    fn from_v2_raw_equals_normalized() {
        init();
        let amount = UnsignedAmount::from_v2(big(7));
        assert!(amount.is_v2());
        assert_eq!(amount.raw(), &big(7));
        assert_eq!(amount.normalized(), &big(7));
    }

    #[test]
    fn from_version_dispatches_by_version() {
        init();
        let v1 = UnsignedAmount::from_version(big(3), TokenAmountVersion::V1);
        assert!(v1.is_v1());
        assert_eq!(v1.normalized(), &big(3 * TEN_TO_THE_SIXTEENTH));

        let v2 = UnsignedAmount::from_version(big(3), TokenAmountVersion::V2);
        assert!(v2.is_v2());
        assert_eq!(v2.normalized(), &big(3));
    }

    #[test]
    fn zero_is_v2_zero() {
        init();
        assert!(UnsignedAmount::ZERO.is_v2());
        assert_eq!(UnsignedAmount::ZERO.raw(), &big(0));
        assert_eq!(UnsignedAmount::ZERO.normalized(), &big(0));
    }

    // ---- as_bool ----

    #[test]
    fn as_bool() {
        init();
        assert!(!UnsignedAmount::ZERO.as_bool());
        assert!(UnsignedAmount::from_v1(big(1)).as_bool());
        assert!(UnsignedAmount::from_v2(big(1)).as_bool());
    }

    // ---- to_signed ----

    #[test]
    fn to_signed_carries_normalized_value() {
        init();
        let from_v1 = UnsignedAmount::from_v1(big(5)).to_signed();
        assert_eq!(from_v1.raw(), &BigInt::from(5 * TEN_TO_THE_SIXTEENTH));

        let from_v2 = UnsignedAmount::from_v2(big(5)).to_signed();
        assert_eq!(from_v2.raw(), &BigInt::from(5));

        let from_zero = UnsignedAmount::ZERO.to_signed();
        assert_eq!(from_zero.raw(), &BigInt::from(0));
    }

    // ---- Display ----

    // V1 renders its `raw` value at two fractional digits, V2 its `normalized` at eighteen. A
    // fractional amount like `0.05` keeps its digits; a whole amount keeps a single `.0`, and zero
    // renders as `0.0`.
    #[test]
    fn display_v1_trims_trailing_zeros() {
        init();
        assert_eq!(UnsignedAmount::from_v1(big(0)).to_string(), "0.0");
        assert_eq!(UnsignedAmount::from_v1(big(5)).to_string(), "0.05");
        assert_eq!(UnsignedAmount::from_v1(big(100)).to_string(), "1.0");
        assert_eq!(UnsignedAmount::from_v1(big(12345)).to_string(), "123.45");
    }

    #[test]
    fn display_v2_trims_trailing_zeros() {
        init();
        assert_eq!(UnsignedAmount::from_v2(big(0)).to_string(), "0.0");
        assert_eq!(
            UnsignedAmount::from_v2(big(5)).to_string(),
            "0.000000000000000005"
        );
        assert_eq!(
            UnsignedAmount::from_v2(big(1_200_000_000_000_000_000)).to_string(),
            "1.2"
        );
        assert_eq!(
            UnsignedAmount::from_v2(big(10u64.pow(18))).to_string(),
            "1.0"
        );
        assert_eq!(UnsignedAmount::ZERO.to_string(), "0.0");
    }

    // ---- parse ----

    // A decimal string parses into a V2 amount whose normalized value is scaled to eighteen
    // places; the result is always V2 regardless of the input's precision.
    #[test]
    fn parse_creates_v2_amount() {
        init();
        let amount = UnsignedAmount::parse("1.5").unwrap();
        assert!(amount.is_v2());
        assert_eq!(amount.normalized(), &big(1_500_000_000_000_000_000));

        let full_precision = UnsignedAmount::parse("0.000000000000000001").unwrap();
        assert!(full_precision.is_v2());
        assert_eq!(full_precision.normalized(), &big(1));
    }

    // Parsing rejects a fractional part longer than the V2 unit can represent.
    #[test]
    fn parse_rejects_more_than_eighteen_decimal_places() {
        init();
        assert_eq!(
            UnsignedAmount::parse("0.0000000000000000001"),
            Err(ParseDecimalError::TooManyDecimalPlaces { found: 19, max: 18 })
        );
    }

    // Parsing inverts the V2 `Display` form: rendering an amount and parsing it back yields the
    // original value.
    #[test]
    fn parse_inverts_v2_display() {
        init();
        let amount = UnsignedAmount::from_v2(big(1_500_000_000_000_000_000));
        assert_eq!(UnsignedAmount::parse(&amount.to_string()).unwrap(), amount);
    }

    // ---- to_v1 ----

    // V1 input is returned by reference (`Cow::Borrowed`); the conversion does
    // not allocate when the value is already in the V1 encoding.
    #[test]
    fn to_v1_on_v1_borrows_self() {
        init();
        let original = UnsignedAmount::from_v1(big(5));
        let converted = original.to_v1().expect("V1 always converts to V1");
        assert!(matches!(converted, Cow::Borrowed(_)));
        assert!(converted.is_v1());
        assert_eq!(converted.raw(), &big(5));
        assert_eq!(converted.normalized(), &big(5 * TEN_TO_THE_SIXTEENTH));
    }

    // V2 whose normalized value is divisible by the factor round-trips to V1
    // exactly; the resulting V1 carries the divided-down `raw` and the same
    // `normalized`, so equality with the source V2 still holds.
    #[test]
    fn to_v1_on_v2_multiple_of_factor_returns_owned_v1() {
        init();
        let source = UnsignedAmount::from_v2(big(5 * TEN_TO_THE_SIXTEENTH));
        let v1 = source.to_v1().expect("multiple of factor converts");
        assert!(matches!(v1, Cow::Owned(_)));
        assert!(v1.is_v1());
        assert_eq!(v1.raw(), &big(5));
        assert_eq!(v1.normalized(), &big(5 * TEN_TO_THE_SIXTEENTH));
        assert_eq!(*v1, source);
    }

    // A V2 value whose normalized form is not a multiple of the factor cannot
    // be represented as V1 without truncating, so the conversion declines.
    #[test]
    fn to_v1_on_v2_non_multiple_returns_none() {
        init();
        let amount = UnsignedAmount::from_v2(big(5 * TEN_TO_THE_SIXTEENTH + 1));
        assert!(amount.to_v1().is_none());
    }

    // Zero is a multiple of every factor, including the V1↔V2 one, so the
    // canonical zero (a V2) converts to a V1 zero.
    #[test]
    fn to_v1_on_zero_returns_v1_zero() {
        init();
        let zero = UnsignedAmount::ZERO;
        let v1 = zero.to_v1().expect("zero is a multiple of every factor");
        assert!(v1.is_v1());
        assert_eq!(v1.raw(), &big(0));
        assert_eq!(v1.normalized(), &big(0));
    }

    // Round-trip invariant: lowering a V1 to its V2-normalized form and back
    // preserves the original value, including its `raw` component.
    #[test]
    fn to_v1_roundtrips_from_v1_through_v2() {
        init();
        let original = UnsignedAmount::from_v1(big(42));
        let as_v2 = UnsignedAmount::from_v2(original.normalized().clone());
        let back = as_v2
            .to_v1()
            .expect("V1-derived normalized always converts");
        assert_eq!(*back, original);
        assert_eq!(back.raw(), original.raw());
    }

    // ---- to_v2 ----

    // V2 input is returned by reference (`Cow::Borrowed`); the conversion does
    // not allocate when the value is already in the V2 encoding.
    #[test]
    fn to_v2_on_v2_borrows_self() {
        init();
        let original = UnsignedAmount::from_v2(big(7));
        let converted = original.to_v2();
        assert!(matches!(converted, Cow::Borrowed(_)));
        assert!(converted.is_v2());
        assert_eq!(converted.raw(), &big(7));
        assert_eq!(converted.normalized(), &big(7));
    }

    // A V1 lifts to an owned V2 carrying the V1's normalized value; raw and
    // normalized coincide in the result, and equality with the source V1 holds
    // because the normalized form is unchanged by the lift.
    #[test]
    fn to_v2_on_v1_returns_owned_v2() {
        init();
        let source = UnsignedAmount::from_v1(big(5));
        let v2 = source.to_v2();
        assert!(matches!(v2, Cow::Owned(_)));
        assert!(v2.is_v2());
        assert_eq!(v2.raw(), &big(5 * TEN_TO_THE_SIXTEENTH));
        assert_eq!(v2.normalized(), &big(5 * TEN_TO_THE_SIXTEENTH));
        assert_eq!(*v2, source);
    }

    // ---- to_version ----

    // `to_version` routes to `to_v1`/`to_v2` by the runtime version: a V2 that is
    // a multiple of the factor lowers to V1, and any value lifts to V2.
    #[test]
    fn to_version_dispatches_by_version() {
        init();
        let v2_multiple = UnsignedAmount::from_v2(big(5 * TEN_TO_THE_SIXTEENTH));
        let to_v1 = v2_multiple
            .to_version(TokenAmountVersion::V1)
            .expect("multiple of factor converts");
        assert!(to_v1.is_v1());
        assert_eq!(to_v1.raw(), &big(5));

        let v1 = UnsignedAmount::from_v1(big(3));
        let to_v2 = v1
            .to_version(TokenAmountVersion::V2)
            .expect("V2 conversion always succeeds");
        assert!(to_v2.is_v2());
        assert_eq!(to_v2.normalized(), &big(3 * TEN_TO_THE_SIXTEENTH));
    }

    // A V1 target that would truncate yields `None`: `to_v1`'s declination
    // propagates through the version dispatch.
    #[test]
    fn to_version_to_v1_non_multiple_returns_none() {
        init();
        let amount = UnsignedAmount::from_v2(big(5 * TEN_TO_THE_SIXTEENTH + 1));
        assert!(amount.to_version(TokenAmountVersion::V1).is_none());
    }

    // ---- Equality and ordering ----

    #[test]
    fn equality_holds_across_versions_when_normalized_matches() {
        init();
        // V1(5).normalized = 5*10^16, matches V2(5*10^16).
        assert_eq!(
            UnsignedAmount::from_v1(big(5)),
            UnsignedAmount::from_v2(big(5 * TEN_TO_THE_SIXTEENTH))
        );
    }

    #[test]
    fn equality_fails_when_normalized_differs() {
        init();
        // V1(5).normalized = 5*10^16, V2(5).normalized = 5.
        assert_ne!(
            UnsignedAmount::from_v1(big(5)),
            UnsignedAmount::from_v2(big(5))
        );
    }

    #[test]
    fn ord_compares_normalized_across_versions() {
        init();
        let v1 = UnsignedAmount::from_v1(big(5)); // normalized = 5*10^16
        let v2_smaller = UnsignedAmount::from_v2(big(1));
        let v2_equal = UnsignedAmount::from_v2(big(5 * TEN_TO_THE_SIXTEENTH));
        let v2_bigger = UnsignedAmount::from_v2(big(6 * TEN_TO_THE_SIXTEENTH));

        assert_eq!(v1.cmp(&v2_smaller), Ordering::Greater);
        assert_eq!(v1.cmp(&v2_equal), Ordering::Equal);
        assert_eq!(v1.cmp(&v2_bigger), Ordering::Less);
    }

    // ---- Arithmetic ----

    #[test]
    fn add_v1_v1_returns_v2() {
        init();
        let result = &UnsignedAmount::from_v1(big(2)) + &UnsignedAmount::from_v1(big(3));
        assert!(result.is_v2());
        assert_eq!(result.normalized(), &big(5 * TEN_TO_THE_SIXTEENTH));
    }

    #[test]
    fn add_v2_v2() {
        init();
        let result = &UnsignedAmount::from_v2(big(2)) + &UnsignedAmount::from_v2(big(3));
        assert!(result.is_v2());
        assert_eq!(result.normalized(), &big(5));
    }

    // Both operand orderings collapse to a V2 result whose normalized value is the
    // sum of the operands' normalized forms — the result variant does not depend
    // on which side was V1.
    #[test]
    fn add_mixed_versions_returns_v2_in_either_order() {
        init();
        let v1 = UnsignedAmount::from_v1(big(2)); // normalized = 2*10^16
        let v2 = UnsignedAmount::from_v2(big(3 * TEN_TO_THE_SIXTEENTH));
        let expected = big(5 * TEN_TO_THE_SIXTEENTH);

        let v1_plus_v2 = &v1 + &v2;
        assert!(v1_plus_v2.is_v2());
        assert_eq!(v1_plus_v2.normalized(), &expected);

        let v2_plus_v1 = &v2 + &v1;
        assert!(v2_plus_v1.is_v2());
        assert_eq!(v2_plus_v1.normalized(), &expected);
    }

    #[test]
    fn sub_v1_v1_returns_v2() {
        init();
        let result = &UnsignedAmount::from_v1(big(5)) - &UnsignedAmount::from_v1(big(2));
        assert!(result.is_v2());
        assert_eq!(result.normalized(), &big(3 * TEN_TO_THE_SIXTEENTH));
    }

    #[test]
    fn sub_v2_v2() {
        init();
        let result = &UnsignedAmount::from_v2(big(10)) - &UnsignedAmount::from_v2(big(3));
        assert!(result.is_v2());
        assert_eq!(result.normalized(), &big(7));
    }

    #[test]
    fn sub_mixed_versions_returns_v2_in_either_order() {
        init();
        let v1 = UnsignedAmount::from_v1(big(5)); // normalized = 5*10^16
        let v2_small = UnsignedAmount::from_v2(big(2 * TEN_TO_THE_SIXTEENTH));
        let v2_big = UnsignedAmount::from_v2(big(8 * TEN_TO_THE_SIXTEENTH));
        let expected = big(3 * TEN_TO_THE_SIXTEENTH);

        let v1_minus_v2 = &v1 - &v2_small;
        assert!(v1_minus_v2.is_v2());
        assert_eq!(v1_minus_v2.normalized(), &expected);

        let v2_minus_v1 = &v2_big - &v1;
        assert!(v2_minus_v1.is_v2());
        assert_eq!(v2_minus_v1.normalized(), &expected);
    }

    #[test]
    #[should_panic]
    fn sub_underflow_panics() {
        init();
        // BigUint cannot represent negative values, so an underflow on subtraction panics.
        let _ = &UnsignedAmount::from_v2(big(3)) - &UnsignedAmount::from_v2(big(5));
    }
}
