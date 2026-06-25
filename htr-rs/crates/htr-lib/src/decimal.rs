//! Decimal rendering and parsing for token amounts.
//!
//! Token amounts are stored as integers; the human-facing form places a decimal point a fixed
//! number of digits from the right — the count depending on the amount's version. The point and
//! at least one fractional digit are always present (so a whole amount reads as `1.0`, not `1`),
//! with any further trailing zeros dropped.

use num_bigint::BigUint;
use std::fmt;

/// Render `magnitude`, read as a fixed-point integer with `decimal_places` fractional digits, as a
/// decimal string. The point and at least one fractional digit are always kept, with any further
/// trailing zeros dropped. So `1_200_000_000_000_000_000` at eighteen places renders as `1.2`, a
/// whole amount as `1.0`, and zero as `0.0`.
pub(crate) fn format_decimal(magnitude: &BigUint, decimal_places: u32) -> String {
    let decimal_places = decimal_places as usize;
    let mut digits = magnitude.to_string();
    if digits.len() <= decimal_places {
        digits.insert_str(0, &"0".repeat(decimal_places + 1 - digits.len()));
    }
    let (integer, fraction) = digits.split_at(digits.len() - decimal_places);
    let fraction = fraction.trim_end_matches('0');
    let fraction = if fraction.is_empty() { "0" } else { fraction };
    format!("{integer}.{fraction}")
}

/// Why a decimal string could not be parsed into a fixed-point integer.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseDecimalError {
    /// The string had no decimal point. An amount must be written with an explicit point and at
    /// least one fractional digit (e.g. `1.0`, not `1`).
    MissingDecimalPoint,
    /// A decimal point had no digit on one side (e.g. `.`, `1.`, `.5`).
    MissingDigits,
    /// The string held a character other than a digit or a `.`.
    InvalidCharacter,
    /// The string held more than one decimal point.
    MultipleDecimalPoints,
    /// The fractional part had more digits than the target precision can represent.
    TooManyDecimalPlaces { found: usize, max: u32 },
}

impl fmt::Display for ParseDecimalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseDecimalError::MissingDecimalPoint => {
                f.write_str("decimal string is missing the decimal point")
            }
            ParseDecimalError::MissingDigits => {
                f.write_str("decimal string is missing required digits")
            }
            ParseDecimalError::InvalidCharacter => {
                f.write_str("decimal string contains a non-digit character")
            }
            ParseDecimalError::MultipleDecimalPoints => {
                f.write_str("decimal string contains more than one decimal point")
            }
            ParseDecimalError::TooManyDecimalPlaces { found, max } => {
                write!(f, "too many decimal places: {found} (at most {max})")
            }
        }
    }
}

impl std::error::Error for ParseDecimalError {}

/// Parse a decimal string into the integer it denotes scaled by `10^decimal_places`, the inverse
/// of [`format_decimal`]. Requires an integer and a fractional part separated by a single `.`,
/// with at least one digit on each side; the fractional part may carry at most `decimal_places`
/// digits. A bare integer with no point is rejected.
pub(crate) fn parse_fixed_point(
    input: &str,
    decimal_places: u32,
) -> Result<BigUint, ParseDecimalError> {
    let is_digit_or_point = |byte: u8| byte.is_ascii_digit() || byte == b'.';
    if !input.bytes().all(is_digit_or_point) {
        return Err(ParseDecimalError::InvalidCharacter);
    }
    let Some((integer_part, fractional_part)) = input.split_once('.') else {
        return Err(ParseDecimalError::MissingDecimalPoint);
    };
    if fractional_part.contains('.') {
        return Err(ParseDecimalError::MultipleDecimalPoints);
    }
    if integer_part.is_empty() || fractional_part.is_empty() {
        return Err(ParseDecimalError::MissingDigits);
    }
    if fractional_part.len() > decimal_places as usize {
        return Err(ParseDecimalError::TooManyDecimalPlaces {
            found: fractional_part.len(),
            max: decimal_places,
        });
    }

    let trailing_zeros = decimal_places as usize - fractional_part.len();
    let mut digits = String::with_capacity(integer_part.len() + decimal_places as usize);
    digits.push_str(integer_part);
    digits.push_str(fractional_part);
    digits.push_str(&"0".repeat(trailing_zeros));
    Ok(digits
        .parse()
        .expect("validated non-empty digit string parses as BigUint"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn big(n: u64) -> BigUint {
        BigUint::from(n)
    }

    // The point and one fractional digit are always present; any further trailing zeros are
    // dropped. A whole amount keeps a single `.0` and zero renders as `0.0`.
    #[test]
    fn format_decimal_keeps_at_least_one_fractional_digit() {
        assert_eq!(format_decimal(&big(0), 18), "0.0");
        assert_eq!(format_decimal(&big(5), 18), "0.000000000000000005");
        assert_eq!(format_decimal(&big(1_200_000_000_000_000_000), 18), "1.2");
        assert_eq!(format_decimal(&big(1_500_000_000_000_000_000), 18), "1.5");
        assert_eq!(format_decimal(&big(10u64.pow(18)), 18), "1.0");
        assert_eq!(format_decimal(&big(0), 2), "0.0");
        assert_eq!(format_decimal(&big(5), 2), "0.05");
        assert_eq!(format_decimal(&big(45), 2), "0.45");
        assert_eq!(format_decimal(&big(100), 2), "1.0");
        assert_eq!(format_decimal(&big(12345), 2), "123.45");
        assert_eq!(format_decimal(&big(0), 0), "0.0");
        assert_eq!(format_decimal(&big(123), 0), "123.0");
    }

    #[test]
    fn parse_integer_and_fraction() {
        assert_eq!(parse_fixed_point("0.0", 18).unwrap(), big(0));
        assert_eq!(parse_fixed_point("1.0", 18).unwrap(), big(10u64.pow(18)));
        assert_eq!(
            parse_fixed_point("1.5", 18).unwrap(),
            big(1_500_000_000_000_000_000)
        );
        assert_eq!(
            parse_fixed_point("0.000000000000000001", 18).unwrap(),
            big(1)
        );
        assert_eq!(
            parse_fixed_point("1.000000000000000000", 18).unwrap(),
            big(10u64.pow(18))
        );
    }

    // A bare integer with no decimal point is rejected; every amount must carry an explicit point
    // and at least one fractional digit.
    #[test]
    fn parse_rejects_missing_decimal_point() {
        assert_eq!(
            parse_fixed_point("0", 18),
            Err(ParseDecimalError::MissingDecimalPoint)
        );
        assert_eq!(
            parse_fixed_point("5", 18),
            Err(ParseDecimalError::MissingDecimalPoint)
        );
        assert_eq!(
            parse_fixed_point("", 18),
            Err(ParseDecimalError::MissingDecimalPoint)
        );
    }

    // A decimal point requires digits on both sides: a leading or trailing point is rejected.
    #[test]
    fn parse_rejects_empty_side() {
        assert_eq!(
            parse_fixed_point(".5", 18),
            Err(ParseDecimalError::MissingDigits)
        );
        assert_eq!(
            parse_fixed_point("1.", 18),
            Err(ParseDecimalError::MissingDigits)
        );
    }

    // The fractional part is bounded by the target precision: eighteen digits parse, nineteen
    // do not, and the error reports both the count found and the limit.
    #[test]
    fn parse_rejects_excess_decimal_places() {
        assert_eq!(
            parse_fixed_point("0.0000000000000000001", 18),
            Err(ParseDecimalError::TooManyDecimalPlaces { found: 19, max: 18 })
        );
    }

    #[test]
    fn parse_rejects_malformed_input() {
        assert_eq!(
            parse_fixed_point(".", 18),
            Err(ParseDecimalError::MissingDigits)
        );
        assert_eq!(
            parse_fixed_point("-1", 18),
            Err(ParseDecimalError::InvalidCharacter)
        );
        assert_eq!(
            parse_fixed_point("1 000", 18),
            Err(ParseDecimalError::InvalidCharacter)
        );
        assert_eq!(
            parse_fixed_point("abc", 18),
            Err(ParseDecimalError::InvalidCharacter)
        );
        assert_eq!(
            parse_fixed_point("1.2.3", 18),
            Err(ParseDecimalError::MultipleDecimalPoints)
        );
    }

    // Round-trips the rendering: a value formatted at a given precision parses back to itself,
    // even after trailing zeros are trimmed — including a whole amount, which renders as `N.0`.
    #[test]
    fn parse_inverts_format() {
        for value in [big(1_500_000_000_000_000_000), big(10u64.pow(18)), big(0)] {
            let rendered = format_decimal(&value, 18);
            assert_eq!(parse_fixed_point(&rendered, 18).unwrap(), value);
        }
    }
}
