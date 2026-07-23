# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

def sum_as_string(a: int, b: int) -> str:
    ...

class SignedAmount:
    """Signed token amount, stored as an integer in the V2-normalized unit.

    The signed counterpart to `UnsignedAmount`: it represents a possibly negative delta or net
    balance, while `UnsignedAmount` represents a versioned unsigned quantity. Instances and the
    class itself are immutable, so signed amounts have value semantics like `int`. Multiplication
    and division are deliberately not provided.
    """

    def __new__(cls, amount: int = 0) -> SignedAmount:
        """Wrap an integer as a signed amount in the V2-normalized unit, defaulting to zero."""
        ...

    def raw(self) -> int:
        """Underlying V2-normalized signed value."""
        ...

    def to_signed(self) -> SignedAmount:
        """Return `self`.

        Mirrors `UnsignedAmount.to_signed` so a value of unknown type (signed or unsigned) can
        be converted to a signed amount through a uniform method.
        """
        ...

    def to_unsigned(self) -> UnsignedAmount:
        """Convert to an `UnsignedAmount`.

        Raises `AssertionError` when the value is negative, since `UnsignedAmount` cannot
        represent negative values.
        """
        ...

    def __repr__(self) -> str: ...
    def __bool__(self) -> bool: ...

    def __add__(self, other: SignedAmount) -> SignedAmount: ...
    def __sub__(self, other: SignedAmount) -> SignedAmount: ...
    def __neg__(self) -> SignedAmount: ...
    def __pos__(self) -> SignedAmount: ...

    def __lt__(self, other: SignedAmount) -> bool: ...
    def __le__(self, other: SignedAmount) -> bool: ...
    def __eq__(self, other: SignedAmount) -> bool: ...
    def __ne__(self, other: SignedAmount) -> bool: ...
    def __gt__(self, other: SignedAmount) -> bool: ...
    def __ge__(self, other: SignedAmount) -> bool: ...

class UnsignedAmount:
    """Unsigned token amount tagged with its decimal-places version (V1 or V2).

    Carries the version under which the value was encoded on a vertex, and also stores a
    `normalized` form scaled to the V2 unit. Ordering, equality, and arithmetic operate on the
    normalized form, so V1 and V2 operands can be mixed without loss of precision; the arithmetic
    operators always return a V2 result. Instances and the class itself are immutable, so amounts
    have value semantics like `int`. Multiplication and division are deliberately not provided.
    """

    @staticmethod
    def set_normalization_factor(*, v1_decimal_places: int, v2_decimal_places: int) -> None:
        """Set the global factor used to scale a V1 value into the V2-normalized value.

        The factor is `10 ** (v2_decimal_places - v1_decimal_places)` and must be set before any
        V1 amount is constructed or queried. Idempotent: a repeated call yielding the same factor
        is a no-op, so independent initializers can each set it without coordinating. Raises when
        `v2_decimal_places < v1_decimal_places`, or when a later call would change an already-set
        factor.
        """
        ...

    @staticmethod
    def get_normalization_factor() -> int:
        """Return the global V1-to-V2 normalization factor. Raises when it has not been set."""
        ...

    @staticmethod
    def from_v1(amount: int) -> UnsignedAmount:
        """Build a V1 amount, storing the V2-scaled normalized form alongside the raw value."""
        ...

    @staticmethod
    def from_v2(amount: int) -> UnsignedAmount:
        """Build a V2 amount; raw and normalized coincide."""
        ...

    @staticmethod
    def from_version(amount: int, *, version: int) -> UnsignedAmount:
        """Build an amount from a raw value and a runtime-known version (`1` or `2`).

        Raises `ValueError` on an unknown version.
        """
        ...

    @staticmethod
    def zero() -> UnsignedAmount:
        """Return the canonical zero, a V2 amount."""
        ...

    def is_v1(self) -> bool:
        """Whether this amount is encoded as V1."""
        ...
    def is_v2(self) -> bool:
        """Whether this amount is encoded as V2."""
        ...
    def normalized(self) -> int:
        """Value scaled to the V2 unit, regardless of variant.

        This is the form used for ordering, equality, and arithmetic; use `raw` when re-emitting
        a vertex in its original encoding.
        """
        ...
    def raw(self) -> int:
        """Value in the encoding native to its variant.

        The un-scaled V1 input for a V1 amount, and the same as `normalized` for a V2.
        """
        ...
    def to_signed(self) -> SignedAmount:
        """Lift to a `SignedAmount` holding the normalized value."""
        ...
    def to_v1(self) -> UnsignedAmount:
        """Convert to V1, regardless of variant.

        Raises `AssertionError` when a V2 value would truncate, since it is not representable as
        V1.
        """
        ...
    def maybe_to_v1(self) -> UnsignedAmount | None:
        """Convert to V1, returning `None` for a value that would truncate.

        The `Option`-returning sibling of `to_v1`.
        """
        ...
    def to_v2(self) -> UnsignedAmount:
        """Convert to V2, regardless of variant. This is infallible."""
        ...
    def to_version(self, version: int) -> UnsignedAmount:
        """Convert to a runtime-known version (`1` or `2`).

        Raises `ValueError` on an unknown version, and `AssertionError` when a V1 target would
        truncate the value.
        """
        ...

    def __repr__(self) -> str: ...
    def __bool__(self) -> bool: ...

    def __add__(self, other: UnsignedAmount) -> UnsignedAmount: ...
    def __sub__(self, other: UnsignedAmount) -> UnsignedAmount: ...

    def __lt__(self, other: UnsignedAmount) -> bool: ...
    def __le__(self, other: UnsignedAmount) -> bool: ...
    def __eq__(self, other: UnsignedAmount) -> bool: ...
    def __ne__(self, other: UnsignedAmount) -> bool: ...
    def __gt__(self, other: UnsignedAmount) -> bool: ...
    def __ge__(self, other: UnsignedAmount) -> bool: ...
