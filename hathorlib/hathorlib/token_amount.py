# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Transitional shim for the versioned token-amount types.

`UnsignedAmount` and `SignedAmount` mirror the public API of the real `htr_lib` types as thin
`int` subclasses, with V1 and V2 collapsed onto a single identity unit. Every value therefore
stays a plain integer at runtime and under `mypy --strict-equality`, so callers can adopt the
wrapped surface while amounts still behave as raw integers. The single import indirection lets
a later change repoint this module at `htr_lib` without touching each caller.
"""

from __future__ import annotations


class SignedAmount(int):
    """Signed token amount, an `int` subclass with the `htr_lib.SignedAmount` surface."""

    __slots__ = ()

    def raw(self) -> int:
        return int(self)

    def to_signed(self) -> SignedAmount:
        return self

    def to_unsigned(self) -> UnsignedAmount:
        assert self >= 0
        return UnsignedAmount(int(self))

    def __add__(self, other: int, /) -> SignedAmount:
        return SignedAmount(int(self) + int(other))

    def __radd__(self, other: int, /) -> SignedAmount:
        return SignedAmount(int(other) + int(self))

    def __sub__(self, other: int, /) -> SignedAmount:
        return SignedAmount(int(self) - int(other))

    def __rsub__(self, other: int, /) -> SignedAmount:
        return SignedAmount(int(other) - int(self))

    def __neg__(self) -> SignedAmount:
        return SignedAmount(-int(self))

    def __pos__(self) -> SignedAmount:
        return SignedAmount(+int(self))


class UnsignedAmount(int):
    """Unsigned token amount, an `int` subclass with the `htr_lib.UnsignedAmount` surface."""

    __slots__ = ()

    @staticmethod
    def set_decimal_places(*, v1_decimal_places: int, v2_decimal_places: int) -> None:
        pass

    @staticmethod
    def get_normalization_factor() -> int:
        return 1

    @classmethod
    def from_v1(cls, amount: int) -> UnsignedAmount:
        return cls(amount)

    @classmethod
    def from_v2(cls, amount: int) -> UnsignedAmount:
        return cls(amount)

    @classmethod
    def from_version(cls, amount: int, *, version: int) -> UnsignedAmount:
        return cls(amount)

    @classmethod
    def zero(cls) -> UnsignedAmount:
        return cls(0)

    @classmethod
    def parse(cls, s: str) -> UnsignedAmount:
        return cls(int(s))

    def is_v1(self) -> bool:
        return True

    def is_v2(self) -> bool:
        return True

    def normalized(self) -> int:
        return int(self)

    def raw(self) -> int:
        return int(self)

    def to_signed(self) -> SignedAmount:
        return SignedAmount(int(self))

    def to_v1(self) -> UnsignedAmount:
        return self

    def maybe_to_v1(self) -> UnsignedAmount | None:
        return self

    def to_v2(self) -> UnsignedAmount:
        return self

    def to_version(self, version: int) -> UnsignedAmount:
        return self

    def __add__(self, other: int, /) -> UnsignedAmount:
        return UnsignedAmount(int(self) + int(other))

    def __radd__(self, other: int, /) -> UnsignedAmount:
        return UnsignedAmount(int(other) + int(self))

    def __sub__(self, other: int, /) -> UnsignedAmount:
        return UnsignedAmount(int(self) - int(other))
