#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Transitional test shim for the versioned token-amount types.

`UnsignedAmount` and `SignedAmount` mirror the public API of the real `htr_lib` types as thin
`int` subclasses, with V1 and V2 collapsed onto a single identity unit. Test fixtures import the
versioned types from here so the entire codebase's test suite can adopt the wrapped form while
`hathorlib.token_amount` still aliases both names to `int`. Every value therefore stays a plain
integer at runtime and under `mypy --strict-equality`, so the fixtures keep passing against the
unflipped production code. The single import indirection lets a later change repoint this module
at `htr_lib` without touching each fixture.
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
