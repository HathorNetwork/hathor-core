#  Copyright 2025 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

from typing import ClassVar

from typing_extensions import Self, override

from hathor.nanocontracts.nc_types.nc_type import NCType
from hathor.serialization import Deserializer, SerializationError, Serializer
from hathor.serialization.adapters import MaxBytesExceededError
from hathor.serialization.encoding.leb128 import decode_leb128, encode_leb128
from hathor.utils.result import Result
from hathor.utils.typing import is_subclass


class _VarIntNCType(NCType[int]):
    _is_hashable = True
    # XXX: subclass must define these values:
    _signed: ClassVar[bool]
    _max_byte_size: ClassVar[int | None]

    @classmethod
    def _upper_bound_value(self) -> int | None:
        if self._max_byte_size is None:
            return None
        if self._signed:
            return 2**(self._max_byte_size * 7 - 1) - 1
        else:
            return 2**(self._max_byte_size * 7) - 1

    @classmethod
    def _lower_bound_value(self) -> int | None:
        if not self._signed:
            return 0
        if self._max_byte_size is not None:
            return -(2**(self._max_byte_size * 7))
        else:
            return None

    @override
    @classmethod
    def _from_type(cls, type_: type[int], /, *, type_map: NCType.TypeMap) -> Self:
        if not is_subclass(type_, int):
            raise TypeError('expected int type')
        return cls()

    @override
    def _check_value(self, value: int, /, *, deep: bool) -> None:
        if not isinstance(value, int):
            raise TypeError('expected integer')
        self._check_range(value)

    def _check_range(self, value: int) -> None:
        upper_bound = self._upper_bound_value()
        lower_bound = self._lower_bound_value()
        if upper_bound is not None and value > upper_bound:
            raise ValueError('above upper bound')
        if lower_bound is not None and value < lower_bound:
            raise ValueError('below lower bound')

    @override
    def _serialize(self, serializer: Serializer, value: int, /) -> None:
        if self._max_byte_size is not None:
            serializer = serializer.with_max_bytes(self._max_byte_size)
        try:
            encode_leb128(serializer, value, signed=self._signed)
        except MaxBytesExceededError as e:
            raise ValueError('value too long') from e

    @override
    def _deserialize(self, deserializer: Deserializer, /) -> Result[int, SerializationError]:
        if self._max_byte_size is not None:
            deserializer = deserializer.with_max_bytes(self._max_byte_size)
        return decode_leb128(deserializer, signed=self._signed)

    @override
    def _json_to_value(self, json_value: NCType.Json, /) -> int:
        # XXX: should we drop support for int?
        if not isinstance(json_value, (int, str)):
            raise ValueError('expected int or str')
        return int(json_value)

    @override
    def _value_to_json(self, value: int, /) -> NCType.Json:
        # XXX: should we use str instead?
        return value


class VarInt32NCType(_VarIntNCType):
    """Variable-size signed integer with at most 32 bytes, effectively 223 bits + sign bit.
    """

    _signed = True
    _max_byte_size = 32


class VarUint32NCType(_VarIntNCType):
    """Variable-size unsigned integer with at most 32 bytes.
    """

    _signed = False
    _max_byte_size = 32
