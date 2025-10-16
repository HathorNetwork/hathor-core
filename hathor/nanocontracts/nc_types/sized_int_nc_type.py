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
from hathor.serialization import Deserializer, Serializer
from hathor.serialization.encoding.int import decode_int, encode_int
from hathor.utils.typing import is_subclass


class _SizedIntNCType(NCType[int]):
    """ Base class for classes that represent builtin `int` values with a fixed size and signedness.
    """

    _is_hashable = True
    # XXX: subclass must define these values:
    _signed: ClassVar[bool]
    _byte_size: ClassVar[int]

    @classmethod
    def _upper_bound_value(self) -> int | None:
        if self._byte_size is None:
            return None
        if self._signed:
            return 2**(self._byte_size * 8 - 1) - 1
        else:
            return 2**(self._byte_size * 8) - 1

    @classmethod
    def _lower_bound_value(self) -> int | None:
        if self._byte_size is None:
            return None
        if self._signed:
            return -(2**(self._byte_size * 8 - 1))
        else:
            return 0

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
        encode_int(serializer, value, length=self._byte_size, signed=self._signed)

    @override
    def _deserialize(self, deserializer: Deserializer, /) -> int:
        return decode_int(deserializer, length=self._byte_size, signed=self._signed)

    @override
    def _json_to_value(self, json_value: NCType.Json, /) -> int:
        # XXX: should we support str?
        if not isinstance(json_value, int):
            raise ValueError('expected int')
        return json_value

    @override
    def _value_to_json(self, value: int, /) -> NCType.Json:
        # XXX: should we support str?
        return value


class Int32NCType(_SizedIntNCType):
    _signed = True
    _byte_size = 4  # 4-bytes -> 32-bits


class Uint32NCType(_SizedIntNCType):
    _signed = False
    _byte_size = 4  # 4-bytes -> 32-bits


class Uint8NCType(_SizedIntNCType):
    _signed = False
    _byte_size = 1
