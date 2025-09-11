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

from enum import IntEnum
from typing import TypeVar

from typing_extensions import Self, override

from hathor.nanocontracts.nc_types.nc_type import NCType
from hathor.serialization import Deserializer, Serializer
from hathor.serialization.encoding.int import decode_int, encode_int
from hathor.utils.typing import is_subclass

T = TypeVar('T', bound=IntEnum)


class IntEnumNCType(NCType[T]):
    """NC Type for IntEnum subclasses."""

    _is_hashable = True

    def __init__(self, enum_class: type[T]) -> None:
        self.enum_class = enum_class

    @override
    @classmethod
    def _from_type(cls, type_: type[T], /, *, type_map: NCType.TypeMap) -> Self:
        if not is_subclass(type_, IntEnum):
            raise TypeError('expected IntEnum subclass')
        return cls(type_)

    @override
    def _check_value(self, value: T, /, *, deep: bool) -> None:
        if not isinstance(value, self.enum_class):
            raise TypeError(f'expected {self.enum_class.__name__}')

    @override
    def _serialize(self, serializer: Serializer, value: T, /) -> None:
        # Serialize as 1-byte unsigned integer (same as TokenVersion range)
        encode_int(serializer, int(value), length=1, signed=False)

    @override
    def _deserialize(self, deserializer: Deserializer, /) -> T:
        int_value = decode_int(deserializer, length=1, signed=False)
        try:
            return self.enum_class(int_value)
        except ValueError as e:
            raise ValueError(f'invalid {self.enum_class.__name__} value: {int_value}') from e

    @override
    def _json_to_value(self, json_value: NCType.Json, /) -> T:
        if isinstance(json_value, str):
            # Try to parse by name
            try:
                return self.enum_class[json_value]
            except KeyError:
                raise ValueError(f'invalid {self.enum_class.__name__} name: {json_value}')
        elif isinstance(json_value, int):
            # Try to parse by value
            try:
                return self.enum_class(json_value)
            except ValueError:
                raise ValueError(f'invalid {self.enum_class.__name__} value: {json_value}')
        else:
            raise ValueError(f'expected str or int for {self.enum_class.__name__}')

    @override
    def _value_to_json(self, value: T, /) -> NCType.Json:
        return int(value)
