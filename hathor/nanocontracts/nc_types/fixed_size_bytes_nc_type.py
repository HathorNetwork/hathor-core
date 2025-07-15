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

from typing import ClassVar, TypeVar

from typing_extensions import Self, override

from hathor.nanocontracts.nc_types.nc_type import NCType
from hathor.serialization import Deserializer, Serializer
from hathor.serialization.exceptions import SerializationTypeError, SerializationValueError
from hathor.utils.typing import is_subclass

B = TypeVar('B', bound=bytes)


class _FixedSizeBytesNCType(NCType[B]):
    _is_hashable = True
    _size: ClassVar[int]
    _actual_type: type[B]

    def __init__(self, actual_type: type[B]) -> None:
        self._actual_type = actual_type

    @override
    @classmethod
    def _from_type(cls, type_: type[B], /, *, type_map: NCType.TypeMap) -> Self:
        if not is_subclass(type_, bytes):
            raise NCTypeError('expected bytes-like type')
        return cls(type_)

    def _filter_in(self, value: B, /) -> bytes:
        """Mechanism to convert B into bytes before serializing."""
        return bytes(value)

    def _filter_out(self, data: bytes, /) -> B:
        """Mechanism to convert bytes into B after deserializing."""
        return self._actual_type(data)

    @override
    def _check_value(self, value: B, /, *, deep: bool) -> None:
        if not isinstance(value, bytes):
            raise NCTypeError(f'expected bytes type, not {type(value)}')
        data = self._filter_in(value)
        if len(data) != self._size:
            raise NCTypeError(
                f'value has {len(value)} bytes, expected '
                f'{self._actual_type.__name__} to always have {self._size} bytes'
            )

    @override
    def _serialize(self, serializer: Serializer, value: B, /) -> None:
        data = bytes(value)
        assert len(data) == self._size  # XXX: double check
        serializer.write_bytes(data)

    @override
    def _deserialize(self, deserializer: Deserializer, /) -> B:
        return self._filter_out(bytes(deserializer.read_bytes(self._size)))

    @override
    def _json_to_value(self, json_value: NCType.Json, /) -> B:
        if not isinstance(json_value, str):
            raise NCValueError('expected str')
        return self._filter_out(bytes.fromhex(json_value))

    @override
    def _value_to_json(self, value: bytes, /) -> NCType.Json:
        return value.hex()


class Bytes32NCType(_FixedSizeBytesNCType[B]):
    _size = 32
