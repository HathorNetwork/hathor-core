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

from inspect import isclass
from typing import TypeVar

from typing_extensions import Self, override

from hathor.nanocontracts.nc_types.nc_type import NCType
from hathor.serialization import Deserializer, Serializer
from hathor.serialization.consts import DEFAULT_BYTES_MAX_LENGTH
from hathor.serialization.encoding.bytes import decode_bytes, encode_bytes
from hathor.utils.typing import is_subclass

B = TypeVar('B', bound=bytes)


class BytesLikeNCType(NCType[B]):
    """ Represents values from class that inherit/new-type `bytes`.
    """

    __slots__ = ('_actual_type')
    _is_hashable = True
    _actual_type: type[B]

    def __init__(self, actual_type: type[B]) -> None:
        self._actual_type = actual_type

    @override
    @classmethod
    def _from_type(cls, type_: type[B], /, *, type_map: NCType.TypeMap) -> Self:
        if not is_subclass(type_, bytes):
            raise TypeError('expected bytes-like type')
        return cls(type_)

    @override
    def _check_value(self, value: bytes, /, *, deep: bool) -> None:
        if isclass(self._actual_type):
            if not isinstance(value, (bytes, self._actual_type)):
                raise TypeError('expected {self._actual_type} instance')
        else:
            if not isinstance(value, bytes):
                raise TypeError('expected bytes instance')

    @override
    def _serialize(self, serializer: Serializer, value: B, /) -> None:
        data = bytes(value)
        encode_bytes(serializer.with_max_bytes(DEFAULT_BYTES_MAX_LENGTH), data)

    @override
    def _deserialize(self, deserializer: Deserializer, /) -> B:
        data = decode_bytes(deserializer.with_max_bytes(DEFAULT_BYTES_MAX_LENGTH))
        return self._actual_type(data)

    @override
    def _json_to_value(self, json_value: NCType.Json, /) -> B:
        if not isinstance(json_value, str):
            raise ValueError('expected str')
        data = bytes.fromhex(json_value)
        return self._actual_type(data)

    @override
    def _value_to_json(self, value: B, /) -> NCType.Json:
        data = bytes(value)
        return data.hex()


class BytesNCType(BytesLikeNCType[bytes]):
    """ Represents builtin `bytes` values.
    """
    __slots__ = ()
    _actual_type = bytes

    @override
    def __init__(self) -> None:
        pass

    @override
    @classmethod
    def _from_type(cls, type_: type[bytes], /, *, type_map: NCType.TypeMap) -> Self:
        if type_ is not bytes:
            raise TypeError('expected bytes type')
        return cls()
