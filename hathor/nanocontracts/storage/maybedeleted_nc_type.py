# Copyright 2025 Hathor Labs
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

from typing import TypeVar

from typing_extensions import override

from hathor.nanocontracts.nc_types import NCType
from hathor.nanocontracts.storage.types import DeletedKey, DeletedKeyType
from hathor.serialization import Deserializer, Serializer
from hathor.serialization.encoding.bool import decode_bool

T = TypeVar('T')


class MaybeDeletedNCType(NCType[T | DeletedKeyType]):
    """ Used internally to wrap a NCType or Delete
    """

    __slots__ = ('_value',)
    _value: NCType[T] | None

    def __init__(self, wrapped_value: NCType[T] | None) -> None:
        self._value = wrapped_value

    @classmethod
    def is_deleted_key(cls, data: bytes) -> bool:
        """ Shortcut to check if serializing data would result in a `DeletedKey`.

        It is possible to do that because of the serialization layout, it basically boils down to checking the first
        byte of data, this is done indirectly but using the same implementation that `MaybeDeletedNCType.deserialize`
        uses.
        """
        deserializer = Deserializer.build_bytes_deserializer(data)
        has_value = decode_bool(deserializer)
        return not has_value

    @override
    def _check_value(self, value: T | DeletedKeyType, /, *, deep: bool) -> None:
        if isinstance(value, DeletedKeyType):
            assert value is DeletedKey
            return
        if deep:
            if self._value is None:
                raise ValueError('missing inner NCType')
            self._value._check_value(value, deep=deep)

    @override
    def _serialize(self, serializer: Serializer, value: T | DeletedKeyType, /) -> None:
        from hathor.serialization.encoding.bool import encode_bool
        if value is DeletedKey:
            encode_bool(serializer, False)
        else:
            if self._value is None:
                raise ValueError('missing inner NCType')
            assert not isinstance(value, DeletedKeyType)
            encode_bool(serializer, True)
            self._value.serialize(serializer, value)

    @override
    def _deserialize(self, deserializer: Deserializer, /) -> T | DeletedKeyType:
        has_value = decode_bool(deserializer)
        if has_value:
            if self._value is None:
                raise ValueError('missing inner NCType')
            return self._value.deserialize(deserializer)
        else:
            return DeletedKey
