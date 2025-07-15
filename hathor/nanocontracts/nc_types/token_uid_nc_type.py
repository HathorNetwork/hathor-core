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

from typing_extensions import Self, override

from hathor.conf.settings import HATHOR_TOKEN_UID
from hathor.nanocontracts.nc_types.fixed_size_bytes_nc_type import Bytes32NCType
from hathor.nanocontracts.nc_types.nc_type import NCType
from hathor.nanocontracts.types import TokenUid
from hathor.serialization import Deserializer, Serializer
from hathor.serialization.compound_encoding.optional import decode_optional, encode_optional
from hathor.serialization.exceptions import SerializationTypeError, SerializationValueError
from hathor.utils.typing import is_subclass

TOKEN_SIZE = 32
HATHOR_TOKEN_HEX = HATHOR_TOKEN_UID.hex()


class TokenUidNCType(NCType[TokenUid]):
    _is_hashable = True

    def __init__(self) -> None:
        self._bytes32_nc_type = Bytes32NCType(bytes)

    @override
    @classmethod
    def _from_type(cls, type_: type[TokenUid], /, *, type_map: NCType.TypeMap) -> Self:
        # XXX: TokenUid is a NewType it cannot be used to make this check, when we have a custom class it will be
        #      possible to use it here instead of bytes
        if not is_subclass(type_, bytes):
            raise NCTypeError('expected bytes type')
        return cls()

    @override
    def _check_value(self, value: TokenUid, /, *, deep: bool) -> None:
        if not isinstance(value, bytes):
            raise NCTypeError('expected bytes instance')
        data = bytes(value)
        if data == HATHOR_TOKEN_UID:
            return
        elif len(data) != TOKEN_SIZE:
            raise NCTypeError(
                f'value has {len(value)} bytes, expected '
                f'TokenUid to always have {TOKEN_SIZE} bytes'
            )

    @override
    def _serialize(self, serializer: Serializer, value: TokenUid, /) -> None:
        # TokenUid is mapped to bytes | None, None represents the native token
        raw_value: bytes | None = None if value == HATHOR_TOKEN_UID else value
        encode_optional(serializer, raw_value, self._bytes32_nc_type.serialize)

    @override
    def _deserialize(self, deserializer: Deserializer, /) -> TokenUid:
        # bytes | None is mapped back to TokenUid, None represents the native token
        raw_value = decode_optional(deserializer, self._bytes32_nc_type.deserialize)
        value = HATHOR_TOKEN_UID if raw_value is None else raw_value
        return TokenUid(value)

    @override
    def _json_to_value(self, json_value: NCType.Json, /) -> TokenUid:
        if not isinstance(json_value, str):
            raise NCValueError('expected str')
        if json_value == HATHOR_TOKEN_HEX:
            return TokenUid(HATHOR_TOKEN_UID)
        data = bytes.fromhex(json_value)
        if len(data) != TOKEN_SIZE:
            raise NCValueError('TokenUid must either be a null byte or have 32 bytes')
        return TokenUid(data)

    @override
    def _value_to_json(self, data: TokenUid, /) -> NCType.Json:
        if data == HATHOR_TOKEN_UID:
            return HATHOR_TOKEN_HEX
        else:
            return data.hex()
