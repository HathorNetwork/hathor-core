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

from hathor.crypto.util import decode_address, get_address_b58_from_bytes
from hathor.nanocontracts.nc_types.nc_type import NCType
from hathor.nanocontracts.types import Address
from hathor.serialization import Deserializer, Serializer
from hathor.serialization.consts import DEFAULT_BYTES_MAX_LENGTH
from hathor.serialization.encoding.bytes import decode_bytes, encode_bytes
from hathor.transaction.headers.nano_header import ADDRESS_LEN_BYTES
from hathor.utils.typing import is_subclass


class AddressNCType(NCType[Address]):
    """ Represents `Address` values, which use a different JSON encoding than bytes.
    """
    _is_hashable = True

    @override
    @classmethod
    def _from_type(cls, type_: type[Address], /, *, type_map: NCType.TypeMap) -> Self:
        if not is_subclass(type_, bytes):
            raise TypeError('expected bytes-like type')
        return cls()

    @override
    def _check_value(self, value: Address, /, *, deep: bool) -> None:
        if not isinstance(value, bytes):
            raise TypeError('expected bytes type')
        if len(value) != ADDRESS_LEN_BYTES:
            raise ValueError(f'an address must always have {ADDRESS_LEN_BYTES} bytes')

    @override
    def _serialize(self, serializer: Serializer, value: Address, /) -> None:
        encode_bytes(serializer.with_max_bytes(DEFAULT_BYTES_MAX_LENGTH), value)

    @override
    def _deserialize(self, deserializer: Deserializer, /) -> Address:
        return Address(decode_bytes(deserializer.with_max_bytes(DEFAULT_BYTES_MAX_LENGTH)))

    @override
    def _json_to_value(self, json_value: NCType.Json, /) -> Address:
        if not isinstance(json_value, str):
            raise ValueError('expected str')
        # XXX: maybe decode_address could be migrated to hathor.serializers.encoding.b58_address
        return Address(decode_address(json_value))

    @override
    def _value_to_json(self, value: Address, /) -> NCType.Json:
        # XXX: maybe get_address_b58_from_bytes could be migrated to hathor.serializers.encoding.b58_address
        return get_address_b58_from_bytes(value)
