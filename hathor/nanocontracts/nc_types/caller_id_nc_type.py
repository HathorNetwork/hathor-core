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

from types import UnionType
from typing import _UnionGenericAlias as UnionGenericAlias, assert_never, get_args  # type: ignore[attr-defined]

from typing_extensions import Self, override

from hathor.crypto.util import decode_address, get_address_b58_from_bytes
from hathor.nanocontracts.nc_types.nc_type import NCType
from hathor.nanocontracts.types import Address, CallerId, ContractId
from hathor.serialization import Deserializer, Serializer
from hathor.serialization.compound_encoding.caller_id import decode_caller_id, encode_caller_id
from hathor.transaction.base_transaction import TX_HASH_SIZE
from hathor.transaction.headers.nano_header import ADDRESS_LEN_BYTES


class CallerIdNCType(NCType[CallerId]):
    """Represents `CallerID` values, which can be `Address` or `ContractId`."""
    __slots__ = ()
    _is_hashable = True

    @override
    @classmethod
    def _from_type(cls, type_: type[Address] | type[ContractId], /, *, type_map: NCType.TypeMap) -> Self:
        if not isinstance(type_, (UnionType, UnionGenericAlias)):
            raise TypeError('expected type union')
        args = get_args(type_)
        assert args, 'union always has args'
        if len(args) != 2 or Address not in args or ContractId not in args:
            raise TypeError('type must be either `Address | ContractId` or `ContractId | Address`')
        return cls()

    @override
    def _check_value(self, value: CallerId, /, *, deep: bool) -> None:
        match value:
            case Address():
                if len(value) != ADDRESS_LEN_BYTES:
                    raise ValueError(f'an address must always have {ADDRESS_LEN_BYTES} bytes')
            case ContractId():
                if len(value) != TX_HASH_SIZE:
                    raise ValueError(f'an contract id must always have {TX_HASH_SIZE} bytes')
            case _:
                assert_never(value)

    @override
    def _serialize(self, serializer: Serializer, value: CallerId, /) -> None:
        encode_caller_id(serializer, value)

    @override
    def _deserialize(self, deserializer: Deserializer, /) -> CallerId:
        return decode_caller_id(deserializer)

    @override
    def _json_to_value(self, json_value: NCType.Json, /) -> CallerId:
        """
        >>> nc_type = CallerIdNCType()
        >>> value = nc_type.json_to_value('HH5As5aLtzFkcbmbXZmE65wSd22GqPWq2T')
        >>> isinstance(value, Address)
        True
        >>> value == Address(bytes.fromhex('2873c0a326af979a12be89ee8a00e8871c8e2765022e9b803c'))
        True
        >>> contract_id = ContractId(b'\x11' * 32)
        >>> value = nc_type.json_to_value(contract_id.hex())
        >>> isinstance(value, ContractId)
        True
        >>> value == contract_id
        True
        >>> nc_type.json_to_value('foo')
        Traceback (most recent call last):
        ...
        ValueError: cannot decode "foo" as CallerId
        """
        if not isinstance(json_value, str):
            raise ValueError('expected str')

        if len(json_value) == 34:
            return Address(decode_address(json_value))

        if len(json_value) == TX_HASH_SIZE * 2:
            return ContractId(bytes.fromhex(json_value))

        raise ValueError(f'cannot decode "{json_value}" as CallerId')

    @override
    def _value_to_json(self, value: CallerId, /) -> NCType.Json:
        """
        >>> nc_type = CallerIdNCType()
        >>> address = Address(bytes.fromhex('2873c0a326af979a12be89ee8a00e8871c8e2765022e9b803c'))
        >>> nc_type.value_to_json(address)
        'HH5As5aLtzFkcbmbXZmE65wSd22GqPWq2T'
        >>> contract_id = ContractId(b'\x11' * 32)
        >>> nc_type.value_to_json(contract_id)
        '1111111111111111111111111111111111111111111111111111111111111111'
        """
        match value:
            case Address():
                return get_address_b58_from_bytes(value)
            case ContractId():
                return value.hex()
            case _:
                assert_never(value)
