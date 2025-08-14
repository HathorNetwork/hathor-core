#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

r"""
A caller ID union type is encoded with a single byte identifier followed by the encoded value according to the type.

Layout:

    [0x00][address] when Address
    [0x01][contract_id] when ContractId

>>> from hathor.nanocontracts.types import Address, ContractId
>>> se = Serializer.build_bytes_serializer()
>>> addr = Address(b'\x11' * 25)
>>> encode_caller_id(se, addr)
>>> bytes(se.finalize()).hex()
'0011111111111111111111111111111111111111111111111111'

>>> se = Serializer.build_bytes_serializer()
>>> contract_id = ContractId(b'\x22' * 32)
>>> encode_caller_id(se, contract_id)
>>> bytes(se.finalize()).hex()
'012222222222222222222222222222222222222222222222222222222222222222'

>>> de = Deserializer.build_bytes_deserializer(bytes.fromhex('0011111111111111111111111111111111111111111111111111'))
>>> result = decode_caller_id(de)
>>> isinstance(result, Address)
True
>>> de.finalize()

>>> value = bytes.fromhex('012222222222222222222222222222222222222222222222222222222222222222')
>>> de = Deserializer.build_bytes_deserializer(value)
>>> result = decode_caller_id(de)
>>> isinstance(result, ContractId)
True
>>> de.finalize()
"""

from typing import assert_never

from hathor.nanocontracts.types import Address, CallerId, ContractId
from hathor.serialization import Deserializer, Serializer
from hathor.serialization.encoding.bool import decode_bool, encode_bool

from ...transaction.base_transaction import TX_HASH_SIZE
from ...transaction.headers.nano_header import ADDRESS_LEN_BYTES


def encode_caller_id(serializer: Serializer, value: CallerId) -> None:
    match value:
        case Address():
            assert len(value) == ADDRESS_LEN_BYTES
            encode_bool(serializer, False)
        case ContractId():
            assert len(value) == TX_HASH_SIZE
            encode_bool(serializer, True)
        case _:
            assert_never(value)
    serializer.write_bytes(value)


def decode_caller_id(deserializer: Deserializer) -> CallerId:
    is_contract = decode_bool(deserializer)
    if is_contract:
        data = bytes(deserializer.read_bytes(TX_HASH_SIZE))
        return ContractId(data)
    else:
        data = bytes(deserializer.read_bytes(ADDRESS_LEN_BYTES))
        return Address(data)
