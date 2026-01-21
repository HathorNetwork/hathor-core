# Copyright 2024 Hathor Labs
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

from enum import IntEnum, unique
from typing import NamedTuple

from hathorlib.conf import HathorSettings
from hathorlib.transaction import Transaction
from hathorlib.utils import int_to_bytes, unpack, unpack_len

settings = HathorSettings()

# used to allow new versions of the serialization format in the future
ON_CHAIN_BLUEPRINT_VERSION: int = 1


@unique
class CodeKind(IntEnum):
    """ Represents what type of code and format is being used, to allow new code/compression types in the future.
    """

    PYTHON_ZLIB = 1

    def __bytes__(self) -> bytes:
        return int_to_bytes(number=self.value, size=1)


class Code(NamedTuple):
    """ Store the code object in memory, along with helper methods.
    """

    # determines how the content will be interpreted
    kind: CodeKind

    # the encoded content, usually encoded implies compressed
    data: bytes

    def __bytes__(self) -> bytes:
        # Code serialization format: [kind:variable bytes][null byte][data:variable bytes]
        if self.kind is not CodeKind.PYTHON_ZLIB:
            raise ValueError('Invalid code kind value')
        buf = bytearray()
        buf.extend(bytes(self.kind))
        buf.extend(self.data)
        return bytes(buf)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'Code':
        """ Parses a Code instance from a byte sequence, the length of the data is encoded outside of this class.

        NOTE: This will not validate whether the encoded has a valid compression format. A Validator must be used to
        check that.
        """
        data_arr = bytearray(data)
        kind = CodeKind(data_arr[0])
        if kind is not CodeKind.PYTHON_ZLIB:
            raise ValueError('Code kind not supported')
        compressed_code = data_arr[1:]
        return cls(kind, bytes(compressed_code))


class OnChainBlueprint(Transaction):
    """On-chain blueprint vertex to be placed on the DAG of transactions."""

    MIN_NUM_INPUTS = 0

    def __init__(self) -> None:
        super().__init__()

        # Pubkey and signature of the transaction owner / caller.
        self.nc_pubkey: bytes = b''
        self.nc_signature: bytes = b''

        self.code: Code = Code(CodeKind.PYTHON_ZLIB, b'')

    def serialize_code(self) -> bytes:
        """Serialization of self.code, to be used for the serialization of this transaction type."""
        buf = bytearray()
        buf.extend(int_to_bytes(ON_CHAIN_BLUEPRINT_VERSION, 1))
        serialized_code = bytes(self.code)
        buf.extend(int_to_bytes(len(serialized_code), 4))
        buf.extend(serialized_code)
        return bytes(buf)

    @classmethod
    def deserialize_code(_cls, buf: bytes) -> tuple[Code, bytes]:
        """Parses the self.code field, returns the parse result and the remaining bytes."""
        (ocb_version,), buf = unpack('!B', buf)
        if ocb_version != ON_CHAIN_BLUEPRINT_VERSION:
            raise ValueError(f'unknown on-chain blueprint version: {ocb_version}')

        (serialized_code_len,), buf = unpack('!L', buf)
        max_serialized_code_len = settings.NC_ON_CHAIN_BLUEPRINT_CODE_MAX_SIZE_COMPRESSED
        if serialized_code_len > max_serialized_code_len:
            raise ValueError(f'compressed code data is too large: {serialized_code_len} > {max_serialized_code_len}')
        serialized_code, buf = unpack_len(serialized_code_len, buf)
        code = Code.from_bytes(serialized_code)
        return code, buf

    def _serialize_ocb(self, *, skip_signature: bool = False) -> bytes:
        buf = bytearray()
        buf += self.serialize_code()
        buf += int_to_bytes(len(self.nc_pubkey), 1)
        buf += self.nc_pubkey
        if not skip_signature:
            buf += int_to_bytes(len(self.nc_signature), 1)
            buf += self.nc_signature
        else:
            buf += int_to_bytes(0, 1)
        return bytes(buf)

    def get_funds_struct(self) -> bytes:
        struct_bytes = super().get_funds_struct()
        struct_bytes += self._serialize_ocb()
        return struct_bytes

    def get_funds_fields_from_struct(self, buf: bytes) -> bytes:
        buf = super().get_funds_fields_from_struct(buf)

        code, buf = OnChainBlueprint.deserialize_code(buf)
        self.code = code

        (nc_pubkey_len,), buf = unpack('!B', buf)
        self.nc_pubkey, buf = unpack_len(nc_pubkey_len, buf)
        (nc_signature_len,), buf = unpack('!B', buf)
        self.nc_signature, buf = unpack_len(nc_signature_len, buf)

        return buf
