# Copyright 2023 Hathor Labs
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

from hathorlib import Transaction, TxVersion


class DeprecatedNanoContract(Transaction):
    """NanoContract vertex to be placed on the DAG of transactions."""

    def __init__(self) -> None:
        super().__init__()

        self.version = TxVersion.NANO_CONTRACT

        # nc_id equals to the blueprint_id when a Nano Contract is being created.
        # nc_id equals to the nanocontract_id when a method is being called.
        self.nc_id: bytes = b''

        # Name of the method to be called. When creating a new Nano Contract, it must be equal to 'initialize'.
        self.nc_method: str = ''

        # Serialized arguments to nc_method.
        self.nc_args_bytes: bytes = b''

        # Pubkey and signature of the transaction owner / caller.
        self.nc_pubkey: bytes = b''
        self.nc_signature: bytes = b''

    ################################
    # Methods for Transaction
    ################################

    def get_funds_fields_from_struct(self, buf: bytes) -> bytes:
        from hathorlib.headers import DeprecatedNanoHeader, VertexHeaderId
        buf = super().get_funds_fields_from_struct(buf)
        nano_header, buf = DeprecatedNanoHeader.deserialize(self, VertexHeaderId.NANO_HEADER.value + buf)
        self.headers.append(nano_header)
        return buf

    def get_funds_struct(self) -> bytes:
        from hathorlib.headers import DeprecatedNanoHeader
        struct_bytes = super().get_funds_struct()
        nano_header_bytes = self._get_header(DeprecatedNanoHeader).serialize()
        struct_bytes += nano_header_bytes[1:]
        return struct_bytes

    def get_headers_hash(self) -> bytes:
        return b''

    def get_headers_struct(self) -> bytes:
        return b''
