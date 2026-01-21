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

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING

from hathorlib.headers.base import VertexBaseHeader
from hathorlib.headers.types import VertexHeaderId
from hathorlib.utils import int_to_bytes, unpack, unpack_len

if TYPE_CHECKING:
    from hathorlib.base_transaction import BaseTransaction
    from hathorlib.headers.nano_header import NanoHeader, NanoHeaderAction


NC_VERSION = 1


@dataclass(frozen=True)
class DeprecatedNanoHeader(VertexBaseHeader):
    tx: BaseTransaction

    # nc_id equals to the blueprint_id when a Nano Contract is being created.
    # nc_id equals to the nanocontract_id when a method is being called.
    nc_id: bytes

    # Name of the method to be called. When creating a new Nano Contract, it must be equal to 'initialize'.
    nc_method: str

    # Serialized arguments to nc_method.
    nc_args_bytes: bytes

    nc_actions: list[NanoHeaderAction]

    # Pubkey and signature of the transaction owner / caller.
    nc_pubkey: bytes
    nc_signature: bytes

    nc_version: int = NC_VERSION

    @classmethod
    def deserialize(cls, tx: BaseTransaction, buf: bytes) -> tuple[DeprecatedNanoHeader, bytes]:
        header_id, buf = buf[:1], buf[1:]
        assert header_id == VertexHeaderId.NANO_HEADER.value
        (nc_version,), buf = unpack('!B', buf)
        if nc_version != NC_VERSION:
            raise ValueError('unknown nanocontract version: {}'.format(nc_version))

        nc_id, buf = unpack_len(32, buf)
        (nc_method_len,), buf = unpack('!B', buf)
        nc_method, buf = unpack_len(nc_method_len, buf)
        (nc_args_bytes_len,), buf = unpack('!H', buf)
        nc_args_bytes, buf = unpack_len(nc_args_bytes_len, buf)

        nc_actions: list[NanoHeaderAction] = []
        from hathorlib.nanocontracts import DeprecatedNanoContract
        if not isinstance(tx, DeprecatedNanoContract):
            (nc_actions_len,), buf = unpack('!B', buf)
            for _ in range(nc_actions_len):
                action, buf = NanoHeader._deserialize_action(buf)
                nc_actions.append(action)

        (nc_pubkey_len,), buf = unpack('!B', buf)
        nc_pubkey, buf = unpack_len(nc_pubkey_len, buf)
        (nc_signature_len,), buf = unpack('!B', buf)
        nc_signature, buf = unpack_len(nc_signature_len, buf)

        decoded_nc_method = nc_method.decode('ascii')

        return cls(
            tx=tx,
            nc_version=nc_version,
            nc_id=nc_id,
            nc_method=decoded_nc_method,
            nc_args_bytes=nc_args_bytes,
            nc_actions=nc_actions,
            nc_pubkey=nc_pubkey,
            nc_signature=nc_signature,
        ), bytes(buf)

    def _serialize_without_header_id(self, *, skip_signature: bool) -> deque[bytes]:
        """Serialize the header with the option to skip the signature."""
        encoded_method = self.nc_method.encode('ascii')

        ret: deque[bytes] = deque()
        ret.append(int_to_bytes(NC_VERSION, 1))
        ret.append(self.nc_id)
        ret.append(int_to_bytes(len(encoded_method), 1))
        ret.append(encoded_method)
        ret.append(int_to_bytes(len(self.nc_args_bytes), 2))
        ret.append(self.nc_args_bytes)

        from hathorlib.nanocontracts import DeprecatedNanoContract
        if not isinstance(self.tx, DeprecatedNanoContract):
            ret.append(int_to_bytes(len(self.nc_actions), 1))
            for action in self.nc_actions:
                ret.append(NanoHeader._serialize_action(action))

        ret.append(int_to_bytes(len(self.nc_pubkey), 1))
        ret.append(self.nc_pubkey)
        if not skip_signature:
            ret.append(int_to_bytes(len(self.nc_signature), 1))
            ret.append(self.nc_signature)
        else:
            ret.append(int_to_bytes(0, 1))
        return ret

    def serialize(self) -> bytes:
        ret = self._serialize_without_header_id(skip_signature=False)
        ret.appendleft(VertexHeaderId.NANO_HEADER.value)
        return b''.join(ret)

    def get_sighash_bytes(self) -> bytes:
        ret = self._serialize_without_header_id(skip_signature=True)
        return b''.join(ret)
