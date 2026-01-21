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
from hathorlib.utils import decode_unsigned, encode_unsigned, int_to_bytes, unpack, unpack_len

if TYPE_CHECKING:
    from hathorlib.base_transaction import BaseTransaction
    from hathorlib.nanocontracts.types import NCActionType

NC_INITIALIZE_METHOD = 'initialize'
ADDRESS_LEN_BYTES = 25
ADDRESS_SEQNUM_SIZE: int = 8  # bytes
_NC_SCRIPT_LEN_MAX_BYTES: int = 2


@dataclass(frozen=True)
class NanoHeaderAction:
    type: 'NCActionType'
    token_index: int
    amount: int


@dataclass(frozen=True)
class NanoHeader(VertexBaseHeader):
    tx: BaseTransaction

    # Sequence number for the caller.
    nc_seqnum: int

    # nc_id equals to the blueprint_id when a Nano Contract is being created.
    # nc_id equals to the nanocontract_id when a method is being called.
    nc_id: bytes

    # Name of the method to be called. When creating a new Nano Contract, it must be equal to 'initialize'.
    nc_method: str

    # Serialized arguments to nc_method.
    nc_args_bytes: bytes

    nc_actions: list[NanoHeaderAction]

    # Address and script with signature(s) of the transaction owner(s)/caller(s). Supports P2PKH and P2SH.
    nc_address: bytes
    nc_script: bytes

    @classmethod
    def _deserialize_action(cls, buf: bytes) -> tuple[NanoHeaderAction, bytes]:
        from hathorlib.base_transaction import bytes_to_output_value
        from hathorlib.nanocontracts.types import NCActionType

        type_bytes, buf = buf[:1], buf[1:]
        action_type = NCActionType.from_bytes(type_bytes)
        (token_index,), buf = unpack('!B', buf)
        amount, buf = bytes_to_output_value(buf)
        return NanoHeaderAction(
            type=action_type,
            token_index=token_index,
            amount=amount,
        ), buf

    @classmethod
    def deserialize(cls, tx: BaseTransaction, buf: bytes) -> tuple[NanoHeader, bytes]:
        from hathorlib.nanocontracts import DeprecatedNanoContract

        header_id, buf = buf[:1], buf[1:]
        assert header_id == VertexHeaderId.NANO_HEADER.value

        nc_id, buf = unpack_len(32, buf)
        nc_seqnum, buf = decode_unsigned(buf, max_bytes=ADDRESS_SEQNUM_SIZE)
        (nc_method_len,), buf = unpack('!B', buf)
        nc_method, buf = unpack_len(nc_method_len, buf)
        (nc_args_bytes_len,), buf = unpack('!H', buf)
        nc_args_bytes, buf = unpack_len(nc_args_bytes_len, buf)

        nc_actions: list[NanoHeaderAction] = []
        if not isinstance(tx, DeprecatedNanoContract):
            (nc_actions_len,), buf = unpack('!B', buf)
            for _ in range(nc_actions_len):
                action, buf = cls._deserialize_action(buf)
                nc_actions.append(action)

        nc_address, buf = unpack_len(ADDRESS_LEN_BYTES, buf)
        nc_script_len, buf = decode_unsigned(buf, max_bytes=_NC_SCRIPT_LEN_MAX_BYTES)
        nc_script, buf = unpack_len(nc_script_len, buf)

        decoded_nc_method = nc_method.decode('ascii')

        return cls(
            tx=tx,
            nc_seqnum=nc_seqnum,
            nc_id=nc_id,
            nc_method=decoded_nc_method,
            nc_args_bytes=nc_args_bytes,
            nc_actions=nc_actions,
            nc_address=nc_address,
            nc_script=nc_script,
        ), bytes(buf)

    @staticmethod
    def _serialize_action(action: NanoHeaderAction) -> bytes:
        from hathorlib.base_transaction import output_value_to_bytes
        ret = [
            action.type.to_bytes(),
            int_to_bytes(action.token_index, 1),
            output_value_to_bytes(action.amount),
        ]
        return b''.join(ret)

    def _serialize_without_header_id(self, *, skip_signature: bool) -> deque[bytes]:
        """Serialize the header with the option to skip the signature."""
        from hathorlib.nanocontracts import DeprecatedNanoContract

        encoded_method = self.nc_method.encode('ascii')

        ret: deque[bytes] = deque()
        ret.append(self.nc_id)
        ret.append(encode_unsigned(self.nc_seqnum, max_bytes=ADDRESS_SEQNUM_SIZE))
        ret.append(int_to_bytes(len(encoded_method), 1))
        ret.append(encoded_method)
        ret.append(int_to_bytes(len(self.nc_args_bytes), 2))
        ret.append(self.nc_args_bytes)

        if not isinstance(self.tx, DeprecatedNanoContract):
            ret.append(int_to_bytes(len(self.nc_actions), 1))
            for action in self.nc_actions:
                ret.append(self._serialize_action(action))

        ret.append(self.nc_address)
        if not skip_signature:
            ret.append(encode_unsigned(len(self.nc_script), max_bytes=_NC_SCRIPT_LEN_MAX_BYTES))
            ret.append(self.nc_script)
        else:
            ret.append(encode_unsigned(0, max_bytes=_NC_SCRIPT_LEN_MAX_BYTES))
        return ret

    def serialize(self) -> bytes:
        ret = self._serialize_without_header_id(skip_signature=False)
        ret.appendleft(VertexHeaderId.NANO_HEADER.value)
        return b''.join(ret)

    def get_sighash_bytes(self) -> bytes:
        ret = self._serialize_without_header_id(skip_signature=True)
        return b''.join(ret)
