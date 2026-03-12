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

from dataclasses import dataclass
from typing import TYPE_CHECKING

from hathor.transaction.headers.base import VertexBaseHeader
from hathor.transaction.util import VerboseCallback
from hathor.types import Address, Amount, TxOutputScript

if TYPE_CHECKING:
    from hathor.transaction.base_transaction import BaseTransaction
    from hathor.transaction.transaction import Transaction


@dataclass(slots=True, kw_only=True, frozen=True)
class TxTransferInput:
    address: Address
    amount: Amount
    token_index: int
    script: TxOutputScript


@dataclass(slots=True, kw_only=True, frozen=True)
class TxTransferOutput:
    address: Address
    amount: Amount
    token_index: int


@dataclass(slots=True, kw_only=True)
class TransferHeader(VertexBaseHeader):
    tx: Transaction

    # TODO: prevent replays.
    # seqnum: int

    inputs: list[TxTransferInput]
    outputs: list[TxTransferOutput]

    @classmethod
    def deserialize(
        cls,
        tx: BaseTransaction,
        buf: bytes,
        *,
        verbose: VerboseCallback = None
    ) -> tuple[TransferHeader, bytes]:
        from hathor.serialization import Deserializer
        from hathor.transaction import Transaction
        from hathor.transaction.vertex_parser._transfer_header import deserialize_transfer_header

        assert isinstance(tx, Transaction)

        deserializer = Deserializer.build_bytes_deserializer(buf)
        inputs, outputs = deserialize_transfer_header(deserializer, verbose=verbose)
        header = cls(
            tx=tx,
            inputs=inputs,
            outputs=outputs,
        )
        return header, bytes(deserializer.read_all())

    def serialize(self) -> bytes:
        from hathor.serialization import Serializer
        from hathor.transaction.vertex_parser._transfer_header import serialize_transfer_header

        serializer = Serializer.build_bytes_serializer()
        serialize_transfer_header(serializer, self)
        return bytes(serializer.finalize())

    def get_sighash_bytes(self) -> bytes:
        from hathor.serialization import Serializer
        from hathor.transaction.vertex_parser._transfer_header import serialize_transfer_header

        serializer = Serializer.build_bytes_serializer()
        serialize_transfer_header(serializer, self, skip_signature=True)
        return bytes(serializer.finalize())
