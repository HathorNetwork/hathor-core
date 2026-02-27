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

from hathor.serialization import Deserializer, Serializer
from hathor.serialization.encoding.bytes import decode_bytes, encode_bytes
from hathor.serialization.encoding.int import decode_int, encode_int
from hathor.serialization.encoding.output_value import decode_output_value, encode_output_value
from hathor.transaction.headers.base import VertexBaseHeader
from hathor.transaction.headers.types import VertexHeaderId
from hathor.transaction.util import VerboseCallback
from hathor.types import Address, Amount, TxOutputScript

if TYPE_CHECKING:
    from hathor.transaction import Transaction
    from hathor.transaction.base_transaction import BaseTransaction


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
        from hathor.transaction import Transaction
        assert isinstance(tx, Transaction)

        deserializer = Deserializer.build_bytes_deserializer(buf)

        header_id = deserializer.read_bytes(1)
        if verbose:
            verbose('header_id', header_id)
        assert header_id == VertexHeaderId.TRANSFER_HEADER.value

        inputs_len = decode_int(deserializer, length=1, signed=False)
        if verbose:
            verbose('inputs_len', inputs_len)

        inputs_: list[TxTransferInput] = []
        for _ in range(inputs_len):
            address = decode_bytes(deserializer)
            amount = decode_output_value(deserializer, strict=True)
            token_index = decode_int(deserializer, length=1, signed=False)
            script = decode_bytes(deserializer)
            inputs_.append(TxTransferInput(
                address=address,
                amount=amount,
                token_index=token_index,
                script=script,
            ))

        outputs_len = decode_int(deserializer, length=1, signed=False)
        if verbose:
            verbose('outputs_len', outputs_len)

        outputs_: list[TxTransferOutput] = []
        for _ in range(outputs_len):
            address = decode_bytes(deserializer)
            amount = decode_output_value(deserializer, strict=True)
            token_index = decode_int(deserializer, length=1, signed=False)
            outputs_.append(TxTransferOutput(
                address=address,
                amount=amount,
                token_index=token_index,
            ))

        transfer_header = TransferHeader(
            tx=tx,
            inputs=inputs_,
            outputs=outputs_,
        )

        return transfer_header, bytes(deserializer.read_all())

    def _serialize_without_header_id(self, serializer: Serializer, *, skip_signature: bool) -> None:
        """Serialize the header with the option to skip the signature."""
        encode_int(serializer, len(self.inputs), length=1, signed=False)
        for txin in self.inputs:
            encode_bytes(serializer, txin.address)
            encode_output_value(serializer, txin.amount, strict=True)
            encode_int(serializer, txin.token_index, length=1, signed=False)
            if not skip_signature:
                encode_bytes(serializer, txin.script)
            else:
                encode_bytes(serializer, b'')

        encode_int(serializer, len(self.outputs), length=1, signed=False)
        for txout in self.outputs:
            encode_bytes(serializer, txout.address)
            encode_output_value(serializer, txout.amount, strict=True)
            encode_int(serializer, txout.token_index, length=1, signed=False)

    def serialize(self) -> bytes:
        serializer = Serializer.build_bytes_serializer()
        serializer.write_bytes(VertexHeaderId.TRANSFER_HEADER.value)
        self._serialize_without_header_id(serializer, skip_signature=False)
        return bytes(serializer.finalize())

    def get_sighash_bytes(self) -> bytes:
        serializer = Serializer.build_bytes_serializer()
        self._serialize_without_header_id(serializer, skip_signature=True)
        return bytes(serializer.finalize())
