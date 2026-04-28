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

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from hathorlib.headers.base import VertexBaseHeader
from hathorlib.headers.types import VertexHeaderId
from hathorlib.serialization import Deserializer, Serializer
from hathorlib.serialization.encoding.int import decode_int, encode_int
from hathorlib.transaction.shielded_tx_output import (
    MAX_SHIELDED_OUTPUTS,
    ShieldedOutput,
    deserialize_shielded_output,
    serialize_shielded_output,
    serialize_sighash_bytes,
)

if TYPE_CHECKING:
    from hathorlib.base_transaction import BaseTransaction
    from hathorlib.transaction import Transaction


@dataclass(frozen=True)
class ShieldedOutputsHeader(VertexBaseHeader):
    tx: Transaction
    shielded_outputs: list[ShieldedOutput] = field(default_factory=list)

    @classmethod
    def deserialize(cls, tx: BaseTransaction, buf: bytes) -> tuple[ShieldedOutputsHeader, bytes]:
        """Deserialize: header_id(1) | num_outputs(1) | outputs..."""
        from hathorlib.transaction import Transaction

        if not isinstance(tx, Transaction):
            raise ValueError(
                f'shielded outputs header requires a Transaction, got {type(tx).__name__}'
            )

        deserializer = Deserializer.build_bytes_deserializer(buf)
        header_id = bytes(deserializer.read_bytes(1))
        if header_id != VertexHeaderId.SHIELDED_OUTPUTS_HEADER.value:
            raise ValueError(
                f'unexpected header id: expected {VertexHeaderId.SHIELDED_OUTPUTS_HEADER.value!r}, '
                f'got {header_id!r}'
            )

        num_outputs = decode_int(deserializer, length=1, signed=False)
        if num_outputs < 1:
            raise ValueError('shielded outputs header must contain at least 1 output')
        if num_outputs > MAX_SHIELDED_OUTPUTS:
            raise ValueError(
                f'too many shielded outputs: {num_outputs} exceeds maximum {MAX_SHIELDED_OUTPUTS}'
            )

        shielded_outputs: list[ShieldedOutput] = [
            deserialize_shielded_output(deserializer) for _ in range(num_outputs)
        ]
        leftover = bytes(deserializer.read_all())

        return cls(tx=tx, shielded_outputs=shielded_outputs), leftover

    def serialize(self) -> bytes:
        """Serialize: header_id(1) | num_outputs(1) | outputs..."""
        serializer = Serializer.build_bytes_serializer()
        serializer.write_bytes(VertexHeaderId.SHIELDED_OUTPUTS_HEADER.value)
        encode_int(serializer, len(self.shielded_outputs), length=1, signed=False)
        for output in self.shielded_outputs:
            serialize_shielded_output(serializer, output)
        return bytes(serializer.finalize())

    def get_sighash_bytes(self) -> bytes:
        """Include in sighash: header_id + count + per-output sighash bytes (no proofs)."""
        serializer = Serializer.build_bytes_serializer()
        serializer.write_bytes(VertexHeaderId.SHIELDED_OUTPUTS_HEADER.value)
        encode_int(serializer, len(self.shielded_outputs), length=1, signed=False)
        for output in self.shielded_outputs:
            serialize_sighash_bytes(serializer, output)
        return bytes(serializer.finalize())
