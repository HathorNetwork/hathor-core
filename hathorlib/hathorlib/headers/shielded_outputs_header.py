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

import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from hathorlib.headers.base import VertexBaseHeader
from hathorlib.headers.types import VertexHeaderId
from hathorlib.transaction.shielded_tx_output import (
    MAX_SHIELDED_OUTPUTS,
    ShieldedOutput,
    deserialize_shielded_output,
    get_sighash_bytes as output_sighash_bytes,
    serialize_shielded_output,
)
from hathorlib.utils import int_to_bytes

if TYPE_CHECKING:
    from hathorlib.base_transaction import BaseTransaction


@dataclass(frozen=True)
class ShieldedOutputsHeader(VertexBaseHeader):
    shielded_outputs: list[ShieldedOutput] = field(default_factory=list)

    @classmethod
    def deserialize(cls, tx: BaseTransaction, buf: bytes) -> tuple[ShieldedOutputsHeader, bytes]:
        """Deserialize: header_id(1) | num_outputs(1) | outputs..."""
        from hathorlib.serialization import Deserializer
        from hathorlib.transaction import Transaction

        if not isinstance(tx, Transaction):
            raise ValueError(
                f'shielded outputs header requires a Transaction, got {type(tx).__name__}'
            )

        deserializer = Deserializer.build_bytes_deserializer(buf)
        try:
            header_id = bytes(deserializer.read_bytes(1))
            assert header_id == VertexHeaderId.SHIELDED_OUTPUTS_HEADER.value

            num_outputs = deserializer.read_byte()
            if num_outputs < 1:
                raise ValueError('shielded outputs header must contain at least 1 output')
            if num_outputs > MAX_SHIELDED_OUTPUTS:
                raise ValueError(
                    f'too many shielded outputs: {num_outputs} exceeds maximum {MAX_SHIELDED_OUTPUTS}'
                )

            shielded_outputs: list[ShieldedOutput] = [
                deserialize_shielded_output(deserializer) for _ in range(num_outputs)
            ]

        except (ValueError, AssertionError):
            raise
        except (IndexError, struct.error) as e:
            # OutOfDataError (truncation) is a struct.error subclass, caught here.
            raise ValueError(f'malformed shielded outputs header: {e}') from e

        # Whatever follows this header (subsequent headers) is the unconsumed leftover.
        remaining = bytes(deserializer.read_all())
        return cls(shielded_outputs=shielded_outputs), remaining

    def serialize(self) -> bytes:
        """Serialize: header_id(1) | num_outputs(1) | outputs..."""
        from hathorlib.serialization import Serializer

        serializer = Serializer.build_bytes_serializer()
        serializer.write_bytes(VertexHeaderId.SHIELDED_OUTPUTS_HEADER.value)
        serializer.write_bytes(int_to_bytes(len(self.shielded_outputs), 1))
        for output in self.shielded_outputs:
            serialize_shielded_output(serializer, output)
        return bytes(serializer.finalize())

    def get_sighash_bytes(self) -> bytes:
        """Include in sighash: header_id + count + per-output sighash bytes."""
        parts: list[bytes] = []
        parts.append(VertexHeaderId.SHIELDED_OUTPUTS_HEADER.value)
        parts.append(int_to_bytes(len(self.shielded_outputs), 1))

        for output in self.shielded_outputs:
            parts.append(output_sighash_bytes(output))

        return b''.join(parts)
