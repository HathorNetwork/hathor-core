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

from hathor.transaction.headers.base import VertexBaseHeader
from hathor.transaction.headers.types import VertexHeaderId
from hathor.transaction.shielded_tx_output import (
    MAX_SHIELDED_OUTPUTS,
    ShieldedOutput,
    deserialize_shielded_output,
    get_sighash_bytes as output_sighash_bytes,
    serialize_shielded_output,
)
from hathor.transaction.util import VerboseCallback, int_to_bytes

if TYPE_CHECKING:
    from hathor.transaction.base_transaction import BaseTransaction
    from hathor.transaction.transaction import Transaction


@dataclass(slots=True, kw_only=True)
class ShieldedOutputsHeader(VertexBaseHeader):
    @classmethod
    def get_header_id(cls) -> bytes:
        return VertexHeaderId.SHIELDED_OUTPUTS_HEADER.value

    tx: Transaction
    shielded_outputs: list[ShieldedOutput] = field(default_factory=list)

    @classmethod
    def deserialize(
        cls,
        tx: BaseTransaction,
        buf: bytes,
        *,
        verbose: VerboseCallback = None,
    ) -> tuple[ShieldedOutputsHeader, bytes]:
        """Deserialize: header_id(1) | num_outputs(1) | outputs..."""
        from hathor.transaction.exceptions import InvalidShieldedOutputError
        from hathor.transaction.transaction import Transaction

        if not isinstance(tx, Transaction):
            raise InvalidShieldedOutputError(
                f'shielded outputs header requires a Transaction, got {type(tx).__name__}'
            )

        try:
            offset = 0
            header_id = buf[offset:offset + 1]
            offset += 1
            if verbose:
                verbose('header_id', header_id)
            assert header_id == VertexHeaderId.SHIELDED_OUTPUTS_HEADER.value

            num_outputs = buf[offset]
            offset += 1
            if verbose:
                verbose('num_shielded_outputs', num_outputs)

            if num_outputs < 1:
                raise InvalidShieldedOutputError('shielded outputs header must contain at least 1 output')
            if num_outputs > MAX_SHIELDED_OUTPUTS:
                raise InvalidShieldedOutputError(
                    f'too many shielded outputs: {num_outputs} exceeds maximum {MAX_SHIELDED_OUTPUTS}'
                )

            shielded_outputs: list[ShieldedOutput] = []
            remaining = buf[offset:]
            for _ in range(num_outputs):
                output, remaining = deserialize_shielded_output(remaining)
                shielded_outputs.append(output)

        except InvalidShieldedOutputError:
            raise
        except (IndexError, struct.error, ValueError) as e:
            raise InvalidShieldedOutputError(f'malformed shielded outputs header: {e}') from e

        return cls(
            tx=tx,
            shielded_outputs=shielded_outputs,
        ), remaining

    def serialize(self) -> bytes:
        """Serialize: header_id(1) | num_outputs(1) | outputs..."""
        parts: list[bytes] = []
        parts.append(VertexHeaderId.SHIELDED_OUTPUTS_HEADER.value)
        parts.append(int_to_bytes(len(self.shielded_outputs), 1))

        for output in self.shielded_outputs:
            parts.append(serialize_shielded_output(output))

        return b''.join(parts)

    def get_sighash_bytes(self) -> bytes:
        """Include in sighash: header_id + count + per-output sighash bytes."""
        parts: list[bytes] = []
        parts.append(VertexHeaderId.SHIELDED_OUTPUTS_HEADER.value)
        parts.append(int_to_bytes(len(self.shielded_outputs), 1))

        for output in self.shielded_outputs:
            parts.append(output_sighash_bytes(output))

        return b''.join(parts)
