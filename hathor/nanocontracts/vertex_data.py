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

from hathor.types import TokenUid, VertexId

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction, TxInput, TxOutput, TxVersion


@dataclass(frozen=True, slots=True, kw_only=True)
class VertexData:
    version: TxVersion
    hash: bytes
    nonce: int
    signal_bits: int
    weight: float
    inputs: tuple[TxInputData, ...]
    outputs: tuple[TxOutputData, ...]
    tokens: tuple[TokenUid, ...]
    parents: tuple[VertexId, ...]

    @staticmethod
    def _get_txin_output(vertex: BaseTransaction, txin: TxInput) -> TxOutput | None:
        """Return the output that txin points to."""
        from hathor.transaction.storage.exceptions import TransactionDoesNotExist

        if vertex.storage is None:
            return None

        try:
            vertex2 = vertex.storage.get_transaction(txin.tx_id)
        except TransactionDoesNotExist:
            assert False, f'missing dependency: {txin.tx_id.hex()}'

        assert len(vertex2.outputs) > txin.index, 'invalid output index'

        txin_output = vertex2.outputs[txin.index]
        return txin_output

    @classmethod
    def create_from_vertex(cls, vertex: BaseTransaction) -> VertexData:
        inputs = tuple(
            TxInputData.create_from_txin(txin, cls._get_txin_output(vertex, txin))
            for txin in vertex.inputs
        )
        outputs = tuple(TxOutputData.create_from_txout(txout) for txout in vertex.outputs)
        parents = tuple(vertex.parents)
        tokens: tuple[TokenUid, ...] = tuple()

        original_tokens = getattr(vertex, 'tokens', None)
        if original_tokens is not None:
            # XXX Should we add HTR_TOKEN_ID as first token?
            tokens = tuple(original_tokens)

        return VertexData(
            version=vertex.version,
            hash=vertex.hash,
            nonce=vertex.nonce,
            signal_bits=vertex.signal_bits,
            weight=vertex.weight,
            inputs=inputs,
            outputs=outputs,
            tokens=tokens,
            parents=parents,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class TxInputData:
    tx_id: VertexId
    index: int
    data: bytes
    info: TxOutputData | None

    @classmethod
    def create_from_txin(cls, txin: TxInput, txin_output: TxOutput | None) -> TxInputData:
        return TxInputData(
            tx_id=txin.tx_id,
            index=txin.index,
            data=txin.data,
            info=TxOutputData.create_from_txout(txin_output) if txin_output else None,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class TxOutputData:
    value: int
    script: bytes
    token_data: int

    @classmethod
    def create_from_txout(cls, txout: TxOutput) -> TxOutputData:
        return TxOutputData(
            value=txout.value,
            script=txout.script,
            token_data=txout.token_data,
        )
