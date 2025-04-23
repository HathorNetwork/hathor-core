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

from typing_extensions import Self

from hathor.types import TokenUid, VertexId

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction, Block, TxInput, TxOutput, TxVersion


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
    block: BlockData

    @classmethod
    def create_from_vertex(cls, vertex: BaseTransaction) -> Self:
        inputs = tuple(
            TxInputData.create_from_txin(txin, _get_txin_output(vertex, txin))
            for txin in vertex.inputs
        )
        outputs = tuple(TxOutputData.create_from_txout(txout) for txout in vertex.outputs)
        parents = tuple(vertex.parents)
        tokens: tuple[TokenUid, ...] = tuple()
        vertex_meta = vertex.get_metadata()
        if vertex_meta.first_block is not None:
            assert vertex.storage is not None
            assert vertex_meta.first_block is not None
            block = vertex.storage.get_block(vertex_meta.first_block)
            block_data = BlockData.create_from_block(block)
        else:
            # XXX: use dummy data instead
            block_data = BlockData(hash=VertexId(b''), timestamp=0, height=0)

        original_tokens = getattr(vertex, 'tokens', None)
        if original_tokens is not None:
            # XXX Should we add HTR_TOKEN_ID as first token?
            tokens = tuple(original_tokens)

        return cls(
            version=vertex.version,
            hash=vertex.hash,
            nonce=vertex.nonce,
            signal_bits=vertex.signal_bits,
            weight=vertex.weight,
            inputs=inputs,
            outputs=outputs,
            tokens=tokens,
            parents=parents,
            block=block_data,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class TxInputData:
    tx_id: VertexId
    index: int
    data: bytes
    info: TxOutputData | None

    @classmethod
    def create_from_txin(cls, txin: TxInput, txin_output: TxOutput | None) -> Self:
        return cls(
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
    def create_from_txout(cls, txout: TxOutput) -> Self:
        return cls(
            value=txout.value,
            script=txout.script,
            token_data=txout.token_data,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class BlockData:
    hash: VertexId
    timestamp: int
    height: int

    @classmethod
    def create_from_block(cls, block: Block) -> Self:
        return cls(
            hash=block.hash,
            timestamp=block.timestamp,
            height=block.get_height(),
        )
