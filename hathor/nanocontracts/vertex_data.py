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
    from hathor.transaction.headers.nano_header import NanoHeader


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
    headers: tuple[HeaderData, ...]

    @classmethod
    def create_from_vertex(cls, vertex: BaseTransaction) -> Self:
        raise NotImplementedError('temporarily removed during nano merge')


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


class HeaderData:
    """Marker class, represents an arbitrary vertex-header."""


@dataclass(frozen=True, slots=True, kw_only=True)
class NanoHeaderData(HeaderData):
    nc_id: VertexId
    nc_method: str
    nc_args_bytes: bytes

    @classmethod
    def create_from_nano_header(cls, nc_header: NanoHeader) -> Self:
        return cls(
            nc_id=nc_header.nc_id,
            nc_method=nc_header.nc_method,
            nc_args_bytes=nc_header.nc_args_bytes,
        )
