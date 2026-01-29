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
from enum import StrEnum, unique
from typing import TYPE_CHECKING

from typing_extensions import Self

from hathor.types import TokenUid, VertexId
from hathorlib.scripts import P2PKH, MultiSig, parse_address_script

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
    headers: tuple[HeaderData, ...]

    @classmethod
    def create_from_vertex(cls, vertex: BaseTransaction) -> Self:
        from hathor.transaction import Transaction
        from hathor.transaction.headers.nano_header import NanoHeader

        inputs = tuple(
            TxInputData.create_from_txin(txin, _get_txin_output(vertex, txin))
            for txin in vertex.inputs
        )
        outputs = tuple(TxOutputData.create_from_txout(txout) for txout in vertex.outputs)
        parents = tuple(vertex.parents)
        tokens: tuple[TokenUid, ...] = tuple()

        assert isinstance(vertex, Transaction)
        headers_data: list[HeaderData] = []
        has_nano_header = False
        for header in vertex.headers:
            if isinstance(header, NanoHeader):
                assert not has_nano_header, 'code should guarantee NanoHeader only appears once'
                headers_data.append(NanoHeaderData.create_from_nano_header(header))
                has_nano_header = True

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
            headers=tuple(headers_data),
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


@unique
class ScriptType(StrEnum):
    P2PKH = 'P2PKH'
    MULTI_SIG = 'MultiSig'


@dataclass(slots=True, frozen=True, kw_only=True)
class ScriptInfo:
    type: ScriptType
    address: str
    timelock: int | None

    @classmethod
    def from_script(cls, script: P2PKH | MultiSig) -> Self:
        return cls(
            type=ScriptType(script.get_type()),
            address=script.get_address(),
            timelock=script.get_timelock(),
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class TxOutputData:
    value: int
    raw_script: bytes
    parsed_script: ScriptInfo | None
    token_data: int

    @classmethod
    def create_from_txout(cls, txout: TxOutput) -> Self:
        parsed = parse_address_script(txout.script)
        return cls(
            value=txout.value,
            raw_script=txout.script,
            parsed_script=ScriptInfo.from_script(parsed) if parsed is not None else None,
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
    nc_seqnum: int
    nc_id: VertexId
    nc_method: str
    nc_args_bytes: bytes

    @classmethod
    def create_from_nano_header(cls, nc_header: NanoHeader) -> Self:
        return cls(
            nc_seqnum=nc_header.nc_seqnum,
            nc_id=nc_header.nc_id,
            nc_method=nc_header.nc_method,
            nc_args_bytes=nc_header.nc_args_bytes,
        )
