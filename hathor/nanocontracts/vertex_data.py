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

from typing import TYPE_CHECKING

from hathor.transaction.scripts import P2PKH, MultiSig, parse_address_script
from hathorlib.nanocontracts.types import VertexId

# Re-export from hathorlib for backward compatibility
from hathorlib.nanocontracts.vertex_data import *  # noqa: F401,F403
from hathorlib.nanocontracts.vertex_data import (  # noqa: F401
    BlockData,
    HeaderData,
    NanoHeaderData,
    ScriptInfo,
    ScriptType,
    TokenUid,
    TxInputData,
    TxOutputData,
    VertexData,
)

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction, Block, TxInput, TxOutput
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


def create_script_info_from_script(script: P2PKH | MultiSig) -> ScriptInfo:
    """Create a ScriptInfo from a parsed script object."""
    return ScriptInfo(
        type=ScriptType(script.get_type()),
        address=script.get_address(),
        timelock=script.get_timelock(),
    )


def create_txoutput_data_from_txout(txout: TxOutput) -> TxOutputData:
    """Create a TxOutputData from a TxOutput."""
    parsed = parse_address_script(txout.script)
    return TxOutputData(
        value=txout.value,
        raw_script=txout.script,
        parsed_script=create_script_info_from_script(parsed) if parsed is not None else None,
        token_data=txout.token_data,
    )


def create_txinput_data_from_txin(txin: TxInput, txin_output: TxOutput | None) -> TxInputData:
    """Create a TxInputData from a TxInput and its corresponding output."""
    return TxInputData(
        tx_id=VertexId(txin.tx_id),
        index=txin.index,
        data=txin.data,
        info=create_txoutput_data_from_txout(txin_output) if txin_output else None,
    )


def create_nano_header_data_from_nano_header(nc_header: NanoHeader) -> NanoHeaderData:
    """Create a NanoHeaderData from a NanoHeader."""
    return NanoHeaderData(
        nc_seqnum=nc_header.nc_seqnum,
        nc_id=VertexId(nc_header.nc_id),
        nc_method=nc_header.nc_method,
        nc_args_bytes=nc_header.nc_args_bytes,
    )


def create_block_data_from_block(block: Block) -> BlockData:
    """Create a BlockData from a Block."""
    return BlockData(
        hash=VertexId(block.hash),
        timestamp=block.timestamp,
        height=block.get_height(),
    )


def create_vertex_data_from_vertex(vertex: BaseTransaction) -> VertexData:
    """Create a VertexData from a transaction vertex."""
    from hathor.transaction import Transaction
    from hathor.transaction.headers.nano_header import NanoHeader

    inputs = tuple(
        create_txinput_data_from_txin(txin, _get_txin_output(vertex, txin))
        for txin in vertex.inputs
    )
    outputs = tuple(create_txoutput_data_from_txout(txout) for txout in vertex.outputs)
    parents = tuple([VertexId(p) for p in vertex.parents])
    tokens: tuple[TokenUid, ...] = tuple()

    assert isinstance(vertex, Transaction)
    headers_data: list[HeaderData] = []
    has_nano_header = False
    for header in vertex.headers:
        if isinstance(header, NanoHeader):
            assert not has_nano_header, 'code should guarantee NanoHeader only appears once'
            headers_data.append(create_nano_header_data_from_nano_header(header))
            has_nano_header = True

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
        headers=tuple(headers_data),
    )
