#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Serialization/deserialization for Block, MergeMinedBlock, and PoaBlock."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hathor.serialization import Deserializer, Serializer
from hathor.transaction.util import VerboseCallback, int_to_bytes
from hathor.transaction.vertex_parser._common import (
    _deserialize_tx_output,
    deserialize_graph_fields,
    serialize_graph_fields,
    serialize_tx_output,
)

if TYPE_CHECKING:
    from hathor.transaction.block import Block
    from hathor.transaction.poa.poa_block import PoaBlock


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def serialize_block_funds(
    serializer: Serializer,
    block: Block,
) -> None:
    """Serialize the funds fields for a Block.

    Format: signal_bits(B) + version(B) + outputs_len(B) + outputs

    Replaces the former Block.get_funds_struct().
    """
    serializer.write_struct((block.signal_bits, block.version, len(block.outputs)), '!BBB')
    for tx_output in block.outputs:
        serialize_tx_output(serializer, tx_output)


def serialize_block_graph_fields(
    serializer: Serializer,
    block: Block,
) -> None:
    """Serialize the graph fields for a Block (includes data field after parents).

    Replaces the former Block.get_graph_struct().
    """
    serialize_graph_fields(serializer, block)
    serializer.write_bytes(int_to_bytes(len(block.data), 1))
    serializer.write_bytes(block.data)


def serialize_poa_block_graph_fields(
    serializer: Serializer,
    block: PoaBlock,
) -> None:
    """Serialize the graph fields for a PoaBlock (block graph + signer_id + signature).

    Replaces the former PoaBlock.get_graph_struct().
    """
    serialize_block_graph_fields(serializer, block)
    serializer.write_bytes(block.signer_id)
    serializer.write_bytes(int_to_bytes(len(block.signature), 1))
    serializer.write_bytes(block.signature)


# ---------------------------------------------------------------------------
# Deserialization
# ---------------------------------------------------------------------------


def deserialize_block_funds(
    deserializer: Deserializer,
    block: Block,
    *,
    verbose: VerboseCallback = None,
) -> None:
    """Deserialize funds fields for a Block.

    Sets block.signal_bits, block.version, block.outputs directly.
    """
    from hathor.transaction.base_transaction import TxOutput

    (signal_bits, version, outputs_len) = deserializer.read_struct('!BBB')
    if verbose:
        verbose('signal_bits', signal_bits)
        verbose('version', version)
        verbose('outputs_len', outputs_len)

    outputs: list[TxOutput] = []
    for _ in range(outputs_len):
        txout = _deserialize_tx_output(deserializer, verbose=verbose)
        outputs.append(txout)

    block.signal_bits = signal_bits
    block.version = version
    block.outputs = outputs


def deserialize_block_graph_fields(
    deserializer: Deserializer,
    block: Block,
    *,
    verbose: VerboseCallback = None,
) -> None:
    """Deserialize graph fields for a Block (includes data field).

    Sets block.weight, block.timestamp, block.parents, block.data directly.
    """
    deserialize_graph_fields(deserializer, block, verbose=verbose)

    (data_len,) = deserializer.read_struct('!B')
    if verbose:
        verbose('data_len', data_len)
    data = bytes(deserializer.read_bytes(data_len))
    if verbose:
        verbose('data', data.hex())

    block.data = data


def deserialize_poa_block_graph_fields(
    deserializer: Deserializer,
    block: PoaBlock,
    *,
    signer_id_len: int,
    max_signature_len: int,
    verbose: VerboseCallback = None,
) -> None:
    """Deserialize graph fields for a PoaBlock (block graph + signer_id + signature).

    Sets all block graph fields plus block.signer_id, block.signature directly.
    """
    deserialize_block_graph_fields(deserializer, block, verbose=verbose)

    signer_id = bytes(deserializer.read_bytes(signer_id_len))
    if verbose:
        verbose('signer_id', signer_id.hex())

    (signature_len,) = deserializer.read_struct('!B')
    if verbose:
        verbose('signature_len', signature_len)

    if signature_len > max_signature_len:
        raise ValueError(f'invalid signature length: {signature_len}')

    signature = bytes(deserializer.read_bytes(signature_len))
    if verbose:
        verbose('signature', signature.hex())

    block.signer_id = signer_id
    block.signature = signature
