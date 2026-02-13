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

"""Shared serialization/deserialization primitives for graph fields, TxInput, and TxOutput."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hathor.serialization import Deserializer, Serializer
from hathor.serialization.encoding.output_value import decode_output_value
from hathor.transaction.base_transaction import TX_HASH_SIZE
from hathor.transaction.util import VerboseCallback, int_to_bytes, output_value_to_bytes

if TYPE_CHECKING:
    from hathor.transaction.base_transaction import BaseTransaction, TxInput, TxOutput

# Weight (d=double 8 bytes), timestamp (I=uint32 4 bytes), parents_len (B=uint8 1 byte)
_GRAPH_FORMAT_STRING = '!dIB'


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def serialize_graph_fields(
    serializer: Serializer,
    vertex: BaseTransaction,
) -> None:
    """Serialize the common graph fields (weight, timestamp, parents).

    Replaces the former GenericVertex.get_graph_struct().
    """
    serializer.write_struct((vertex.weight, vertex.timestamp, len(vertex.parents)), _GRAPH_FORMAT_STRING)
    for parent in vertex.parents:
        serializer.write_bytes(parent)


def serialize_tx_input(serializer: Serializer, tx_input: TxInput) -> None:
    """Serialize a TxInput. Matches bytes(TxInput)."""
    serializer.write_bytes(tx_input.tx_id)
    serializer.write_bytes(int_to_bytes(tx_input.index, 1))
    serializer.write_bytes(int_to_bytes(len(tx_input.data), 2))
    serializer.write_bytes(tx_input.data)


def serialize_tx_input_sighash(serializer: Serializer, tx_input: TxInput) -> None:
    """Serialize a TxInput for sighash (data field cleared). Matches TxInput.get_sighash_bytes()."""
    serializer.write_bytes(tx_input.tx_id)
    serializer.write_bytes(int_to_bytes(tx_input.index, 1))
    serializer.write_bytes(int_to_bytes(0, 2))


def serialize_tx_output(serializer: Serializer, tx_output: TxOutput) -> None:
    """Serialize a TxOutput. Matches bytes(TxOutput)."""
    serializer.write_bytes(output_value_to_bytes(tx_output.value))
    serializer.write_bytes(int_to_bytes(tx_output.token_data, 1))
    serializer.write_bytes(int_to_bytes(len(tx_output.script), 2))
    serializer.write_bytes(tx_output.script)


# ---------------------------------------------------------------------------
# Deserialization
# ---------------------------------------------------------------------------


def deserialize_graph_fields(
    deserializer: Deserializer,
    vertex: BaseTransaction,
    *,
    verbose: VerboseCallback = None,
) -> None:
    """Deserialize the common graph fields (weight, timestamp, parents).

    Sets vertex.weight, vertex.timestamp, vertex.parents directly.
    """
    (weight, timestamp, parents_len) = deserializer.read_struct(_GRAPH_FORMAT_STRING)
    if verbose:
        verbose('weigth', weight)  # Note: original typo preserved for compatibility
        verbose('timestamp', timestamp)
        verbose('parents_len', parents_len)

    parents: list[bytes] = []
    for _ in range(parents_len):
        parent = bytes(deserializer.read_bytes(TX_HASH_SIZE))
        parents.append(parent)
        if verbose:
            verbose('parent', parent.hex())

    vertex.weight = weight
    vertex.timestamp = timestamp
    vertex.parents = parents


def _deserialize_tx_input(
    deserializer: Deserializer,
    *,
    verbose: VerboseCallback = None,
) -> 'TxInput':
    """Deserialize a single TxInput. Matches TxInput.create_from_bytes()."""
    from hathor.transaction.base_transaction import TxInput

    input_tx_id = bytes(deserializer.read_bytes(TX_HASH_SIZE))
    if verbose:
        verbose('txin_tx_id', input_tx_id.hex())

    (input_index, data_len) = deserializer.read_struct('!BH')
    if verbose:
        verbose('txin_index', input_index)
        verbose('txin_data_len', data_len)

    input_data = bytes(deserializer.read_bytes(data_len))
    if verbose:
        verbose('txin_data', input_data.hex())

    return TxInput(input_tx_id, input_index, input_data)


def _deserialize_tx_output(
    deserializer: Deserializer,
    *,
    verbose: VerboseCallback = None,
) -> 'TxOutput':
    """Deserialize a single TxOutput. Matches TxOutput.create_from_bytes()."""
    from hathor.serialization import BadDataError
    from hathor.transaction.base_transaction import TxOutput
    from hathor.transaction.exceptions import InvalidOutputValue

    try:
        value = decode_output_value(deserializer)
    except BadDataError as e:
        raise InvalidOutputValue(*e.args) from e
    if verbose:
        verbose('txout_value', value)

    (token_data, script_len) = deserializer.read_struct('!BH')
    if verbose:
        verbose('txout_token_data', token_data)
        verbose('txout_script_len', script_len)

    script = bytes(deserializer.read_bytes(script_len))
    if verbose:
        verbose('txout_script', script.hex())

    return TxOutput(value, script, token_data)
