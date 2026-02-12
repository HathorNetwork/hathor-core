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

"""Serialization/deserialization for TokenCreationTransaction."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hathor.serialization import Deserializer, Serializer
from hathor.transaction.util import VerboseCallback, decode_string_utf8
from hathor.transaction.vertex_parser._common import (
    _deserialize_tx_input,
    _deserialize_tx_output,
    serialize_tx_input,
    serialize_tx_input_sighash,
    serialize_tx_output,
)

if TYPE_CHECKING:
    from hathor.transaction.token_creation_tx import TokenCreationTransaction


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def serialize_token_creation_funds(
    serializer: Serializer,
    tx: TokenCreationTransaction,
) -> None:
    """Serialize the funds fields for a TokenCreationTransaction.

    Format: signal_bits(B) + version(B) + inputs_len(B) + outputs_len(B)
            + inputs + outputs + token_info

    This matches the output of TokenCreationTransaction.get_funds_struct().
    """
    serializer.write_struct(
        (tx.signal_bits, tx.version, len(tx.inputs), len(tx.outputs)),
        '!BBBB',
    )
    for tx_input in tx.inputs:
        serialize_tx_input(serializer, tx_input)
    for tx_output in tx.outputs:
        serialize_tx_output(serializer, tx_output)
    serializer.write_bytes(_serialize_token_info(tx))


def serialize_token_creation_sighash(
    serializer: Serializer,
    tx: TokenCreationTransaction,
    *,
    headers_sighash: list[bytes],
) -> None:
    """Serialize the sighash for a TokenCreationTransaction.

    This matches the output of TokenCreationTransaction.get_sighash_all().
    """
    serializer.write_struct(
        (tx.signal_bits, tx.version, len(tx.inputs), len(tx.outputs)),
        '!BBBB',
    )
    for tx_input in tx.inputs:
        serialize_tx_input_sighash(serializer, tx_input)
    for tx_output in tx.outputs:
        serialize_tx_output(serializer, tx_output)
    serializer.write_bytes(_serialize_token_info(tx))
    for header_bytes in headers_sighash:
        serializer.write_bytes(header_bytes)


# ---------------------------------------------------------------------------
# Deserialization
# ---------------------------------------------------------------------------


def deserialize_token_creation_funds(
    deserializer: Deserializer,
    tx: TokenCreationTransaction,
    *,
    verbose: VerboseCallback = None,
) -> None:
    """Deserialize funds fields for a TokenCreationTransaction.

    Sets tx.signal_bits, tx.version, tx.inputs, tx.outputs, tx.token_name,
    tx.token_symbol, tx.token_version directly.
    """
    from hathor.transaction.base_transaction import TxInput, TxOutput
    from hathor.transaction.token_info import TokenVersion

    (signal_bits, version, inputs_len, outputs_len) = deserializer.read_struct('!BBBB')
    if verbose:
        verbose('signal_bits', signal_bits)
        verbose('version', version)
        verbose('inputs_len', inputs_len)
        verbose('outputs_len', outputs_len)

    inputs: list[TxInput] = []
    for _ in range(inputs_len):
        txin = _deserialize_tx_input(deserializer, verbose=verbose)
        inputs.append(txin)

    outputs: list[TxOutput] = []
    for _ in range(outputs_len):
        txout = _deserialize_tx_output(deserializer, verbose=verbose)
        outputs.append(txout)

    # Token info
    (raw_token_version,) = deserializer.read_struct('!B')
    if verbose:
        verbose('token_version', raw_token_version)

    try:
        token_version = TokenVersion(raw_token_version)
    except ValueError:
        raise ValueError('unknown token version: {}'.format(raw_token_version))

    (name_len,) = deserializer.read_struct('!B')
    if verbose:
        verbose('token_name_len', name_len)
    name = bytes(deserializer.read_bytes(name_len))
    if verbose:
        verbose('token_name', name)
    (symbol_len,) = deserializer.read_struct('!B')
    if verbose:
        verbose('token_symbol_len', symbol_len)
    symbol = bytes(deserializer.read_bytes(symbol_len))
    if verbose:
        verbose('token_symbol', symbol)

    decoded_name = decode_string_utf8(name, 'Token name')
    decoded_symbol = decode_string_utf8(symbol, 'Token symbol')

    tx.signal_bits = signal_bits
    tx.version = version
    tx.inputs = inputs
    tx.outputs = outputs
    tx.token_name = decoded_name
    tx.token_symbol = decoded_symbol
    tx.token_version = token_version


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _serialize_token_info(tx: TokenCreationTransaction) -> bytes:
    """Serialize token info (version, name, symbol) to bytes."""
    from hathor.transaction.util import int_to_bytes

    encoded_name = tx.token_name.encode('utf-8')
    encoded_symbol = tx.token_symbol.encode('utf-8')

    ret = b''
    ret += int_to_bytes(tx.token_version, 1)
    ret += int_to_bytes(len(encoded_name), 1)
    ret += encoded_name
    ret += int_to_bytes(len(encoded_symbol), 1)
    ret += encoded_symbol
    return ret
