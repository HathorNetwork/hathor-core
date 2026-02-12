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

"""Serialization/deserialization for Transaction (also used by OnChainBlueprint)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hathor.serialization import Deserializer, Serializer
from hathor.transaction.base_transaction import TX_HASH_SIZE
from hathor.transaction.util import VerboseCallback
from hathor.transaction.vertex_parser._common import (
    _deserialize_tx_input,
    _deserialize_tx_output,
    serialize_tx_input,
    serialize_tx_input_sighash,
    serialize_tx_output,
)

if TYPE_CHECKING:
    from hathor.transaction.transaction import Transaction


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def serialize_tx_funds(
    serializer: Serializer,
    tx: Transaction,
) -> None:
    """Serialize the funds fields for a Transaction.

    Format: signal_bits(B) + version(B) + tokens_len(B) + inputs_len(B) + outputs_len(B)
            + token_uids + inputs + outputs

    This matches the output of Transaction.get_funds_struct().
    """
    serializer.write_struct(
        (tx.signal_bits, tx.version, len(tx.tokens), len(tx.inputs), len(tx.outputs)),
        '!BBBBB',
    )
    for token_uid in tx.tokens:
        serializer.write_bytes(token_uid)
    for tx_input in tx.inputs:
        serialize_tx_input(serializer, tx_input)
    for tx_output in tx.outputs:
        serialize_tx_output(serializer, tx_output)


def serialize_tx_sighash(
    serializer: Serializer,
    tx: Transaction,
    *,
    headers_sighash: list[bytes],
) -> None:
    """Serialize the sighash for a Transaction.

    Same as funds but with input data cleared, plus header sighash bytes.
    This matches the output of Transaction.get_sighash_all().
    """
    serializer.write_struct(
        (tx.signal_bits, tx.version, len(tx.tokens), len(tx.inputs), len(tx.outputs)),
        '!BBBBB',
    )
    for token_uid in tx.tokens:
        serializer.write_bytes(token_uid)
    for tx_input in tx.inputs:
        serialize_tx_input_sighash(serializer, tx_input)
    for tx_output in tx.outputs:
        serialize_tx_output(serializer, tx_output)
    for header_bytes in headers_sighash:
        serializer.write_bytes(header_bytes)


# ---------------------------------------------------------------------------
# Deserialization
# ---------------------------------------------------------------------------


def deserialize_tx_funds(
    deserializer: Deserializer,
    tx: Transaction,
    *,
    verbose: VerboseCallback = None,
) -> None:
    """Deserialize funds fields for a Transaction.

    Sets tx.signal_bits, tx.version, tx.tokens, tx.inputs, tx.outputs directly.
    """
    from hathor.transaction.base_transaction import TxInput, TxOutput

    (signal_bits, version, tokens_len, inputs_len, outputs_len) = deserializer.read_struct('!BBBBB')
    if verbose:
        verbose('signal_bits', signal_bits)
        verbose('version', version)
        verbose('tokens_len', tokens_len)
        verbose('inputs_len', inputs_len)
        verbose('outputs_len', outputs_len)

    tokens: list[bytes] = []
    for _ in range(tokens_len):
        token_uid = bytes(deserializer.read_bytes(TX_HASH_SIZE))
        tokens.append(token_uid)
        if verbose:
            verbose('token_uid', token_uid.hex())

    inputs: list[TxInput] = []
    for _ in range(inputs_len):
        txin = _deserialize_tx_input(deserializer, verbose=verbose)
        inputs.append(txin)

    outputs: list[TxOutput] = []
    for _ in range(outputs_len):
        txout = _deserialize_tx_output(deserializer, verbose=verbose)
        outputs.append(txout)

    tx.signal_bits = signal_bits
    tx.version = version
    tx.tokens = tokens
    tx.inputs = inputs
    tx.outputs = outputs
