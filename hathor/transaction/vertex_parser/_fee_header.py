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

"""Serialization/deserialization for FeeHeader."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hathor.serialization import Deserializer, Serializer
from hathor.serialization.encoding.output_value import decode_output_value, encode_output_value
from hathor.transaction.headers.fee_header import FeeHeader, FeeHeaderEntry
from hathor.transaction.headers.types import VertexHeaderId
from hathor.transaction.util import VerboseCallback, int_to_bytes

if TYPE_CHECKING:
    from hathor.transaction.base_transaction import BaseTransaction


# ---------------------------------------------------------------------------
# Deserialization
# ---------------------------------------------------------------------------


def deserialize_fee_header(
    deserializer: Deserializer,
    tx: BaseTransaction,
    *,
    verbose: VerboseCallback = None,
) -> FeeHeader:
    """Deserialize a FeeHeader from the deserializer."""
    from hathor.transaction import Transaction
    assert isinstance(tx, Transaction)

    header_id = bytes(deserializer.read_bytes(1))
    if verbose:
        verbose('header_id', header_id)
    assert header_id == VertexHeaderId.FEE_HEADER.value

    fees: list[FeeHeaderEntry] = []
    fees_len = deserializer.read_byte()
    if verbose:
        verbose('fees_len', fees_len)
    for _ in range(fees_len):
        token_index = deserializer.read_byte()
        amount = decode_output_value(deserializer)
        fees.append(FeeHeaderEntry(
            token_index=token_index,
            amount=amount,
        ))

    return FeeHeader(
        settings=tx._settings,
        tx=tx,
        fees=fees,
    )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def serialize_fee_header(serializer: Serializer, header: FeeHeader) -> None:
    """Serialize a FeeHeader into the serializer."""
    serializer.write_bytes(VertexHeaderId.FEE_HEADER.value)
    serializer.write_bytes(int_to_bytes(len(header.fees), 1))

    for fee in header.fees:
        serializer.write_bytes(int_to_bytes(fee.token_index, 1))
        encode_output_value(serializer, fee.amount)
