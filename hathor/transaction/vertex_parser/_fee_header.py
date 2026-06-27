# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Serialization/deserialization for FeeHeader."""

from __future__ import annotations

from hathor.serialization import Deserializer, Serializer
from hathor.serialization.encoding.output_value import decode_output_value
from hathor.transaction.headers.fee_header import FeeHeader, FeeHeaderEntry
from hathor.transaction.headers.types import VertexHeaderId
from hathor.transaction.util import VerboseCallback, int_to_bytes
from hathorlib.serialization.encoding.output_value import encode_output_value
from hathorlib.token_amount_version import TokenAmountVersion

# ---------------------------------------------------------------------------
# Deserialization
# ---------------------------------------------------------------------------


def deserialize_fee_header(
    deserializer: Deserializer,
    *,
    token_amount_version: TokenAmountVersion,
    verbose: VerboseCallback = None,
) -> list[FeeHeaderEntry]:
    """Deserialize fee header data from the deserializer."""
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
        amount = decode_output_value(deserializer, token_amount_version=token_amount_version)
        fees.append(FeeHeaderEntry(
            token_index=token_index,
            amount=amount,
        ))

    return fees


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def serialize_fee_header(
    serializer: Serializer,
    header: FeeHeader,
    *,
    token_amount_version: TokenAmountVersion,
) -> None:
    """Serialize a FeeHeader into the serializer."""
    serializer.write_bytes(VertexHeaderId.FEE_HEADER.value)
    serializer.write_bytes(int_to_bytes(len(header.fees), 1))

    for fee in header.fees:
        serializer.write_bytes(int_to_bytes(fee.token_index, 1))
        encode_output_value(serializer, fee.amount, token_amount_version=token_amount_version)
