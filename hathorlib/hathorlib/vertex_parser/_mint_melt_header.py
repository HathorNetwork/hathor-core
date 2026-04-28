#  Copyright 2026 Hathor Labs
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

"""Serialization/deserialization for MintHeader and MeltHeader.

Both share an identical wire format: `header_id(1) | num_entries(1) |
(token_index(1) | amount(8 BE))*N`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hathorlib.headers.mint_melt_header import (
    MAX_MINT_MELT_ENTRIES,
    MeltHeader,
    MintHeader,
    MintMeltEntry,
)
from hathorlib.headers.types import VertexHeaderId
from hathorlib.serialization import Deserializer, Serializer
from hathorlib.serialization.encoding.int import decode_int, encode_int

if TYPE_CHECKING:
    from hathorlib.transaction import Transaction


def _serialize_entries(serializer: Serializer, entries: list[MintMeltEntry]) -> None:
    """Serialize: num_entries(1) | (token_index(1) | amount(8 BE))*N."""
    encode_int(serializer, len(entries), length=1, signed=False)
    for entry in entries:
        encode_int(serializer, entry.token_index, length=1, signed=False)
        encode_int(serializer, entry.amount, length=8, signed=False)


def _deserialize_entries(
    deserializer: Deserializer,
    *,
    header_name: str,
) -> list[MintMeltEntry]:
    """Deserialize `num_entries(1) | entries...`. Returns the decoded entries.

    Wire-format level checks only: count bounds, per-entry token_index/amount
    bounds, and uniqueness of token_index within this header. Cross-header
    rules (Rule M3, bounds against tx.tokens length) are enforced later in
    the verifier.
    """
    num_entries = decode_int(deserializer, length=1, signed=False)
    if num_entries < 1:
        raise ValueError(f'{header_name}: must contain at least 1 entry')
    if num_entries > MAX_MINT_MELT_ENTRIES:
        raise ValueError(
            f'{header_name}: too many entries: {num_entries} exceeds maximum {MAX_MINT_MELT_ENTRIES}'
        )

    entries: list[MintMeltEntry] = []
    seen_indexes: set[int] = set()
    for _ in range(num_entries):
        token_index = decode_int(deserializer, length=1, signed=False)
        amount = decode_int(deserializer, length=8, signed=False)

        if token_index < 1:
            raise ValueError(
                f'{header_name}: token_index must be >= 1 (got {token_index}); HTR is forbidden'
            )
        if token_index > MAX_MINT_MELT_ENTRIES:
            raise ValueError(
                f'{header_name}: token_index {token_index} exceeds maximum {MAX_MINT_MELT_ENTRIES}'
            )
        if amount < 1:
            raise ValueError(
                f'{header_name}: amount must be >= 1 (got {amount})'
            )
        if token_index in seen_indexes:
            raise ValueError(
                f'{header_name}: duplicate token_index {token_index}'
            )
        seen_indexes.add(token_index)
        entries.append(MintMeltEntry(token_index=token_index, amount=amount))

    return entries


def _read_and_check_header_id(
    deserializer: Deserializer, *, expected: bytes, header_name: str
) -> None:
    actual = bytes(deserializer.read_bytes(1))
    if actual != expected:
        raise ValueError(
            f'{header_name}: unexpected header id: expected {expected!r}, got {actual!r}'
        )


def serialize_mint_header(serializer: Serializer, header: MintHeader) -> None:
    serializer.write_bytes(VertexHeaderId.MINT_HEADER.value)
    _serialize_entries(serializer, header.entries)


def serialize_melt_header(serializer: Serializer, header: MeltHeader) -> None:
    serializer.write_bytes(VertexHeaderId.MELT_HEADER.value)
    _serialize_entries(serializer, header.entries)


def deserialize_mint_header(deserializer: Deserializer, tx: Transaction) -> MintHeader:
    _read_and_check_header_id(
        deserializer, expected=VertexHeaderId.MINT_HEADER.value, header_name='MintHeader',
    )
    entries = _deserialize_entries(deserializer, header_name='MintHeader')
    return MintHeader(tx=tx, entries=entries)


def deserialize_melt_header(deserializer: Deserializer, tx: Transaction) -> MeltHeader:
    _read_and_check_header_id(
        deserializer, expected=VertexHeaderId.MELT_HEADER.value, header_name='MeltHeader',
    )
    entries = _deserialize_entries(deserializer, header_name='MeltHeader')
    return MeltHeader(tx=tx, entries=entries)
