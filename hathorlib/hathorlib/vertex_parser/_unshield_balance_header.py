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

"""Serialization/deserialization for UnshieldBalanceHeader."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hathorlib.headers.types import VertexHeaderId
from hathorlib.headers.unshield_balance_header import EXCESS_BLINDING_FACTOR_SIZE, UnshieldBalanceHeader
from hathorlib.serialization import Deserializer, Serializer

if TYPE_CHECKING:
    from hathorlib.transaction import Transaction


def serialize_unshield_balance_header(serializer: Serializer, header: UnshieldBalanceHeader) -> None:
    """Serialize: header_id(1) | excess_blinding_factor(32)."""
    serializer.write_bytes(VertexHeaderId.UNSHIELD_BALANCE_HEADER.value)
    serializer.write_bytes(header.excess_blinding_factor)


def deserialize_unshield_balance_header(
    deserializer: Deserializer, tx: Transaction
) -> UnshieldBalanceHeader:
    """Deserialize: header_id(1) | excess_blinding_factor(32)."""
    header_id = bytes(deserializer.read_bytes(1))
    if header_id != VertexHeaderId.UNSHIELD_BALANCE_HEADER.value:
        raise ValueError(
            f'unexpected header id: expected '
            f'{VertexHeaderId.UNSHIELD_BALANCE_HEADER.value!r}, got {header_id!r}'
        )
    excess_bf = bytes(deserializer.read_bytes(EXCESS_BLINDING_FACTOR_SIZE))
    return UnshieldBalanceHeader(tx=tx, excess_blinding_factor=excess_bf)
