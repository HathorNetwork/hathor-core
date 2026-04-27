# Copyright 2026 Hathor Labs
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

"""MintHeader/MeltHeader for shielded transactions.

The wire format and per-entry validation live in
`hathorlib.headers.mint_melt_header`. This module re-exports the shared
`MintMeltEntry` plus thin hathor-core subclasses whose `deserialize` raises
the consensus-typed `InvalidMintMeltHeaderError` and whose `tx` field is
typed against hathor-core's `Transaction`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar

from hathor.transaction.headers.base import VertexBaseHeader
from hathor.transaction.headers.types import VertexHeaderId
from hathor.transaction.util import VerboseCallback
from hathorlib.headers.mint_melt_header import (
    ENTRY_SIZE,
    MAX_MINT_MELT_ENTRIES,
    MintMeltEntry,
    deserialize_entries,
    serialize_entries,
)

if TYPE_CHECKING:
    from hathor.transaction.base_transaction import BaseTransaction
    from hathor.transaction.transaction import Transaction


__all__ = [
    'ENTRY_SIZE',
    'MAX_MINT_MELT_ENTRIES',
    'MintMeltEntry',
    'MintHeader',
    'MeltHeader',
]


@dataclass(slots=True, kw_only=True)
class _MintMeltHeaderBase(VertexBaseHeader):
    """Shared deserialize/serialize/sighash logic for MintHeader and MeltHeader.

    Subclasses set `_HEADER_ID` and `_HEADER_NAME`. The wire format and entry
    constraints are identical (RFC §4.1).

    Design note: a single header carries a list of (token_index, amount)
    entries rather than spreading entries across multiple headers. The
    codebase enforces one-instance-per-header-type (see `verify_headers` in
    `vertex_verifier.py`) and a strict ascending canonical order on header
    IDs, so allowing repeated MintHeader/MeltHeader instances would require
    relaxing those invariants. Bundling the entries keeps the canonical-order
    rule intact and the per-entry uniqueness check local to the header.
    """

    _HEADER_ID: ClassVar[bytes] = b''
    _HEADER_NAME: ClassVar[str] = ''

    tx: Transaction
    entries: list[MintMeltEntry] = field(default_factory=list)

    @classmethod
    def get_header_id(cls) -> bytes:
        return cls._HEADER_ID

    @classmethod
    def deserialize(
        cls,
        tx: BaseTransaction,
        buf: bytes,
        *,
        verbose: VerboseCallback = None,
    ) -> tuple[_MintMeltHeaderBase, bytes]:
        from hathor.transaction.exceptions import InvalidMintMeltHeaderError
        from hathor.transaction.transaction import Transaction

        if not isinstance(tx, Transaction):
            raise InvalidMintMeltHeaderError(
                f'{cls._HEADER_NAME} requires a Transaction, got {type(tx).__name__}'
            )

        if len(buf) < 1:
            raise InvalidMintMeltHeaderError(f'{cls._HEADER_NAME}: empty buffer')
        header_id = buf[0:1]
        if verbose:
            verbose('header_id', header_id)
        if header_id != cls._HEADER_ID:
            raise InvalidMintMeltHeaderError(
                f'{cls._HEADER_NAME}: unexpected header id: expected {cls._HEADER_ID!r}, got {header_id!r}'
            )

        try:
            entries, leftover = deserialize_entries(buf[1:], header_name=cls._HEADER_NAME)
        except ValueError as e:
            raise InvalidMintMeltHeaderError(str(e)) from e
        except (IndexError, struct.error) as e:
            raise InvalidMintMeltHeaderError(f'{cls._HEADER_NAME}: malformed: {e}') from e

        if verbose:
            verbose('num_entries', len(entries))
            for i, entry in enumerate(entries):
                verbose(f'entry_{i}_token_index', entry.token_index)
                verbose(f'entry_{i}_amount', entry.amount)

        return cls(tx=tx, entries=entries), leftover

    def serialize(self) -> bytes:
        return self._HEADER_ID + serialize_entries(self.entries)

    def get_sighash_bytes(self) -> bytes:
        # Full serialization is bound to the signature: any mutation to the
        # declared mint/melt amounts invalidates all signatures over the tx.
        return self.serialize()


@dataclass(slots=True, kw_only=True)
class MintHeader(_MintMeltHeaderBase):
    """Publicly declares per-token supply created by this shielded transaction."""

    _HEADER_ID: ClassVar[bytes] = VertexHeaderId.MINT_HEADER.value
    _HEADER_NAME: ClassVar[str] = 'MintHeader'


@dataclass(slots=True, kw_only=True)
class MeltHeader(_MintMeltHeaderBase):
    """Publicly declares per-token supply destroyed by this shielded transaction."""

    _HEADER_ID: ClassVar[bytes] = VertexHeaderId.MELT_HEADER.value
    _HEADER_NAME: ClassVar[str] = 'MeltHeader'
