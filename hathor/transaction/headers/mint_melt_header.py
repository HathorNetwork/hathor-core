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

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar

from hathor.transaction.headers.base import VertexBaseHeader
from hathor.transaction.headers.types import VertexHeaderId
from hathor.transaction.util import VerboseCallback, int_to_bytes

if TYPE_CHECKING:
    from hathor.transaction.base_transaction import BaseTransaction
    from hathor.transaction.transaction import Transaction


# Per RFC 0000-shielded-outputs-mint-melt §4.1.
MAX_MINT_MELT_ENTRIES = 16
ENTRY_SIZE = 1 + 8  # token_index(1) + amount(8 BE)


@dataclass(slots=True, frozen=True)
class MintMeltEntry:
    """A single (token_index, amount) entry in a MintHeader or MeltHeader.

    Wire format: token_index(1B) | amount(8B BE).
    Constraints (enforced at deserialize-time): 1 <= token_index <= 16, amount >= 1.
    """

    token_index: int
    amount: int


def _serialize_entries(entries: list[MintMeltEntry]) -> bytes:
    parts: list[bytes] = []
    parts.append(int_to_bytes(len(entries), 1))
    for entry in entries:
        parts.append(int_to_bytes(entry.token_index, 1))
        parts.append(struct.pack('!Q', entry.amount))
    return b''.join(parts)


def _deserialize_entries(buf: bytes, *, header_name: str) -> tuple[list[MintMeltEntry], bytes]:
    """Parse `num_entries(1) | entries...`. Returns (entries, leftover).

    Wire-format level checks only: count bounds, per-entry token_index/amount bounds,
    and uniqueness of token_index within this header. Cross-header rules (Rule M3,
    bounds against tx.tokens length) are enforced later in the verifier.
    """
    from hathor.transaction.exceptions import InvalidMintMeltHeaderError

    if len(buf) < 1:
        raise InvalidMintMeltHeaderError(f'{header_name}: missing num_entries byte')
    num_entries = buf[0]
    if num_entries < 1:
        raise InvalidMintMeltHeaderError(f'{header_name}: must contain at least 1 entry')
    if num_entries > MAX_MINT_MELT_ENTRIES:
        raise InvalidMintMeltHeaderError(
            f'{header_name}: too many entries: {num_entries} exceeds maximum {MAX_MINT_MELT_ENTRIES}'
        )

    needed = 1 + num_entries * ENTRY_SIZE
    if len(buf) < needed:
        raise InvalidMintMeltHeaderError(
            f'{header_name}: requires {needed} bytes, got {len(buf)}'
        )

    entries: list[MintMeltEntry] = []
    seen_indexes: set[int] = set()
    offset = 1
    for _ in range(num_entries):
        token_index = buf[offset]
        offset += 1
        (amount,) = struct.unpack_from('!Q', buf, offset)
        offset += 8

        if token_index < 1:
            raise InvalidMintMeltHeaderError(
                f'{header_name}: token_index must be >= 1 (got {token_index}); HTR is forbidden'
            )
        if token_index > MAX_MINT_MELT_ENTRIES:
            raise InvalidMintMeltHeaderError(
                f'{header_name}: token_index {token_index} exceeds maximum {MAX_MINT_MELT_ENTRIES}'
            )
        if amount < 1:
            raise InvalidMintMeltHeaderError(
                f'{header_name}: amount must be >= 1 (got {amount})'
            )
        if token_index in seen_indexes:
            raise InvalidMintMeltHeaderError(
                f'{header_name}: duplicate token_index {token_index}'
            )
        seen_indexes.add(token_index)
        entries.append(MintMeltEntry(token_index=token_index, amount=amount))

    return entries, bytes(buf[offset:])


@dataclass(slots=True, kw_only=True)
class _MintMeltHeaderBase(VertexBaseHeader):
    """Shared deserialize/serialize/sighash logic for MintHeader and MeltHeader.

    Subclasses set `_HEADER_ID` and `_HEADER_NAME`. The wire format and entry
    constraints are identical (RFC §4.1).
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
            entries, leftover = _deserialize_entries(buf[1:], header_name=cls._HEADER_NAME)
        except InvalidMintMeltHeaderError:
            raise
        except (IndexError, struct.error, ValueError) as e:
            raise InvalidMintMeltHeaderError(f'{cls._HEADER_NAME}: malformed: {e}') from e

        if verbose:
            verbose('num_entries', len(entries))
            for i, entry in enumerate(entries):
                verbose(f'entry_{i}_token_index', entry.token_index)
                verbose(f'entry_{i}_amount', entry.amount)

        return cls(tx=tx, entries=entries), leftover

    def serialize(self) -> bytes:
        return self._HEADER_ID + _serialize_entries(self.entries)

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
