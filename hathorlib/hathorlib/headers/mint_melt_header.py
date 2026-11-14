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

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar

from hathorlib.headers.base import VertexBaseHeader
from hathorlib.headers.types import VertexHeaderId
from hathorlib.utils import int_to_bytes

if TYPE_CHECKING:
    from hathorlib.base_transaction import BaseTransaction
    from hathorlib.serialization import Deserializer, Serializer


# Per RFC 0000-shielded-outputs-mint-melt §4.1.
MAX_MINT_MELT_ENTRIES = 16
AMOUNT_SIZE = 8  # amount is a u64, big-endian
# Exclusive upper bound on a mint/melt amount: a u64 (matches AMOUNT_SIZE).
# NOTE: once shielded range proofs land, this should be tightened to the
# range-proof bit width (MAX_AMOUNT = 2 ** RANGE_PROOF_BITS), since a hidden
# value is always capped by the proof. RANGE_PROOF_BITS isn't defined on this
# branch yet, so the u64 wire bound stands for now.
MAX_AMOUNT = 2 ** 64


@dataclass(frozen=True, slots=True, kw_only=True)
class MintMeltEntry:
    """A single (token_index, amount) entry in a MintHeader or MeltHeader.

    Wire format: token_index(1B) | amount(8B BE).

    The strict positive amount bound (1 <= amount < 2**64) is what lets us
    skip a range proof on these headers: by construction the declared scalar
    cannot encode a negative or zero supply change, so it cannot be used to
    sneak a negative value into the Pedersen-augmented balance equation.
    Validated at construction so programmatic builders fail fast at the call
    site, and again at deserialize-time via this same constructor.
    """

    token_index: int
    amount: int

    def __post_init__(self) -> None:
        if not (1 <= self.token_index <= MAX_MINT_MELT_ENTRIES):
            raise ValueError(
                f'token_index must be in [1, {MAX_MINT_MELT_ENTRIES}]; got {self.token_index}'
            )
        if not (1 <= self.amount < MAX_AMOUNT):
            raise ValueError(f'amount must be in [1, {MAX_AMOUNT}); got {self.amount}')


def serialize_entries(serializer: Serializer, entries: list[MintMeltEntry]) -> None:
    """Serialize `num_entries(1) | (token_index(1) | amount(8 BE))...` into the serializer."""
    serializer.write_bytes(int_to_bytes(len(entries), 1))
    for entry in entries:
        serializer.write_bytes(int_to_bytes(entry.token_index, 1))
        serializer.write_bytes(int_to_bytes(entry.amount, AMOUNT_SIZE))


def deserialize_entries(deserializer: Deserializer, *, header_name: str) -> list[MintMeltEntry]:
    """Parse `num_entries(1) | entries...` from the deserializer.

    Wire-format level checks only: count bounds, per-entry token_index/amount
    bounds (via MintMeltEntry), and uniqueness of token_index within this
    header. Cross-header rules (M2/M3, bounds against tx.tokens length) are
    enforced later in the verifier.
    """
    num_entries = deserializer.read_byte()
    if num_entries < 1:
        raise ValueError(f'{header_name}: must contain at least 1 entry')
    if num_entries > MAX_MINT_MELT_ENTRIES:
        raise ValueError(
            f'{header_name}: too many entries: {num_entries} exceeds maximum {MAX_MINT_MELT_ENTRIES}'
        )

    entries: list[MintMeltEntry] = []
    seen_indexes: set[int] = set()
    for _ in range(num_entries):
        token_index = deserializer.read_byte()
        amount = int.from_bytes(bytes(deserializer.read_bytes(AMOUNT_SIZE)), 'big')
        if token_index in seen_indexes:
            raise ValueError(f'{header_name}: duplicate token_index {token_index}')
        seen_indexes.add(token_index)
        # MintMeltEntry enforces the token_index/amount bounds.
        entries.append(MintMeltEntry(token_index=token_index, amount=amount))

    return entries


@dataclass(frozen=True, slots=True)
class _MintMeltHeaderBase(VertexBaseHeader):
    """Shared (de)serialization for MintHeader and MeltHeader.

    Subclasses set `_HEADER_ID` and `_HEADER_NAME`. The wire format and entry
    constraints are identical (RFC §4.1).

    Design note: a single header carries a list of (token_index, amount)
    entries rather than spreading entries across multiple headers. The codebase
    enforces one-instance-per-header-type (see verify_headers in hathor-core's
    vertex_verifier), so allowing repeated MintHeader/MeltHeader instances would
    require relaxing that invariant. Bundling the entries keeps the per-entry
    uniqueness check local to the header.
    """

    _HEADER_ID: ClassVar[bytes] = b''
    _HEADER_NAME: ClassVar[str] = ''

    entries: list[MintMeltEntry] = field(default_factory=list)

    # These three concrete overrides exist only to satisfy the VertexBaseHeader
    # ABC; they are intentionally unused. The real (de)serialization is driven
    # through the framework by hathor-core's free functions in
    # ``_mint_melt_header.py``, which delegate to the module-level
    # ``serialize_entries`` / ``deserialize_entries`` helpers above. A future PR
    # should drop these from the base interface entirely (see PR #1730 review).

    @classmethod
    def deserialize(cls, tx: BaseTransaction, buf: bytes) -> tuple[_MintMeltHeaderBase, bytes]:
        raise NotImplementedError

    def serialize(self) -> bytes:
        raise NotImplementedError

    def get_sighash_bytes(self) -> bytes:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class MintHeader(_MintMeltHeaderBase):
    """Publicly declares per-token supply created by this shielded transaction."""

    _HEADER_ID: ClassVar[bytes] = VertexHeaderId.MINT_HEADER.value
    _HEADER_NAME: ClassVar[str] = 'MintHeader'


@dataclass(frozen=True, slots=True)
class MeltHeader(_MintMeltHeaderBase):
    """Publicly declares per-token supply destroyed by this shielded transaction."""

    _HEADER_ID: ClassVar[bytes] = VertexHeaderId.MELT_HEADER.value
    _HEADER_NAME: ClassVar[str] = 'MeltHeader'
