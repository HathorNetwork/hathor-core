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
from typing import TYPE_CHECKING

from hathorlib.headers.base import VertexBaseHeader

if TYPE_CHECKING:
    from hathorlib.transaction import Transaction


# Per RFC 0000-shielded-outputs-mint-melt §4.1.
MAX_MINT_MELT_ENTRIES = 16


@dataclass(frozen=True)
class MintMeltEntry:
    """A single (token_index, amount) entry in a MintHeader or MeltHeader.

    Wire format: token_index(1B) | amount(8B BE).

    The strict positive amount bound (1 <= amount < 2**64) is what lets us
    skip a range proof on these headers: by construction the declared scalar
    cannot encode a negative or zero supply change, so it cannot be used to
    sneak a negative value into the Pedersen-augmented balance equation.
    Validated both at construction and at deserialize-time so programmatic
    builders fail fast at the call site rather than at serialize time.
    """

    token_index: int
    amount: int

    def __post_init__(self) -> None:
        if not 1 <= self.token_index <= MAX_MINT_MELT_ENTRIES:
            raise ValueError(
                f'token_index must be in [1, {MAX_MINT_MELT_ENTRIES}]; got {self.token_index}'
            )
        if not 1 <= self.amount < 2 ** 64:
            raise ValueError(f'amount must be in [1, 2**64); got {self.amount}')


@dataclass(frozen=True)
class MintHeader(VertexBaseHeader):
    """Publicly declares per-token supply created by this shielded transaction.

    Design note: a single header carries a list of (token_index, amount)
    entries rather than spreading entries across multiple headers. The
    codebase enforces one-instance-per-header-type (see verify_headers in
    hathor-core's vertex_verifier) and a strict ascending canonical order on
    header IDs, so allowing repeated MintHeader/MeltHeader instances would
    require relaxing those invariants. Bundling the entries keeps the
    canonical-order rule intact and the per-entry uniqueness check local to
    the header.

    Wire-format (de)serialization lives in
    ``hathorlib.vertex_parser._mint_melt_header``; the inherited
    ``serialize``/``deserialize``/``get_sighash_bytes`` methods route
    through the central dispatcher in ``hathorlib.vertex_parser._headers``.
    """

    tx: Transaction
    entries: list[MintMeltEntry] = field(default_factory=list)


@dataclass(frozen=True)
class MeltHeader(VertexBaseHeader):
    """Publicly declares per-token supply destroyed by this shielded transaction.

    Wire format and entry constraints match MintHeader (RFC §4.1); the
    distinction is purely the header id and the semantic direction (creation
    vs destruction).

    Wire-format (de)serialization lives in
    ``hathorlib.vertex_parser._mint_melt_header``; the inherited
    ``serialize``/``deserialize``/``get_sighash_bytes`` methods route
    through the central dispatcher in ``hathorlib.vertex_parser._headers``.
    """

    tx: Transaction
    entries: list[MintMeltEntry] = field(default_factory=list)
