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

from dataclasses import dataclass
from typing import TYPE_CHECKING

from hathor.transaction.headers.base import VertexBaseHeader
from hathor.transaction.headers.types import VertexHeaderId
from hathor.transaction.util import VerboseCallback

if TYPE_CHECKING:
    from hathor.transaction.base_transaction import BaseTransaction
    from hathor.transaction.transaction import Transaction


EXCESS_BLINDING_FACTOR_SIZE = 32


@dataclass(slots=True, kw_only=True)
class UnshieldBalanceHeader(VertexBaseHeader):
    """Carries the excess blinding factor for a full-unshield tx.

    A tx that spends shielded inputs into transparent-only outputs needs to
    reveal `excess = sum(r_in) − sum(r_out)` so the Pedersen balance equation
    sum(C_in) = sum(C_out) + excess*G can hold. Mutually exclusive with
    ShieldedOutputsHeader: present only when the tx has no shielded outputs.
    The mutual-exclusion invariant is enforced at verification time.

    Privacy: with exactly one shielded input the scalar is effectively r_in
    of that input, but the transparent outputs of a full unshield already
    expose the spent amount, so nothing previously-private is additionally
    leaked. With two or more shielded inputs only the sum of their blinding
    factors is revealed; individual input amounts remain confidential.
    """

    @classmethod
    def get_header_id(cls) -> bytes:
        return VertexHeaderId.UNSHIELD_BALANCE_HEADER.value

    tx: Transaction
    excess_blinding_factor: bytes

    def __post_init__(self) -> None:
        if len(self.excess_blinding_factor) != EXCESS_BLINDING_FACTOR_SIZE:
            from hathor.transaction.exceptions import InvalidShieldedOutputError
            raise InvalidShieldedOutputError(
                f'excess_blinding_factor must be {EXCESS_BLINDING_FACTOR_SIZE} bytes, '
                f'got {len(self.excess_blinding_factor)}'
            )

    @classmethod
    def deserialize(
        cls,
        tx: BaseTransaction,
        buf: bytes,
        *,
        verbose: VerboseCallback = None,
    ) -> tuple[UnshieldBalanceHeader, bytes]:
        """Deserialize: header_id(1) | excess_blinding_factor(32)."""
        from hathor.transaction.exceptions import InvalidShieldedOutputError
        from hathor.transaction.transaction import Transaction

        if not isinstance(tx, Transaction):
            raise InvalidShieldedOutputError(
                f'unshield balance header requires a Transaction, got {type(tx).__name__}'
            )

        header_size = 1 + EXCESS_BLINDING_FACTOR_SIZE
        if len(buf) < header_size:
            raise InvalidShieldedOutputError(
                f'unshield balance header requires {header_size} bytes, got {len(buf)}'
            )

        header_id = buf[0:1]
        if verbose:
            verbose('header_id', header_id)
        if header_id != VertexHeaderId.UNSHIELD_BALANCE_HEADER.value:
            raise InvalidShieldedOutputError(
                f'unexpected header id: expected '
                f'{VertexHeaderId.UNSHIELD_BALANCE_HEADER.value!r}, got {header_id!r}'
            )

        excess_bf = bytes(buf[1:1 + EXCESS_BLINDING_FACTOR_SIZE])
        if verbose:
            verbose('excess_blinding_factor', excess_bf)

        leftover = bytes(buf[header_size:])
        return cls(tx=tx, excess_blinding_factor=excess_bf), leftover

    def serialize(self) -> bytes:
        return VertexHeaderId.UNSHIELD_BALANCE_HEADER.value + self.excess_blinding_factor

    def get_sighash_bytes(self) -> bytes:
        # The full serialization is bound to the signature, so any mutation of
        # the scalar invalidates signatures over the tx.
        return self.serialize()
