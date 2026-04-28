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

from hathorlib.headers.base import VertexBaseHeader
from hathorlib.headers.types import VertexHeaderId
from hathorlib.serialization import Deserializer, Serializer

if TYPE_CHECKING:
    from hathorlib.base_transaction import BaseTransaction
    from hathorlib.transaction import Transaction


EXCESS_BLINDING_FACTOR_SIZE = 32


@dataclass(frozen=True)
class UnshieldBalanceHeader(VertexBaseHeader):
    """Carries the excess blinding factor for a full-unshield tx.

    A tx that spends shielded inputs into transparent-only outputs needs to
    reveal `excess = sum(r_in) - sum(r_out)` so the Pedersen balance equation
    sum(C_in) = sum(C_out) + excess*G can hold. Mutually exclusive with
    ShieldedOutputsHeader: present only when the tx has no shielded outputs.
    The mutual-exclusion invariant is enforced at verification time.

    Privacy: with exactly one shielded input the scalar is effectively r_in
    of that input, but the transparent outputs of a full unshield already
    expose the spent amount, so nothing previously-private is additionally
    leaked. With two or more shielded inputs only the sum of their blinding
    factors is revealed; individual input amounts remain confidential.
    """

    tx: Transaction
    excess_blinding_factor: bytes

    def __post_init__(self) -> None:
        if len(self.excess_blinding_factor) != EXCESS_BLINDING_FACTOR_SIZE:
            raise ValueError(
                f'excess_blinding_factor must be {EXCESS_BLINDING_FACTOR_SIZE} bytes, '
                f'got {len(self.excess_blinding_factor)}'
            )

    @classmethod
    def deserialize(cls, tx: BaseTransaction, buf: bytes) -> tuple[UnshieldBalanceHeader, bytes]:
        """Deserialize: header_id(1) | excess_blinding_factor(32)."""
        from hathorlib.transaction import Transaction

        if not isinstance(tx, Transaction):
            raise ValueError(
                f'unshield balance header requires a Transaction, got {type(tx).__name__}'
            )

        deserializer = Deserializer.build_bytes_deserializer(buf)
        header_id = bytes(deserializer.read_bytes(1))
        if header_id != VertexHeaderId.UNSHIELD_BALANCE_HEADER.value:
            raise ValueError(
                f'unexpected header id: expected '
                f'{VertexHeaderId.UNSHIELD_BALANCE_HEADER.value!r}, got {header_id!r}'
            )

        excess_bf = bytes(deserializer.read_bytes(EXCESS_BLINDING_FACTOR_SIZE))
        leftover = bytes(deserializer.read_all())
        return cls(tx=tx, excess_blinding_factor=excess_bf), leftover

    def serialize(self) -> bytes:
        serializer = Serializer.build_bytes_serializer()
        serializer.write_bytes(VertexHeaderId.UNSHIELD_BALANCE_HEADER.value)
        serializer.write_bytes(self.excess_blinding_factor)
        return bytes(serializer.finalize())

    def get_sighash_bytes(self) -> bytes:
        # The full serialization is bound to the signature, so any mutation of
        # the scalar invalidates signatures over the tx.
        return self.serialize()
