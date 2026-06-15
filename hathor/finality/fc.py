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

"""
Vote and Finality Certificate value objects.

A `Vote` is a single validator's BLS signature pinning a transaction. A `FinalityCertificate` (FC)
aggregates the votes of a quorum (weight ``>= 2f+1``) into one BLS signature plus a committee bitmap,
and verifies against the committee with a single ``FastAggregateVerify`` pairing check. Both objects
have a fixed, compact wire format that fits comfortably in a single p2p line.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterable

from hathor.finality.crypto import (
    BLS_SIGNATURE_LEN,
    VALIDATOR_ID_LEN,
    BLSSignature,
    ValidatorId,
    bls_fast_aggregate_verify,
    get_pin_message,
)
from hathor.types import VertexId

if TYPE_CHECKING:
    from hathor.finality.finality_settings import FinalitySettings

# Length of a transaction id (sha256d digest).
_TX_ID_LEN = 32


def bitmap_from_indices(indices: Iterable[int]) -> int:
    """Build a committee bitmap (bit ``i`` set means validator at index ``i`` signed)."""
    bitmap = 0
    for index in indices:
        bitmap |= 1 << index
    return bitmap


def indices_from_bitmap(bitmap: int) -> list[int]:
    """Return the sorted validator indices whose bits are set in ``bitmap``."""
    indices = []
    index = 0
    while bitmap:
        if bitmap & 1:
            indices.append(index)
        bitmap >>= 1
        index += 1
    return indices


@dataclass(frozen=True, slots=True)
class Vote:
    """A single validator's signature pinning a transaction to itself.

    The `validator_id` is only a non-unique skip-hint to find the candidate public key quickly; the
    signature is always verified against the committee's actual public keys.
    """

    tx_id: VertexId
    validator_id: ValidatorId
    signature: BLSSignature

    def __bytes__(self) -> bytes:
        assert len(self.tx_id) == _TX_ID_LEN
        assert len(self.validator_id) == VALIDATOR_ID_LEN
        assert len(self.signature) == BLS_SIGNATURE_LEN
        return bytes(self.tx_id) + bytes(self.validator_id) + bytes(self.signature)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'Vote':
        expected_len = _TX_ID_LEN + VALIDATOR_ID_LEN + BLS_SIGNATURE_LEN
        if len(data) != expected_len:
            raise ValueError(f'vote must be {expected_len} bytes, got {len(data)}')
        tx_id = data[:_TX_ID_LEN]
        validator_id = data[_TX_ID_LEN:_TX_ID_LEN + VALIDATOR_ID_LEN]
        signature = data[_TX_ID_LEN + VALIDATOR_ID_LEN:]
        return cls(
            tx_id=VertexId(tx_id),
            validator_id=ValidatorId(validator_id),
            signature=BLSSignature(signature),
        )


@dataclass(frozen=True, slots=True)
class FinalityCertificate:
    """An aggregate certificate proving a quorum of validators pinned ``tx_id``.

    Wire format: ``tx_id(32) || bitmap_len(1) || bitmap(bitmap_len) || agg_signature(96)``. The bitmap
    is the big-endian byte encoding of the committee bitmap; bit ``i`` set means the validator at
    committee index ``i`` is part of the quorum.
    """

    tx_id: VertexId
    bitmap: int
    agg_signature: BLSSignature

    def __bytes__(self) -> bytes:
        assert len(self.tx_id) == _TX_ID_LEN
        assert len(self.agg_signature) == BLS_SIGNATURE_LEN
        assert self.bitmap >= 0
        bitmap_bytes = self.bitmap.to_bytes(max(1, (self.bitmap.bit_length() + 7) // 8), 'big')
        if len(bitmap_bytes) > 0xff:
            raise ValueError('committee bitmap too large to serialize')
        return (
            bytes(self.tx_id)
            + len(bitmap_bytes).to_bytes(1, 'big')
            + bitmap_bytes
            + bytes(self.agg_signature)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> 'FinalityCertificate':
        min_len = _TX_ID_LEN + 1 + BLS_SIGNATURE_LEN
        if len(data) < min_len:
            raise ValueError(f'finality certificate must be at least {min_len} bytes, got {len(data)}')
        tx_id = data[:_TX_ID_LEN]
        bitmap_len = data[_TX_ID_LEN]
        bitmap_start = _TX_ID_LEN + 1
        bitmap_end = bitmap_start + bitmap_len
        if len(data) != bitmap_end + BLS_SIGNATURE_LEN:
            raise ValueError('finality certificate has an inconsistent length')
        bitmap = int.from_bytes(data[bitmap_start:bitmap_end], 'big')
        agg_signature = data[bitmap_end:]
        return cls(
            tx_id=VertexId(tx_id),
            bitmap=bitmap,
            agg_signature=BLSSignature(agg_signature),
        )

    def verify(self, settings: 'FinalitySettings') -> bool:
        """Verify the certificate against the committee.

        Returns True iff the signing validators reach a quorum (weight ``>= 2f+1``) and the aggregate
        signature is valid over this transaction's pin-message. The pin-message is recomputed from the
        committee hash and `tx_id`, so a certificate is bound to a specific committee.
        """
        if not settings.reaches_quorum(self.bitmap):
            return False
        public_keys = settings.public_keys_for_bitmap(self.bitmap)
        pin_message = get_pin_message(self.tx_id, settings.calculate_committee_hash())
        return bls_fast_aggregate_verify(public_keys, pin_message, self.agg_signature)
