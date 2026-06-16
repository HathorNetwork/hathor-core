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
The pending-FC pool.

Finality-eligible transactions that do not yet have a quorum certificate live here, separately from
the mempool. A submitter keeps a transaction here while it waits for the certificate to come back over
the network; a validator keeps it here while it accumulates votes. Once a transaction's accumulated
votes reach a quorum, it is promoted out of the pool (assembled into an FC and relayed). The pool is
in-memory: its contents are pre-final and can always be re-collected, so they need not survive a
restart.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from hathor.finality.crypto import bls_aggregate
from hathor.finality.fc import FinalityCertificate, Vote, bitmap_from_indices
from hathor.types import VertexId

if TYPE_CHECKING:  # pragma: no cover
    from hathor.finality.finality_settings import FinalitySettings
    from hathor.transaction import Transaction


@dataclass(slots=True)
class _PendingEntry:
    tx: 'Transaction'
    # Votes accumulated for this transaction, keyed by the signer's committee index.
    votes: dict[int, Vote] = field(default_factory=dict)


class PendingFinalityPool:
    """In-memory pool of finality-eligible transactions awaiting a quorum certificate."""

    def __init__(self) -> None:
        self._entries: dict[bytes, _PendingEntry] = {}

    def __contains__(self, tx_id: VertexId) -> bool:
        return bytes(tx_id) in self._entries

    def __len__(self) -> int:
        return len(self._entries)

    def add_tx(self, tx: 'Transaction') -> bool:
        """Add a transaction to the pool. Returns True if it was newly added, False if already present."""
        key = bytes(tx.hash)
        if key in self._entries:
            return False
        self._entries[key] = _PendingEntry(tx=tx)
        return True

    def get_tx(self, tx_id: VertexId) -> Optional['Transaction']:
        """Return the pending transaction for ``tx_id``, or None."""
        entry = self._entries.get(bytes(tx_id))
        return entry.tx if entry is not None else None

    def add_vote(self, tx_id: VertexId, validator_index: int, vote: Vote) -> bool:
        """Record a (already-verified) vote for a pending transaction.

        Returns True if this is a new vote from a validator not seen before for this transaction.
        Votes from an already-counted validator index are ignored (idempotent / anti-double-count).
        """
        entry = self._entries.get(bytes(tx_id))
        if entry is None:
            return False
        if validator_index in entry.votes:
            return False
        entry.votes[validator_index] = vote
        return True

    def get_bitmap(self, tx_id: VertexId) -> int:
        """Return the committee bitmap of validators that have voted for ``tx_id``."""
        entry = self._entries.get(bytes(tx_id))
        if entry is None:
            return 0
        return bitmap_from_indices(entry.votes.keys())

    def is_ready(self, tx_id: VertexId, settings: 'FinalitySettings') -> bool:
        """Return whether the accumulated votes for ``tx_id`` reach a quorum."""
        return settings.reaches_quorum(self.get_bitmap(tx_id))

    def assemble_certificate(self, tx_id: VertexId, settings: 'FinalitySettings') -> Optional[FinalityCertificate]:
        """Aggregate the accumulated votes for ``tx_id`` into a FinalityCertificate.

        Returns None if the votes do not (yet) reach a quorum. The individual votes were verified when
        added, so aggregating them yields a valid certificate.
        """
        entry = self._entries.get(bytes(tx_id))
        if entry is None:
            return None
        bitmap = bitmap_from_indices(entry.votes.keys())
        if not settings.reaches_quorum(bitmap):
            return None
        # Aggregate signatures in committee-index order so the bitmap and the aggregate agree.
        ordered_indices = sorted(entry.votes.keys())
        agg = bls_aggregate([entry.votes[i].signature for i in ordered_indices])
        return FinalityCertificate(tx_id=VertexId(bytes(tx_id)), bitmap=bitmap, agg_signature=agg)

    def remove(self, tx_id: VertexId) -> None:
        """Drop a transaction from the pool (e.g. once it has been certified and promoted)."""
        self._entries.pop(bytes(tx_id), None)
