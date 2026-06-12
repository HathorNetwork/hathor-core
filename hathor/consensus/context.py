# Copyright 2021 Hathor Labs
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

from structlog import get_logger

from hathor.transaction import BaseTransaction, Block, Transaction

if TYPE_CHECKING:
    from hathor.consensus.block_consensus import BlockConsensusAlgorithm
    from hathor.consensus.consensus import ConsensusAlgorithm
    from hathor.consensus.transaction_consensus import TransactionConsensusAlgorithm
    from hathor.nanocontracts.nc_exec_logs import NCEvent

logger = get_logger()

_base_transaction_log = logger.new()


@dataclass(kw_only=True, slots=True, frozen=True)
class ReorgInfo:
    common_block: Block
    old_best_block: Block
    new_best_block: Block


class ConsensusAlgorithmContext:
    """ An instance of this class holds all the relevant information related to a single run of a consensus update.
    """
    __slots__ = (
        'consensus',
        'block_algorithm',
        'transaction_algorithm',
        'txs_affected',
        'reorg_info',
        'nc_events',
        'nc_exec_success',
        '_pending_saves',
        '_saves_flushed',
    )

    consensus: 'ConsensusAlgorithm'
    block_algorithm: 'BlockConsensusAlgorithm'
    transaction_algorithm: 'TransactionConsensusAlgorithm'
    txs_affected: set[BaseTransaction]
    reorg_info: ReorgInfo | None
    nc_events: list[tuple[Transaction, list[NCEvent]]] | None
    nc_exec_success: list[Transaction]

    def __init__(self, consensus: 'ConsensusAlgorithm') -> None:
        self.consensus = consensus
        self.block_algorithm = self.consensus.block_algorithm_factory(self)
        self.transaction_algorithm = self.consensus.transaction_algorithm_factory(self)
        self.txs_affected = set()
        self.reorg_info = None
        self.nc_events = None
        self.nc_exec_success = []
        # metadata saves are deferred and deduped while the algorithms run (an 8-input tx
        # would otherwise save the same spent tx's metadata once per input); unsafe_update
        # flushes once, after which save() writes through (the reorg removal paths run after
        # the flush and keep their original immediate-persistence semantics)
        self._pending_saves: dict[bytes, BaseTransaction] = {}
        self._saves_flushed = False

    def save(self, tx: BaseTransaction) -> None:
        """Only metadata is ever saved in a consensus update."""
        assert tx.storage is not None
        self.txs_affected.add(tx)
        if self._saves_flushed:
            tx.storage.save_transaction(tx, only_metadata=True)
        else:
            self._pending_saves[tx.hash] = tx

    def flush_saves(self) -> None:
        """Persist every deferred metadata save (each affected tx exactly once) and switch
        save() to write-through. Must be called exactly once per consensus update, before any
        path that deletes transactions (a deferred save flushed after a removal would
        resurrect the removed tx's metadata row)."""
        assert not self._saves_flushed
        self._saves_flushed = True
        for tx in self._pending_saves.values():
            assert tx.storage is not None
            tx.storage.save_transaction(tx, only_metadata=True)
        self._pending_saves.clear()

    def mark_as_reorg(self, reorg_info: ReorgInfo) -> None:
        """Must only be called once, will raise an assert error if called twice."""
        assert self.reorg_info is None
        self.reorg_info = reorg_info
