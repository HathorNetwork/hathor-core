# Copyright 2020 Hathor Labs
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

from collections import deque
from typing import TYPE_CHECKING, Deque, Generator, List, Optional, Set

from structlog import get_logger
from twisted.internet.defer import Deferred, inlineCallbacks

from hathor.transaction import BaseTransaction
from hathor.transaction.storage.exceptions import TransactionDoesNotExist

if TYPE_CHECKING:
    from hathor.p2p.node_sync_v2 import NodeBlockSync

logger = get_logger()


class SyncMempoolManager:
    """Manage the sync-v2 mempool with one peer.
    """
    def __init__(self, sync_manager: 'NodeBlockSync'):
        """Initialize the sync-v2 mempool manager."""
        # Shortcuts.
        self.sync_manager = sync_manager
        self.manager = self.sync_manager.manager
        self.tx_storage = self.manager.tx_storage
        self.reactor = self.sync_manager.reactor

        # Set of tips we know but couldn't add to the DAG yet.
        self.missing_tips: Set[bytes] = set()

        # Stack used by the DFS in the dependencies.
        # We use a deque for performance reasons.
        self.deque: Deque[BaseTransaction] = deque()

        # Maximum number of items in the DFS.
        self.MAX_STACK_LENGTH: int = 1000

        # Internal variables.
        # This is used to keep track of the latest requested tx.
        self._download_tx_deferred: Optional[Deferred] = None
        self._download_tx_hash: Optional[bytes] = None

    def start(self):
        pass

    @inlineCallbacks
    def get_tx(self, tx_id: bytes) -> Generator[BaseTransaction, BaseTransaction, BaseTransaction]:
        """Async internal method to get a transaction from the db or to download it."""
        try:
            tx = self.tx_storage.get_transaction(tx_id)
        except TransactionDoesNotExist:
            tx = yield self._download_tx(tx_id)
        return tx

    @inlineCallbacks
    def _download_tx(self, tx_id: bytes) -> Generator[BaseTransaction, BaseTransaction, BaseTransaction]:
        """Async internal method to download a transaction."""
        tx = yield self._get_data(tx_id)
        # TODO Verify tx.
        # tx.verify()
        return tx

    def _get_data(self, tx_id: bytes) -> Deferred:
        """Internal method to request the tx."""
        assert self._download_tx_deferred is None
        assert self._download_tx_hash is None
        self._download_tx_deferred = Deferred()
        self._download_tx_hash = tx_id
        self.sync_manager.send_get_data(tx_id, origin='mempool')
        return self._download_tx_deferred

    def on_new_mempool_tx(self, tx: BaseTransaction) -> None:
        """Called when a requested tx is received."""
        assert self._download_tx_deferred is not None
        if tx.hash != self._download_tx_hash:
            # Peer sent the wrong transaction?!
            # Maybe we should ban the peer.
            raise Exception('This should never happen.')
        deferred = self._download_tx_deferred
        self._download_tx_deferred = None
        self._download_tx_hash = None
        deferred.callback(tx)

    def run(self) -> None:
        """Run a loop of the sync-v2 mempool and schedules the next call.
        It can safely be called multiple times.
        """
        self.run_once()
        self.reactor.callLater(1000, self.run)

    @inlineCallbacks
    def run_once(self) -> Generator[None, BaseTransaction, None]:
        """Run a single loop of the sync-v2 mempool."""
        if not self.missing_tips:
            # No missing tips? Let's get them!
            self.sync_manager.send_get_tips()

        elif not self.deque:
            # Not downloading? Let's start!
            tx_id = next(iter(self.missing_tips))
            tx = yield self.get_tx(tx_id)
            self._dfs_start(tx)

        else:
            # Nothing to do. \o/
            pass

    def on_new_tips(self, tx_hashes: List[bytes]) -> None:
        """Called when a new list of tips is received from the peer."""
        for tx_id in tx_hashes:
            if self.tx_storage.transaction_exists(tx_id):
                continue
            self.missing_tips.add(tx_id)

    def _dfs_start(self, tx: BaseTransaction) -> None:
        """Initialize and start the DFS."""
        assert len(self.deque) == 0
        self.deque.append(tx)
        self._dfs()

    def get_one_missing_dep(self, tx: BaseTransaction) -> Optional[bytes]:
        """Get this first missing dependency found of tx."""
        assert not tx.is_block
        for txin in tx.inputs:
            if not self.tx_storage.transaction_exists(txin.tx_id):
                return txin.tx_id
        for parent in tx.parents:
            if not self.tx_storage.transaction_exists(parent):
                return parent
        return None

    def add_tx(self, tx: BaseTransaction) -> None:
        """Add tx to the DAG."""
        assert tx.hash is not None
        self.missing_tips.discard(tx.hash)
        self.manager.on_new_tx(tx)

    @inlineCallbacks
    def _dfs(self) -> Generator[None, BaseTransaction, None]:
        """DFS recursive method."""
        if not self.deque:
            self.reactor.callLater(0, self.run)
            return
        tx = self.deque[-1]

        missing_dep = self.get_one_missing_dep(tx)
        if not missing_dep:
            # No dependencies! \o/
            self.add_tx(tx)
            assert tx == self.deque.pop()

        else:
            # Iterate in the DFS.
            tx_dep = yield self.get_tx(missing_dep)
            self.deque.append(tx_dep)
            if len(self.deque) > self.MAX_STACK_LENGTH:
                self.deque.popleft()

        # Schedule next call.
        self.reactor.callLater(0, self._dfs)
