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
from typing import TYPE_CHECKING, Any, Generator, Optional

from structlog import get_logger
from twisted.internet.defer import Deferred, inlineCallbacks

from hathor.transaction import BaseTransaction

if TYPE_CHECKING:
    from hathor.p2p.sync_v2.agent import NodeBlockSync

logger = get_logger()


class SyncMempoolManager:
    """Manage the sync-v2 mempool with one peer.
    """
    def __init__(self, sync_agent: 'NodeBlockSync'):
        """Initialize the sync-v2 mempool manager."""
        self.log = logger.new(peer=sync_agent.protocol.get_short_peer_id())

        # Shortcuts.
        self.sync_agent = sync_agent
        self.manager = self.sync_agent.manager
        self.reactor = self.sync_agent.reactor

        self._deferred: Optional[Deferred[bool]] = None

        # Set of tips we know but couldn't add to the DAG yet.
        self.missing_tips: set[bytes] = set()

        # Maximum number of items in the DFS.
        self.MAX_STACK_LENGTH: int = 1000

        # Whether the mempool algorithm is running
        self._is_running = False

    def is_running(self) -> bool:
        """Whether the sync-mempool is currently running."""
        return self._is_running

    def run(self) -> Deferred[bool]:
        """Starts _run in, won't start again if already running."""
        if self.is_running():
            self.log.warn('already started')
            assert self._deferred is not None
            return self._deferred
        self._is_running = True
        self.reactor.callLater(0, self._run)

        # TODO Implement a stop() and call it after N minutes.

        assert self._deferred is None
        self._deferred = Deferred()
        return self._deferred

    @inlineCallbacks
    def _run(self) -> Generator[Deferred, Any, None]:
        is_synced = False
        try:
            is_synced = yield self._unsafe_run()
        finally:
            # sync_agent.run_sync will start it again when needed
            self._is_running = False
            assert self._deferred is not None
            self._deferred.callback(is_synced)
            self._deferred = None

    @inlineCallbacks
    def _unsafe_run(self) -> Generator[Deferred, Any, bool]:
        """Run a single loop of the sync-v2 mempool."""
        if not self.missing_tips:
            # No missing tips? Let's get them!
            tx_hashes: list[bytes] = yield self.sync_agent.get_tips()
            self.missing_tips.update(h for h in tx_hashes if not self.sync_agent.p2p_storage.local_vertex_exists(h))

        while self.missing_tips:
            self.log.debug('We have missing tips! Let\'s start!', missing_tips=[x.hex() for x in self.missing_tips])
            tx_id = next(iter(self.missing_tips))
            tx: BaseTransaction = yield self.sync_agent.get_tx(tx_id)
            # Stack used by the DFS in the dependencies.
            # We use a deque for performance reasons.
            self.log.debug('start mempool DSF', tx=tx.hash_hex)
            yield self._dfs(deque([tx]))

        if not self.missing_tips:
            return True
        return False

    @inlineCallbacks
    def _dfs(self, stack: deque[BaseTransaction]) -> Generator[Deferred, Any, None]:
        """DFS method."""
        while stack:
            tx = stack[-1]
            self.log.debug('step mempool DSF', tx=tx.hash_hex, stack_len=len(stack))
            missing_dep = self._next_missing_dep(tx)
            if missing_dep is None:
                self.log.debug(r'No dependencies missing! \o/')
                self._add_tx(tx)
                assert tx == stack.pop()
            else:
                self.log.debug('Iterate in the DFS.', missing_dep=missing_dep.hex())
                tx_dep = yield self.sync_agent.get_tx(missing_dep)
                stack.append(tx_dep)
                if len(stack) > self.MAX_STACK_LENGTH:
                    stack.popleft()

    def _next_missing_dep(self, tx: BaseTransaction) -> Optional[bytes]:
        """Get the first missing dependency found of tx."""
        assert not tx.is_block
        for txin in tx.inputs:
            if not self.sync_agent.p2p_storage.local_vertex_exists(txin.tx_id):
                return txin.tx_id
        for parent in tx.parents:
            if not self.sync_agent.p2p_storage.local_vertex_exists(parent):
                return parent
        return None

    def _add_tx(self, tx: BaseTransaction) -> None:
        """Add tx to the DAG."""
        assert tx.hash is not None
        self.missing_tips.discard(tx.hash)
        self.sync_agent.p2p_vertex_handler.handle_new_vertex(tx)
