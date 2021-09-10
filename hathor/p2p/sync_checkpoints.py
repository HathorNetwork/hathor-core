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

from itertools import chain
from typing import TYPE_CHECKING, Dict, List, NamedTuple, Optional

from structlog import get_logger
from twisted.internet.task import LoopingCall

from hathor.checkpoint import Checkpoint
from hathor.transaction.block import Block
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.util import Reactor

if TYPE_CHECKING:
    from hathor.manager import HathorManager  # noqa: F401
    from hathor.p2p.node_sync_v2 import NodeBlockSync  # noqa: F401

logger = get_logger()


class _SyncInterval(NamedTuple):
    start_hash: bytes
    start_height: int
    end_hash: bytes
    end_height: int


class SyncCheckpoint:
    """This is the central manager of the sync between checkpoints among all peers.
    """

    # Looping call interval.
    LC_INTERVAL: int = 5

    def __init__(self, manager: 'HathorManager'):
        # All peers that have all the checkpoints to download
        self.peers_to_request: List['NodeBlockSync'] = []

        # All peers that we are connected but don't have all the checkpoints
        self.incomplete_peers: List['NodeBlockSync'] = []

        # All peers that we tried to download but they sent wrong blocks
        self.banned_peers: List['NodeBlockSync'] = []

        # Indicate whether the checkpoint sync has been started.
        self._started: bool = False

        # HathorManager object to get checkpoints and storage
        self.manager: 'HathorManager' = manager

        self.reactor: Reactor = manager.reactor

        # All checkpoints that still need to sync
        self.checkpoints_to_sync: List[Checkpoint] = []

        # Previous checkpoints map
        self.previous_checkpoints: Dict[Checkpoint, Checkpoint] = {}

        # The peer that is syncing (the one we are downloading the blocks from)
        self.peer_syncing = None

        # If set to true next run_sync_transactions will be skipped
        self.should_skip_sync_tx = False

        # Create logger with context
        self.log = logger.new()

        # Looping call of the main method
        self._lc_run = LoopingCall(self.run_sync)
        self._lc_run.clock = self.reactor
        self._is_running = False

    def is_started(self) -> bool:
        return self._is_running

    def start(self) -> bool:
        """Start sync between checkpoints.
        """
        if self._started:
            self.log.warn('already running, not starting new one')
            return False

        self.log.info('start checkpoint sync')
        checkpoints = self.manager.checkpoints
        bestblock = self.manager.tx_storage.get_best_block()
        meta = bestblock.get_metadata()
        assert meta.validation.is_fully_connected()

        # Fill the previous checkpoints map
        it_cps = iter(checkpoints)
        prev_cp = next(it_cps)
        for cp in it_cps:
            self.previous_checkpoints[cp] = prev_cp
            prev_cp = cp

        # Get all checkpoints to sync
        self.checkpoints_to_sync = [checkpoint for checkpoint in checkpoints if checkpoint.height > meta.height]

        if not self.checkpoints_to_sync:
            self.log.error('something went wrong, no checkpoints to sync')
            # Should start this only if there are missing checkpoints on storage
            return False

        self._started = True
        self._lc_run.start(self.LC_INTERVAL)
        return True

    def stop(self) -> bool:
        """Stop sync between checkpoints.
        """
        if not self._started:
            self.log.warn('already stopped')
            return False
        if self.peer_syncing is not None:
            if self.peer_syncing in self.peers_to_request:
                self.peers_to_request.remove(self.peer_syncing)
            self.peer_syncing = None
        self._started = False
        self._lc_run.stop()
        self.log.debug('stop sync')
        return True

    def _checkpoint_sync_interval(self, checkpoint: Checkpoint) -> Optional[_SyncInterval]:
        """Calculate start and end point of a checkpoint."""
        start_height, start_hash = checkpoint
        end_height, end_hash = self.previous_checkpoints[checkpoint]
        # XXX: this could be optimized a lot, but it actually isn't that slow
        while start_height > end_height:
            try:
                block = self.manager.tx_storage.get_transaction(start_hash)
            except TransactionDoesNotExist:
                break
            assert isinstance(block, Block)
            start_hash = block.get_block_parent_hash()  # parent hash
            start_height = block.get_metadata().get_soft_height() - 1  # parent height
        # don't try to sync checkpoints that we already have all the blocks for
        if start_height == end_height:
            return None
        assert start_height > end_height
        return _SyncInterval(start_hash, start_height, end_hash, end_height)

    def _get_next_sync_interval(self) -> Optional[_SyncInterval]:
        """Iterate over checkpoints_to_sync and find a valid interval to sync, pruning already synced intervals.

        Will only return None when there are no more intervals to sync.
        """
        for checkpoint in self.checkpoints_to_sync[::]:
            sync_interval = self._checkpoint_sync_interval(checkpoint)
            if sync_interval is not None:
                return sync_interval
            else:
                self.checkpoints_to_sync.remove(checkpoint)
        return None

    def run_sync(self):
        """Run sync. This is the entrypoint for the sync.
        It is always safe to call this method.
        """
        assert self._started
        self.log.info('try to sync checkpoints')

        if self._is_running:
            self.log.debug('still running')
            return

        if self.peer_syncing:
            if self.peer_syncing.protocol.aborting:
                self.log.warn('syncing peer disconnected')
                self.stop()
            else:
                self.log.debug('already syncing')
            return

        self._is_running = True
        try:
            peer_to_request = self.get_peer_to_request()
            if peer_to_request:
                self.peer_syncing = peer_to_request
                self._run_sync()
            else:
                self.log.debug('no peers to sync from, try again later')
        finally:
            self._is_running = False

    def get_peer_to_request(self) -> Optional['NodeBlockSync']:
        """
        """
        # XXX: we could use a better peer selecting strategy here
        for peer in self.peers_to_request[:]:
            if peer.protocol.state is None:
                self.peers_to_request.remove(peer)
            else:
                return peer
        return None

    def _run_sync(self):
        """Method that actually run the sync.
        It should never be called directly.
        """
        assert self._started
        assert self.manager.tx_storage.indexes is not None

        if self.peer_syncing.protocol.state is None:
            self.log.error('lost state, something went wrong')
            self.stop()

        if self.manager.tx_storage.indexes.deps.has_needed_tx() and not self.should_skip_sync_tx:
            # Streaming ended. If there are needed txs, prioritize that
            return self.peer_syncing.run_sync_transactions()

        if not self.checkpoints_to_sync:
            self.log.debug('no checkpoints to sync')
            return

        sync_interval = self._get_next_sync_interval()
        if not sync_interval:
            self.log.debug('no checkpoints to sync anymore')
            return

        self.peer_syncing.synced_height = sync_interval.end_height
        self.peer_syncing.run_sync_between_heights(*sync_interval)

        # XXX: reset skip flag
        self.should_skip_sync_tx = False

    def continue_sync(self) -> None:
        """Restart peer selection and wait for the next looping call.
        """
        self.peer_syncing = None

    def on_sync_error(self):
        """Called by NodeBlockSync when an error occurs (e.g. receive invalid blocks or receive too many blocks)."""
        self.log.debug('sync error')
        # Send peer_syncing to banned_peers and start again with another peer
        self.banned_peers.append(self.peer_syncing)
        self.peers_to_request.remove(self.peer_syncing)
        self.peer_syncing = None

    def on_stream_ends(self):
        """Called by NodeBlockSync when the streaming of blocks is ended.
        """
        assert self.manager.tx_storage.indexes is not None

        self.log.debug('sync stream ended')

        if self.manager.tx_storage.indexes.deps.has_needed_tx():
            self.log.debug('checkpoint sync not complete: has needed txs')
            self.continue_sync()
            return

        if not self.checkpoints_to_sync:
            self.log.debug('checkpoint sync not complete: no checkpoints to sync')
            return

        # Double check I have the first checkpoint
        first_cp = self.checkpoints_to_sync[0]

        if not self.manager.tx_storage.transaction_exists(first_cp.hash):
            # the sync ended but I still don't have the checkpoint
            self.log.debug('checkpoint sync not complete: checkpoint not found')
            self.continue_sync()
            return

        # Everything went fine and I have all blocks until the next checkpoint
        self.checkpoints_to_sync.remove(first_cp)

        if self.checkpoints_to_sync:
            # Sync until next checkpoint again if I still have unsynced checkpoints
            # self.run_sync()
            self.log.debug('checkpoint sync not complete: checkpoint not found')
            self.continue_sync()
            return

        # All blocks are downloaded until the last checkpoint.
        # So, we stop the checkpoint sync and mark all connections as checkpoint finished.
        # XXX Should we execute ban for the banned_peers list? How long the ban?
        self.log.debug('stop all sync-checkpoints')
        for peer_sync in chain(self.peers_to_request, self.incomplete_peers, self.banned_peers):
            peer_sync.sync_checkpoints_finished()
        self.stop()

    def update_peer_height(self, peer: 'NodeBlockSync', height: int) -> None:
        """Called by NodeBlockSync when we have updated information about a peers height."""
        if height >= self.manager.checkpoints[-1].height:
            if peer in self.incomplete_peers:
                self.incomplete_peers.remove(peer)
            # This peer has all checkpoints
            self.peers_to_request.append(peer)
        else:
            # XXX: Maybe this isn't possible, but just in case
            if peer in self.peers_to_request:
                self.peers_to_request.remove(peer)
            # This peer does not have all checkpoints
            self.incomplete_peers.append(peer)
