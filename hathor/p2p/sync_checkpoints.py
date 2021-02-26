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
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from structlog import get_logger

from hathor.checkpoint import Checkpoint
from hathor.transaction.block import Block
from hathor.transaction.storage.exceptions import TransactionDoesNotExist

if TYPE_CHECKING:
    from hathor.manager import HathorManager  # noqa: F401
    from hathor.p2p.node_sync_v2 import NodeBlockSync  # noqa: F401

logger = get_logger()


class SyncCheckpoint:
    """ It is a central manager of the sync between checkpoints among all peers.
    """

    def __init__(self, manager: 'HathorManager'):
        # All peers that have all the checkpoints to download
        self.peers_to_request: List['NodeBlockSync'] = []

        # All peers that we are connected but don't have all the checkpoints
        self.incomplete_peers: List['NodeBlockSync'] = []

        # All peers that we tried to download but they sent wrong blocks
        self.banned_peers: List['NodeBlockSync'] = []

        # If the object is running sync
        self.is_running: bool = False

        # HathorManager object to get checkpoints and storage
        self.manager: 'HathorManager' = manager

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

    def start(self):
        if self.is_running:
            self.log.debug('alreay running, not starting new one')

        self.log.debug('start sync')
        checkpoints = self.manager.checkpoints
        bestblock = self.manager.tx_storage.get_best_block()
        meta = bestblock.get_metadata()

        # Fill the previous checkpoints map
        it_cps = iter(checkpoints)
        prev_cp = next(it_cps)
        for cp in it_cps:
            self.previous_checkpoints[cp] = prev_cp
            prev_cp = cp

        # Get all checkpoints to sync
        self.checkpoints_to_sync = [checkpoint for checkpoint in checkpoints if checkpoint.height > meta.height]

        if not self.checkpoints_to_sync:
            # Something went wrong
            # Should start this only if there are missing checkpoints on storage
            return

        self.is_running = True
        self.manager.reactor.callLater(0, self.try_to_sync)

    # XXX: the tuple (start_hash, start_int, end_hash, end_int) appears too often, maybe make a named tuple for it
    def _checkpoint_sync_interval(self, checkpoint: Checkpoint) -> Optional[Tuple[bytes, int, bytes, int]]:
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
            start_height = block.get_metadata().height - 1  # parent height
        # don't try to sync checkpoints that we already have all the blocks for
        if start_height == end_height:
            return None
        return (start_hash, start_height, end_hash, end_height)

    def _get_next_sync_interval(self) -> Optional[Tuple[bytes, int, bytes, int]]:
        """Iterate over checkpoints_to_sync and find a valid interval to sync, pruning already synced intervals.

        Will only return None when there are no more intervals to sync.
        """
        # for checkpoint in self.checkpoints_to_sync[::]:
        for checkpoint in self.checkpoints_to_sync[::-1]:
            sync_interval = self._checkpoint_sync_interval(checkpoint)
            if sync_interval is not None:
                return sync_interval
            else:
                self.checkpoints_to_sync.remove(checkpoint)
        return None

    def stop(self):
        self.log.debug('stop sync')
        self.is_running = False

    def try_to_sync(self):
        self.log.debug('try to sync')

        if self.peer_syncing:
            self.log.debug('already syncing')
            return

        if not self.is_running:
            self.log.debug('not running')
            return

        if self.peers_to_request:
            self.peer_syncing = self.peers_to_request[0]
            self.run_sync()
        else:
            self.log.debug('no peers to sync from, try again later')
            self.manager.reactor.callLater(5, self.try_to_sync)

    def continue_sync(self) -> None:
        self.peer_syncing = None
        self.manager.reactor.callLater(0, self.try_to_sync)

    def run_sync(self):
        if not self.is_running:
            self.log.debug('not running')
            return

        if self.manager.tx_storage.has_needed_tx() and not self.should_skip_sync_tx:
            # Streaming ended. If there are needed txs, prioritize that
            return self.peer_syncing.run_sync_transactions()

        if not self.checkpoints_to_sync:
            self.log.debug('no checkpoints to sync')
            return

        sync_interval = self._get_next_sync_interval()
        if not sync_interval:
            self.log.debug('no checkpoints to sync anymore')
            return

        self.peer_syncing.run_sync_between_heights(*sync_interval)

        # XXX: reset skip flag
        self.should_skip_sync_tx = False

    def sync_error(self):
        self.log.debug('sync error')
        # Send peer_syncing to banned_peers and start again with another peer
        self.banned_peers.append(self.peer_syncing)
        self.peers_to_request.remove(self.peer_syncing)
        self.peer_syncing = None
        self.manager.reactor.callLater(0, self.try_to_sync)

    def sync_ended(self):
        self.log.debug('sync ended')

        if self.manager.tx_storage.has_needed_tx():
            self.continue_sync()
            return

        if not self.checkpoints_to_sync:
            return

        # Double check I have the first checkpoint
        first_cp = self.checkpoints_to_sync[0]

        if not self.manager.tx_storage.transaction_exists(first_cp.hash):
            # the sync ended but I still don't have the checkpoint
            self.continue_sync()
            return

        # Everything went fine and I have all blocks until the next checkpoint
        self.checkpoints_to_sync.remove(first_cp)

        if self.checkpoints_to_sync:
            # Sync until next checkpoint again if I still have unsynced checkpoints
            # self.run_sync()
            self.continue_sync()
        else:
            # All blocks are downloaded until the last checkpoint
            # XXX Should we execute ban for the banned_peers list? How long the ban?
            self.stop()
            for peer_sync in chain(self.peers_to_request, self.incomplete_peers, self.banned_peers):
                peer_sync.sync_checkpoints_finished()
