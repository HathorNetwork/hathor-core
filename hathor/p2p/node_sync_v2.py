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

import base64
import json
import math
import struct
from collections import OrderedDict
from enum import Enum, IntFlag
from typing import TYPE_CHECKING, Any, Callable, Dict, Generator, List, Optional, Tuple

from structlog import get_logger
from twisted.internet.defer import Deferred, inlineCallbacks
from twisted.internet.interfaces import IConsumer, IDelayedCall, IPushProducer
from twisted.internet.task import LoopingCall
from zope.interface import implementer

from hathor.conf import HathorSettings
from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.sync_checkpoints import SyncCheckpoint
from hathor.p2p.sync_manager import SyncManager
from hathor.p2p.sync_mempool import SyncMempoolManager
from hathor.transaction import BaseTransaction, Block, Transaction
from hathor.transaction.base_transaction import tx_or_block_from_bytes
from hathor.transaction.exceptions import HathorError
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction.storage.traversal import BFSWalk
from hathor.util import Reactor, verified_cast

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol

settings = HathorSettings()
logger = get_logger()


class PeerState(Enum):
    ERROR = 'error'
    UNKNOWN = 'unknown'
    SYNCING_CHECKPOINTS = 'syncing-checkpoints'
    SYNCING_BLOCKS = 'syncing-blocks'


class StreamEnd(IntFlag):
    END_HASH_REACHED = 0
    NO_MORE_BLOCKS = 1
    LIMIT_EXCEEDED = 2
    STREAM_BECAME_VOIDED = 3  # this will happen when the current chain becomes voided while it is being sent

    def __str__(self):
        if self is StreamEnd.END_HASH_REACHED:
            return 'end hash reached'
        elif self is StreamEnd.NO_MORE_BLOCKS:
            return 'end of blocks, no more blocks to download from this peer'
        elif self is StreamEnd.LIMIT_EXCEEDED:
            return 'streaming limit exceeded'
        elif self is StreamEnd.STREAM_BECAME_VOIDED:
            return 'streamed block chain became voided'
        else:
            raise ValueError(f'invalid StreamEnd value: {self.value}')


class NodeBlockSync(SyncManager):
    """ An algorithm to sync the Blockchain between two peers.
    """
    name: str = 'node-block-sync'

    def __init__(self, protocol: 'HathorProtocol', sync_checkpoints: SyncCheckpoint,
                 reactor: Optional[Reactor] = None) -> None:
        """
        :param protocol: Protocol of the connection.
        :type protocol: HathorProtocol

        :param reactor: Reactor to schedule later calls. (default=twisted.internet.reactor)
        :type reactor: Reactor
        """
        self.protocol = protocol
        self.manager = protocol.node
        self.tx_storage = protocol.node.tx_storage
        self.sync_checkpoints = sync_checkpoints
        self.state = PeerState.UNKNOWN

        if reactor is None:
            from hathor.util import reactor as twisted_reactor
            reactor = twisted_reactor
        assert reactor is not None
        self.reactor: Reactor = reactor
        self._is_streaming = False

        # Create logger with context
        self.log = logger.new(peer=self.protocol.get_short_peer_id())

        # Extra
        self._blk_size = 0
        self._blk_end_hash = settings.GENESIS_BLOCK_HASH
        self._blk_max_quantity = 0

        # indicates whether we're receiving a stream from the peer
        self.receiving_stream = False

        # highest block where we are synced
        self.synced_height = 0

        # highest block peer has
        self.peer_height = 0

        # Latest deferred waiting for a reply.
        self.deferred_by_key: Dict[str, Deferred] = {}

        # When syncing blocks we start streaming with all peers
        # so the moment I get some repeated blocks, I stop the download
        # because it's probably a streaming that I've just received
        self.max_repeated_blocks = 10

        # Blockchain streaming object, so I can stop anytime
        self.blockchain_streaming: Optional[BlockchainStreaming] = None

        # Whether the peers are synced, i.e. our best height and best block are the same
        self._synced = False

        # Indicate whether the sync manager has been started.
        self._started: bool = False

        # Saves the last received block from the block streaming # this is useful to be used when running the sync of
        # transactions in the case when I am downloading a side chain. Starts at the genesis, which is common to all
        # peers on the network
        self._last_received_block: Optional[Block] = None

        # Saves if I am in the middle of a mempool sync
        # we don't execute any sync while in the middle of it
        self.mempool_manager = SyncMempoolManager(self)
        self._receiving_tips: Optional[List[bytes]] = None

        # Cache for get_tx calls
        self._get_tx_cache: OrderedDict[bytes, BaseTransaction] = OrderedDict()
        self._get_tx_cache_maxsize = 1000

        # This exists to avoid sync-txs loop on sync-checkpoints
        self._last_sync_transactions_start_hash: Optional[bytes] = None

        # Looping call of the main method
        self._lc_run = LoopingCall(self.run_sync)
        self._lc_run.clock = self.reactor
        self._is_running = False

        # Whether we propagate transactions or not
        self._is_relaying = False

        # Initial value
        self._blk_height: Optional[int] = None
        self._blk_end_height: Optional[int] = None

    def get_status(self) -> Dict[str, Any]:
        """ Return the status of the sync.
        """
        res = {
            'peer_height': self.peer_height,
            'synced_height': self.synced_height,
            'synced': self._synced,
            'state': self.state.value,
        }
        return res

    def is_synced(self) -> bool:
        return self._synced

    def is_errored(self) -> bool:
        return self.state is PeerState.ERROR

    def is_syncing_checkpoints(self) -> bool:
        """True if state is SYNCING_CHECKPOINTS."""
        return self.state is PeerState.SYNCING_CHECKPOINTS

    def send_tx_to_peer_if_possible(self, tx: BaseTransaction) -> None:
        if not self.is_synced():
            # XXX Should we accept any tx while I am not synced?
            return

        # XXX When we start having many txs/s this become a performance issue
        # Then we could change this to be a streaming of real time data with
        # blocks as priorities to help miners get the blocks as fast as we can
        # We decided not to implement this right now because we already have some producers
        # being used in the sync algorithm and the code was becoming a bit too complex
        if self._is_relaying:
            self.send_data(tx)

    def is_started(self) -> bool:
        return self._started

    def start(self) -> None:
        """ Start sync.
        """
        if self._started:
            raise Exception('NodeSyncBlock is already running')
        self._started = True
        self._lc_run.start(5)

    def stop(self) -> None:
        """ Stop sync.
        """
        if not self._started:
            raise Exception('NodeSyncBlock is already stopped')
        self._started = False
        self._lc_run.stop()

    def get_cmd_dict(self) -> Dict[ProtocolMessages, Callable[[str], None]]:
        """ Return a dict of messages of the plugin.

        For further information about each message, see the RFC.
        Link: https://github.com/HathorNetwork/rfcs/blob/master/text/0025-p2p-sync-v2.md#p2p-sync-protocol-messages
        """
        return {
            ProtocolMessages.GET_NEXT_BLOCKS: self.handle_get_next_blocks,
            ProtocolMessages.GET_PREV_BLOCKS: self.handle_get_prev_blocks,
            ProtocolMessages.BLOCKS: self.handle_blocks,
            ProtocolMessages.BLOCKS_END: self.handle_blocks_end,
            ProtocolMessages.GET_BEST_BLOCK: self.handle_get_best_block,
            ProtocolMessages.BEST_BLOCK: self.handle_best_block,
            ProtocolMessages.GET_BLOCK_TXS: self.handle_get_block_txs,
            ProtocolMessages.TRANSACTION: self.handle_transaction,
            ProtocolMessages.GET_PEER_BLOCK_HASHES: self.handle_get_peer_block_hashes,
            ProtocolMessages.PEER_BLOCK_HASHES: self.handle_peer_block_hashes,
            ProtocolMessages.STOP_BLOCK_STREAMING: self.handle_stop_block_streaming,
            ProtocolMessages.GET_TIPS: self.handle_get_tips,
            ProtocolMessages.TIPS: self.handle_tips,
            ProtocolMessages.TIPS_END: self.handle_tips_end,
            # XXX: overriding ReadyState.handle_error
            ProtocolMessages.ERROR: self.handle_error,
            ProtocolMessages.GET_DATA: self.handle_get_data,
            ProtocolMessages.DATA: self.handle_data,
            ProtocolMessages.RELAY: self.handle_relay,
        }

    def handle_error(self, payload: str) -> None:
        """ Override protocols original handle_error so we can recover a sync in progress.
        """
        assert self.protocol.connections is not None
        if self.sync_checkpoints.is_started() and self.sync_checkpoints.peer_syncing == self:
            # Oops, we're syncing and we received an error, remove ourselves and let it recover
            self.sync_checkpoints.peer_syncing = None
            self.sync_checkpoints.peers_to_request.remove(self)
        # forward message to overloaded handle_error:
        self.protocol.handle_error(payload)

    def update_synced(self, synced: bool) -> None:
        self._synced = synced

    def sync_checkpoints_finished(self) -> None:
        self.log.info('finished syncing checkpoints')
        self.state = PeerState.SYNCING_BLOCKS

    @inlineCallbacks
    def run_sync(self) -> Generator[Any, Any, None]:
        if self._is_running:
            # Already running...
            self.log.debug('already running')
            return
        self._is_running = True
        try:
            yield self._run_sync()
        finally:
            self._is_running = False

    @inlineCallbacks
    def _run_sync(self) -> Generator[Any, Any, None]:
        """Run sync. This is the entrypoint for the sync.
        It is always safe to call this method.
        """

        if self.receiving_stream:
            # If we're receiving a stream, wait for it to finish before running sync.
            # If we're sending a stream, do the sync to update the peer's synced block
            self.log.debug('receiving stream, try again later')
            return

        if self.mempool_manager.is_running():
            # It's running a mempool sync, so we wait until it finishes
            self.log.debug('running mempool sync, try again later')
            return

        checkpoints = self.manager.checkpoints
        bestblock = self.tx_storage.get_best_block()
        meta = bestblock.get_metadata()

        self.log.debug('run sync', height=meta.height)

        assert self.protocol.connections is not None
        assert self.tx_storage.indexes is not None
        assert self.tx_storage.indexes.deps is not None

        if self.is_syncing_checkpoints():
            # already syncing checkpoints, nothing to do
            self.log.debug('already syncing checkpoints', height=meta.height)
        elif meta.height < checkpoints[-1].height:
            yield self.start_sync_checkpoints()
        elif self.tx_storage.indexes.deps.has_needed_tx():
            self.log.debug('needed tx exist, sync transactions')
            self.update_synced(False)
            # TODO: find out whether we can sync transactions from this peer to speed things up
            self.run_sync_transactions()
        else:
            # I am already in sync with all checkpoints, sync next blocks
            yield self.run_sync_blocks()

    @inlineCallbacks
    def start_sync_checkpoints(self) -> Generator[Any, Any, None]:
        assert self.protocol.connections is not None
        # Start object to sync until last checkpoint
        # and request the best block height of the peer
        self.state = PeerState.SYNCING_CHECKPOINTS
        self.log.debug('run sync checkpoints')
        data = yield self.get_peer_best_block()
        peer_best_height = data['height']
        self.peer_height = peer_best_height
        self.sync_checkpoints.update_peer_height(self, peer_best_height)
        self.sync_checkpoints.start()

    def run_sync_transactions(self) -> None:
        from hathor.transaction.genesis import BLOCK_GENESIS

        assert self.protocol.connections is not None
        assert self.tx_storage.indexes is not None
        assert self.tx_storage.indexes.deps is not None

        start_hash = self.tx_storage.indexes.deps.get_next_needed_tx()

        if self.is_syncing_checkpoints():
            if start_hash == self._last_sync_transactions_start_hash:
                self.log.info('sync transactions looped, skipping', start=start_hash.hex())
                self.sync_checkpoints.should_skip_sync_tx = True
                self.sync_checkpoints.continue_sync()
                return
            self._last_sync_transactions_start_hash = start_hash

        # Start with the last received block and find the best block full validated in its chain
        if self.is_syncing_checkpoints():
            block_hash = self._blk_end_hash
            block_height = self._blk_end_height
        else:
            block = self._last_received_block
            if block is None:
                block = BLOCK_GENESIS
            else:
                while not block.get_metadata().validation.is_valid():
                    block = block.get_block_parent()
            assert block.hash is not None
            block_hash = block.hash
            block_height = block.get_metadata().get_soft_height()

        self.log.info('run sync transactions', start=start_hash.hex(), end_block_hash=block_hash.hex(),
                      end_block_height=block_height)
        self.send_get_block_txs(start_hash, block_hash)

    @inlineCallbacks
    def run_sync_blocks(self) -> Generator[Any, Any, None]:
        self.state = PeerState.SYNCING_BLOCKS

        # Find my height
        bestblock = self.tx_storage.get_best_block()
        meta = bestblock.get_metadata()
        my_height = meta.height

        self.log.debug('run sync blocks', my_height=my_height)

        # Find best block
        data = yield self.get_peer_best_block()
        peer_best_block = data['block']
        peer_best_height = data['height']
        self.peer_height = peer_best_height

        # find best common block
        yield self.find_best_common_block(peer_best_height, peer_best_block)
        self.log.debug('run_sync_blocks', peer_height=self.peer_height, synced_height=self.synced_height)

        if self.synced_height < self.peer_height:
            # sync from common block
            peer_block_at_height = yield self.get_peer_block_hashes([self.synced_height])
            self.run_block_sync(peer_block_at_height[0][1], self.synced_height, peer_best_block, peer_best_height)
        elif my_height == self.synced_height == self.peer_height:
            # we're synced and on the same height, get their mempool
            self.mempool_manager.run()
        else:
            # we got all the peer's blocks but aren't on the same height, nothing to do
            pass

    # --------------------------------------------
    # BEGIN: GET_TIPS/TIPS/TIPS_END implementation
    # --------------------------------------------

    def get_tips(self) -> Deferred[List[bytes]]:
        """Async method to request the tips, returned hashes guaranteed to be new"""
        key = 'tips'
        deferred = self.deferred_by_key.get(key, None)
        if deferred is None:
            deferred = self.deferred_by_key[key] = Deferred()
            self.send_get_tips()
        else:
            assert self._receiving_tips is not None
        return deferred

    def send_get_tips(self) -> None:
        self.log.debug('get tips')
        self.send_message(ProtocolMessages.GET_TIPS)
        self._receiving_tips = []

    def handle_get_tips(self, payload: str) -> None:
        """Handle a received GET_TIPS message."""
        assert self.tx_storage.indexes is not None
        assert self.tx_storage.indexes.mempool_tips is not None
        if self._is_streaming:
            self.log.warn('can\'t send while streaming')  # XXX: or can we?
            self.send_message(ProtocolMessages.MEMPOOL_END)
            return
        self.log.debug('handle_get_tips')
        # TODO Use a streaming of tips
        for txid in self.tx_storage.indexes.mempool_tips.get():
            self.send_tips(txid)
        self.send_message(ProtocolMessages.TIPS_END)

    def send_tips(self, tx_id: bytes) -> None:
        """Send a TIPS message."""
        self.send_message(ProtocolMessages.TIPS, json.dumps([tx_id.hex()]))

    def handle_tips(self, payload: str) -> None:
        """Handle a received TIPS message."""
        self.log.debug('tips', receiving_tips=self._receiving_tips)
        if self._receiving_tips is None:
            self.protocol.send_error_and_close_connection('TIPS not expected')
            return
        data = json.loads(payload)
        data = [bytes.fromhex(x) for x in data]
        # filter-out txs we already have
        self._receiving_tips.extend(tx_id for tx_id in data if not self.tx_storage.transaction_exists(tx_id))

    def handle_tips_end(self, payload: str) -> None:
        """Handle a received TIPS-END message."""
        assert self._receiving_tips is not None
        key = 'tips'
        deferred = self.deferred_by_key.pop(key, None)
        if deferred is None:
            self.protocol.send_error_and_close_connection('TIPS-END not expected')
            return
        deferred.callback(self._receiving_tips)
        self._receiving_tips = None

    # ------------------------------------------
    # END: GET_TIPS/TIPS/TIPS_END implementation
    # ------------------------------------------

    def send_relay(self) -> None:
        self.log.debug('ask for relay')
        self.send_message(ProtocolMessages.RELAY)

    def handle_relay(self, payload: str) -> None:
        """Handle a received RELAY message."""
        # XXX: we need a way to turn this off, should we have arguments like: OFF, ALWAYS, SYNCED, ...? there is no
        # specific design for this
        self._is_relaying = True

    def _setup_block_streaming(self, start_hash: bytes, start_height: int, end_hash: bytes, end_height: int,
                               reverse: bool) -> None:
        self._blk_start_hash = start_hash
        self._blk_start_height = start_height
        self._blk_end_hash = end_hash
        self._blk_end_height = end_height
        self._blk_received = 0
        self._blk_repeated = 0
        self._blk_height = start_height
        raw_quantity = end_height - start_height + 1
        self._blk_max_quantity = -raw_quantity if reverse else raw_quantity
        self._blk_prev_hash: Optional[bytes] = None
        self._blk_stream_reverse = reverse
        self._last_received_block = None

    def run_sync_between_heights(self, start_hash: bytes, start_height: int, end_hash: bytes, end_height: int) -> None:
        """Called when the bestblock is between two checkpoints.
        It must syncs to the left until it reaches a known block.

        We assume that we can trust in `start_hash`.

        Possible cases:
            o---------------------o
            o####-----------------o

        Impossible cases:
            o####-----##----------o
            o####---------------##o

        TODO Check len(downloads) == h(start) - h(end)
        """
        self._setup_block_streaming(start_hash, start_height, end_hash, end_height, True)
        quantity = start_height - end_height
        self.log.info('get prev blocks', start_height=start_height, end_height=end_height, quantity=quantity,
                      start_hash=start_hash.hex(), end_hash=end_hash.hex())
        self.send_get_prev_blocks(start_hash, end_hash)

    def run_block_sync(self, start_hash: bytes, start_height: int, end_hash: bytes, end_height: int) -> None:
        """Called when the bestblock is after all checkpoints.
        It must syncs to the left until it reaches the remote's best block or the max stream limit.
        """
        self._setup_block_streaming(start_hash, start_height, end_hash, end_height, False)
        quantity = end_height - start_height
        self.log.info('get next blocks', start_height=start_height, end_height=end_height, quantity=quantity,
                      start_hash=start_hash.hex(), end_hash=end_hash.hex())
        self.send_get_next_blocks(start_hash, end_hash)

    def send_message(self, cmd: ProtocolMessages, payload: Optional[str] = None) -> None:
        """ Helper to send a message.
        """
        assert self.protocol.state is not None
        self.protocol.state.send_message(cmd, payload)

    @inlineCallbacks
    def find_best_common_block(self, peer_best_height: int, peer_best_block: bytes) -> Generator[Any, Any, None]:
        """ Search for the highest block/height where we're synced.
        """
        assert self.tx_storage.indexes is not None
        my_best_height = self.tx_storage.get_height_best_block()

        self.log.debug('find common chain', peer_height=peer_best_height, my_height=my_best_height)

        if peer_best_height <= my_best_height:
            my_block = self.tx_storage.indexes.height.get(peer_best_height)
            if my_block == peer_best_block:
                # we have all the peer's blocks
                if peer_best_height == my_best_height:
                    # We are in sync, ask for relay so the remote sends transactions in real time
                    self.update_synced(True)
                    self.send_relay()
                else:
                    self.update_synced(False)

                self.log.debug('synced to the latest peer block', height=peer_best_height)
                self.synced_height = peer_best_height
                return
            else:
                # TODO peer is on a different best chain
                self.log.warn('peer on different chain', peer_height=peer_best_height,
                              peer_block=peer_best_block.hex(), my_block=(my_block.hex() if my_block is not None else
                                                                          None))

        self.update_synced(False)
        not_synced = min(peer_best_height, my_best_height)
        synced = self.synced_height

        if not_synced < synced:
            self.log.warn('find_best_common_block not_synced < synced', synced=synced, not_synced=not_synced)
            # not_synced at this moment has the minimum of this node's or the peer's best height. If this is
            # smaller than the previous synced_height, it means either this node or the peer has switched best
            # chains. In this case, find the common block from checkpoint.
            synced = self.manager.checkpoints[-1].height

        while not_synced - synced > 1:
            self.log.debug('find_best_common_block synced not_synced', synced=synced, not_synced=not_synced)
            step = math.ceil((not_synced - synced)/10)
            heights = []
            height = synced
            while height < not_synced:
                heights.append(height)
                height += step
            heights.append(not_synced)
            block_height_list = yield self.get_peer_block_hashes(heights)
            block_height_list.reverse()
            for height, block_hash in block_height_list:
                # TODO initially I was checking the block_hash by height on the best chain. However, if the
                # peers are not on the same chain, the sync would never move forward. I think we need to debate it
                # better. Currently, the peer would show up as being in sync until the latest block I have in common
                # with him, even though we're not on the same best chain
                # if block_hash == self.tx_storage.get_from_block_height_index(height):
                if self.tx_storage.transaction_exists(block_hash):
                    synced = height
                    break
                else:
                    not_synced = height

            if not_synced == self.synced_height:
                self.log.warn('find_best_common_block not synced to previous synced height', synced=synced,
                              not_synced=not_synced)
                # We're not synced in our previous synced height anymore, so someone changed best chains
                not_synced = min(peer_best_height, my_best_height)
                synced = self.manager.checkpoints[-1].height

        self.log.debug('find_best_common_block finished synced not_synced', synced=synced, not_synced=not_synced)
        self.synced_height = synced

    def get_peer_block_hashes(self, heights: List[int]) -> Deferred[List[Tuple[int, bytes]]]:
        """ Returns the peer's block hashes in the given heights.
        """
        key = 'peer-block-hashes'
        if self.deferred_by_key.get(key, None) is not None:
            raise Exception('latest_deferred is not None')
        self.send_get_peer_block_hashes(heights)
        deferred: Deferred[List[Tuple[int, bytes]]] = Deferred()
        self.deferred_by_key[key] = deferred
        return deferred

    def send_get_peer_block_hashes(self, heights: List[int]) -> None:
        payload = json.dumps(heights)
        self.send_message(ProtocolMessages.GET_PEER_BLOCK_HASHES, payload)

    def handle_get_peer_block_hashes(self, payload: str) -> None:
        assert self.tx_storage.indexes is not None
        heights = json.loads(payload)
        data = []
        for h in heights:
            block = self.tx_storage.indexes.height.get(h)
            if block is None:
                break
            data.append((h, block.hex()))
        payload = json.dumps(data)
        self.send_message(ProtocolMessages.PEER_BLOCK_HASHES, payload)

    def handle_peer_block_hashes(self, payload: str) -> None:
        data = json.loads(payload)
        data = [(h, bytes.fromhex(block_hash)) for (h, block_hash) in data]
        key = 'peer-block-hashes'
        deferred = self.deferred_by_key.pop(key, None)
        if deferred:
            deferred.callback(data)

    def send_get_next_blocks(self, start_hash: bytes, end_hash: bytes) -> None:
        payload = json.dumps(dict(
            start_hash=start_hash.hex(),
            end_hash=end_hash.hex(),
        ))
        self.send_message(ProtocolMessages.GET_NEXT_BLOCKS, payload)
        self.receiving_stream = True

    def handle_get_next_blocks(self, payload: str) -> None:
        self.log.debug('handle GET-NEXT-BLOCKS')
        if self._is_streaming:
            self.protocol.send_error_and_close_connection('GET-NEXT-BLOCKS received before previous one finished')
            return
        data = json.loads(payload)
        self.send_next_blocks(
            start_hash=bytes.fromhex(data['start_hash']),
            end_hash=bytes.fromhex(data['end_hash']),
        )

    def send_next_blocks(self, start_hash: bytes, end_hash: bytes) -> None:
        self.log.debug('start GET-NEXT-BLOCKS stream response')
        # XXX If I don't have this block it will raise TransactionDoesNotExist error. Should I handle this?
        blk = self.tx_storage.get_transaction(start_hash)
        assert isinstance(blk, Block)
        self.blockchain_streaming = BlockchainStreaming(self, blk, end_hash)
        self.blockchain_streaming.start()

    def send_get_prev_blocks(self, start_hash: bytes, end_hash: bytes) -> None:
        payload = json.dumps(dict(
            start_hash=start_hash.hex(),
            end_hash=end_hash.hex(),
        ))
        self.send_message(ProtocolMessages.GET_PREV_BLOCKS, payload)
        self.receiving_stream = True

    def handle_get_prev_blocks(self, payload: str) -> None:
        self.log.debug('handle GET-PREV-BLOCKS')
        if self._is_streaming:
            self.protocol.send_error_and_close_connection('GET-PREV-BLOCKS received before previous one finished')
            return
        data = json.loads(payload)
        self.send_prev_blocks(
            start_hash=bytes.fromhex(data['start_hash']),
            end_hash=bytes.fromhex(data['end_hash']),
        )

    def send_prev_blocks(self, start_hash: bytes, end_hash: bytes) -> None:
        self.log.debug('start GET-PREV-BLOCKS stream response')
        # XXX If I don't have this block it will raise TransactionDoesNotExist error. Should I handle this?
        # TODO
        blk = self.tx_storage.get_transaction(start_hash)
        assert isinstance(blk, Block)
        self.blockchain_streaming = BlockchainStreaming(self, blk, end_hash, reverse=True)
        self.blockchain_streaming.start()

    def send_blocks(self, blk: Block) -> None:
        """Send a BLOCK message."""
        # self.log.debug('sending block to peer', block=blk.hash_hex)
        payload = base64.b64encode(bytes(blk)).decode('ascii')
        self.send_message(ProtocolMessages.BLOCKS, payload)

    def send_blocks_end(self, response_code: StreamEnd) -> None:
        payload = str(int(response_code))
        self.log.debug('send BLOCKS-END', payload=payload)
        self.send_message(ProtocolMessages.BLOCKS_END, payload)

    def handle_blocks_end(self, payload: str) -> None:
        self.log.debug('recv BLOCKS-END', payload=payload, size=self._blk_size)

        response_code = StreamEnd(int(payload))
        self.receiving_stream = False
        assert self.protocol.connections is not None

        if self.state not in [PeerState.SYNCING_BLOCKS, PeerState.SYNCING_CHECKPOINTS]:
            self.log.error('unexpected BLOCKS-END', state=self.state)
            self.protocol.send_error_and_close_connection('Not expecting to receive BLOCKS-END message')
            return

        self.log.debug('block streaming ended', reason=str(response_code))

        if self.is_syncing_checkpoints():
            if self._blk_height == self._blk_end_height:
                # Tell the checkpoints sync that it's over and can continue
                self.sync_checkpoints.on_stream_ends()
            else:
                self.sync_checkpoints.continue_sync()
        else:
            # XXX What should we do if it's in the next block sync phase?
            return

    def handle_blocks(self, payload: str) -> None:
        """Handle a received BLOCK message."""
        if self.state not in [PeerState.SYNCING_BLOCKS, PeerState.SYNCING_CHECKPOINTS]:
            self.log.error('unexpected BLOCK', state=self.state)
            self.protocol.send_error_and_close_connection('Not expecting to receive BLOCK message')
            return

        assert self.protocol.connections is not None

        blk_bytes = base64.b64decode(payload)
        blk = tx_or_block_from_bytes(blk_bytes)
        if not isinstance(blk, Block):
            # Not a block. Punish peer?
            return
        blk.storage = self.tx_storage

        assert blk.hash is not None

        self._blk_received += 1
        if self._blk_received > self._blk_max_quantity + 1:
            self.log.warn('too many blocks received', last_block=blk.hash_hex)
            # Too many blocks. Punish peer?
            if self.is_syncing_checkpoints():
                # Tell the checkpoints sync to stop syncing from this peer and ban him
                self.sync_checkpoints.on_sync_error()

            self.state = PeerState.ERROR
            return

        if self.tx_storage.transaction_exists(blk.hash):
            # We reached a block we already have. Skip it.
            self._blk_prev_hash = blk.hash
            self._blk_repeated += 1
            if self.receiving_stream and self._blk_repeated > self.max_repeated_blocks:
                self.log.debug('repeated block received', total_repeated=self._blk_repeated)
                self.handle_many_repeated_blocks()

        # basic linearity validation, crucial for correctly predicting the next block's height
        if self._blk_stream_reverse:
            if self._last_received_block and blk.hash != self._last_received_block.get_block_parent_hash():
                self.handle_invalid_block('received block is not parent of previous block')
                return
        else:
            if self._last_received_block and blk.get_block_parent_hash() != self._last_received_block.hash:
                self.handle_invalid_block('received block is not child of previous block')
                return

        try:
            # this methods takes care of checking if the block already exists,
            # it will take care of doing at least a basic validation
            # self.log.debug('add new block', block=blk.hash_hex)
            is_syncing_checkpoints = self.is_syncing_checkpoints()
            if is_syncing_checkpoints:
                assert self._blk_height is not None
                # XXX: maybe improve this, feels a bit hacky
                blk.storage = self.tx_storage
                blk.set_height(self._blk_height)
            if self.manager.tx_storage.transaction_exists(blk.hash):
                # XXX: early terminate?
                self.log.debug('block early terminate?', blk_id=blk.hash.hex())
            else:
                self.log.debug('block received', blk_id=blk.hash.hex())
                self.manager.on_new_tx(blk, propagate_to_peers=False, quiet=True, partial=True,
                                       sync_checkpoints=is_syncing_checkpoints,
                                       reject_locked_reward=not is_syncing_checkpoints)
        except HathorError:
            self.handle_invalid_block(exc_info=True)
            return
        else:
            self._last_received_block = blk
            self._blk_repeated = 0
            assert self._blk_height is not None
            if self._blk_stream_reverse:
                self._blk_height -= 1
            else:
                self._blk_height += 1
            # XXX: debugging log, maybe add timing info
            if self._blk_received % 500 == 0:
                self.log.debug('block streaming in progress', blocks_received=self._blk_received,
                               next_height=self._blk_height)

    def handle_invalid_block(self, msg: Optional[str] = None, *, exc_info: bool = False) -> None:
        """ Call this method when receiving an invalid block.
        """
        kwargs: Dict[str, Any] = {}
        if msg is not None:
            kwargs['error'] = msg
        if exc_info:
            kwargs['exc_info'] = True
        self.log.warn('invalid new block', **kwargs)
        # Invalid block?!
        if self.is_syncing_checkpoints():
            # Tell the checkpoints sync to stop syncing from this peer and ban him
            assert self.protocol.connections is not None
            self.sync_checkpoints.on_sync_error()
        self.state = PeerState.ERROR

    def handle_many_repeated_blocks(self) -> None:
        """ Method called when a block stream received many repeated blocks
            so I must stop the stream and reschedule to continue the sync with this peer later
        """
        self.send_stop_block_streaming()
        self.receiving_stream = False

    def send_stop_block_streaming(self) -> None:
        self.send_message(ProtocolMessages.STOP_BLOCK_STREAMING)

    def handle_stop_block_streaming(self, payload: str) -> None:
        if not self.blockchain_streaming or not self._is_streaming:
            self.log.debug('got stop streaming message with no streaming running')
            return

        self.log.debug('got stop streaming message')
        self.blockchain_streaming.stop()
        self.blockchain_streaming = None

    def get_peer_best_block(self) -> Deferred:
        key = 'best-block'
        deferred = self.deferred_by_key.pop(key, None)
        if self.deferred_by_key.get(key, None) is not None:
            raise Exception('latest_deferred is not None')

        self.send_get_best_block()
        deferred = Deferred()
        self.deferred_by_key[key] = deferred
        return deferred

    def send_get_best_block(self) -> None:
        self.send_message(ProtocolMessages.GET_BEST_BLOCK)

    def handle_get_best_block(self, payload: str) -> None:
        best_block = self.tx_storage.get_best_block()
        meta = best_block.get_metadata()
        data = {'block': best_block.hash_hex, 'height': meta.height}
        self.send_message(ProtocolMessages.BEST_BLOCK, json.dumps(data))

    def handle_best_block(self, payload: str) -> None:
        data = json.loads(payload)
        assert self.protocol.connections is not None
        self.log.debug('got best block', **data)
        data['block'] = bytes.fromhex(data['block'])

        key = 'best-block'
        deferred = self.deferred_by_key.pop(key, None)
        if deferred:
            deferred.callback(data)

    def _setup_tx_streaming(self):
        self._tx_received = 0
        self._tx_max_quantity = DEAFAULT_STREAMING_LIMIT  # XXX: maybe this is redundant
        # XXX: what else can we add for checking if everything is going well?

    def send_get_block_txs(self, child_hash: bytes, last_block_hash: bytes) -> None:
        """ Request a BFS of all transactions that parent of CHILD, up to the ones first comfirmed by LAST-BLOCK.

        Note that CHILD can either be a block or a transaction. But LAST-BLOCK is always a block.
        """
        self._setup_tx_streaming()
        self.log.debug('send_get_block_txs', child=child_hash.hex(), last_block=last_block_hash.hex())
        payload = json.dumps(dict(
            child=child_hash.hex(),
            last_block=last_block_hash.hex(),
        ))
        self.send_message(ProtocolMessages.GET_BLOCK_TXS, payload)
        self.receiving_stream = True

    def handle_get_block_txs(self, payload: str) -> None:
        if self._is_streaming:
            self.log.warn('already streaming')
            # self.log.warn('ignore GET-BLOCK-TXS, already streaming')
            # return
        data = json.loads(payload)
        self.log.debug('handle_get_block_txs', **data)
        child_hash = bytes.fromhex(data['child'])
        last_block_hash = bytes.fromhex(data['last_block'])
        self.send_block_txs(child_hash, last_block_hash)

    def send_block_txs(self, child_hash: bytes, last_block_hash: bytes) -> None:
        try:
            tx = self.tx_storage.get_transaction(child_hash)
        except TransactionDoesNotExist:
            # In case the tx does not exist we send a NOT-FOUND message
            self.send_message(ProtocolMessages.NOT_FOUND, child_hash.hex())
            return
        if not self.tx_storage.transaction_exists(last_block_hash):
            # In case the tx does not exist we send a NOT-FOUND message
            self.send_message(ProtocolMessages.NOT_FOUND, last_block_hash.hex())
            return
        x = TransactionsStreaming(self, tx, last_block_hash)
        x.start()

    def send_transaction(self, tx: Transaction) -> None:
        """Send a TRANSACTION message."""
        # payload = bytes(tx).hex()  # fails for big transactions
        payload = base64.b64encode(bytes(tx)).decode('ascii')
        self.send_message(ProtocolMessages.TRANSACTION, payload)

    def handle_transaction(self, payload: str) -> None:
        """Handle a received TRANSACTION message."""
        assert self.protocol.connections is not None

        # if self.state != PeerState.SYNCING_TXS:
        #     self.protocol.send_error_and_close_connection('Not expecting to receive transactions')
        #     return

        # tx_bytes = bytes.fromhex(payload)
        tx_bytes = base64.b64decode(payload)
        tx = tx_or_block_from_bytes(tx_bytes)
        assert tx.hash is not None
        if not isinstance(tx, Transaction):
            self.log.warn('not a transaction', hash=tx.hash_hex)
            # Not a transaction. Punish peer?
            return

        self._tx_received += 1
        if self._tx_received > self._tx_max_quantity + 1:
            self.log.warn('too many txs received')
            # Too many blocks. Punish peer?
            if self.is_syncing_checkpoints():
                # Tell the checkpoints sync to stop syncing from this peer and ban him
                self.sync_checkpoints.on_sync_error()

            self.state = PeerState.ERROR
            return

        try:
            # this methods takes care of checking if the tx already exists, it will take care of doing at least
            # a basic validation
            # self.log.debug('add new tx', tx=tx.hash_hex)
            is_syncing_checkpoints = self.is_syncing_checkpoints()
            if self.manager.tx_storage.transaction_exists(tx.hash):
                # XXX: early terminate?
                self.log.debug('tx early terminate?', tx_id=tx.hash.hex())
            else:
                self.log.debug('tx received', tx_id=tx.hash.hex())
                self.manager.on_new_tx(tx, propagate_to_peers=False, quiet=True, partial=True,
                                       sync_checkpoints=is_syncing_checkpoints,
                                       reject_locked_reward=not is_syncing_checkpoints)
        except HathorError:
            self.log.warn('invalid new tx', exc_info=True)
            # Invalid block?!
            # Invalid transaction?!
            if self.is_syncing_checkpoints():
                assert self.protocol.connections is not None
                # Tell the checkpoints sync to stop syncing from this peer and ban him
                self.sync_checkpoints.on_sync_error()
            # Maybe stop syncing and punish peer.
            self.state = PeerState.ERROR
            return
        else:
            # XXX: debugging log, maybe add timing info
            if self._tx_received % 100 == 0:
                self.log.debug('tx streaming in progress', txs_received=self._tx_received)

    # -----------------------------------
    # BEGIN: GET_DATA/DATA implementation
    # -----------------------------------

    @inlineCallbacks
    def get_tx(self, tx_id: bytes) -> Generator[Deferred, Any, BaseTransaction]:
        """Async method to get a transaction from the db/cache or to download it."""
        tx = self._get_tx_cache.get(tx_id)
        if tx is not None:
            self.log.debug('tx in cache', tx=tx_id.hex())
            return tx
        try:
            tx = self.tx_storage.get_transaction(tx_id)
        except TransactionDoesNotExist:
            tx = yield self.get_data(tx_id, 'mempool')
            if tx is None:
                self.log.error('failed to get tx', tx_id=tx_id.hex())
                self.protocol.send_error_and_close_connection(f'DATA mempool {tx_id.hex()} not found')
                raise
            # XXX: Verify tx?
            # tx.verify()
        return tx

    def get_data(self, tx_id: bytes, origin: str) -> Deferred:
        """Async method to request a tx by id"""
        # TODO: deal with stale `get_data` calls
        if origin != 'mempool':
            raise ValueError(f'origin={origin} not supported, only origin=mempool is supported')
        key = f'{origin}:{tx_id.hex()}'
        deferred = self.deferred_by_key.get(key, None)
        if deferred is None:
            deferred = self.deferred_by_key[key] = Deferred()
            self.send_get_data(tx_id, origin=origin)
            self.log.debug('get_data of new tx_id', deferred=deferred, key=key)
        else:
            # XXX: can we re-use deferred objects like this?
            self.log.debug('get_data of same tx_id, reusing deferred', deferred=deferred, key=key)
        return deferred

    def _on_get_data(self, tx: BaseTransaction, origin: str) -> None:
        """Called when a requested tx is received."""
        assert tx.hash is not None
        key = f'{origin}:{tx.hash_hex}'
        deferred = self.deferred_by_key.pop(key, None)
        if deferred is None:
            # Peer sent the wrong transaction?!
            # XXX: ban peer?
            self.protocol.send_error_and_close_connection(f'DATA {origin}: with tx that was not requested')
            return
        self.log.debug('get_data fulfilled', deferred=deferred, key=key)
        self._get_tx_cache[tx.hash] = tx
        if len(self._get_tx_cache) > self._get_tx_cache_maxsize:
            self._get_tx_cache.popitem(last=False)
        deferred.callback(tx)

    def send_data(self, tx: BaseTransaction, *, origin: str = '') -> None:
        """ Send a DATA message.
        """
        self.log.debug('send tx', tx=tx.hash_hex)
        tx_payload = base64.b64encode(tx.get_struct()).decode('ascii')
        if not origin:
            payload = tx_payload
        else:
            payload = ' '.join([origin, tx_payload])
        self.send_message(ProtocolMessages.DATA, payload)

    def send_get_data(self, txid: bytes, *, origin: Optional[str] = None) -> None:
        """Send a GET-DATA message for a given txid."""
        data = {
            'txid': txid.hex(),
        }
        if origin is not None:
            data['origin'] = origin
        payload = json.dumps(data)
        self.send_message(ProtocolMessages.GET_DATA, payload)

    def handle_get_data(self, payload: str) -> None:
        """Handle a received GET-DATA message."""
        data = json.loads(payload)
        txid_hex = data['txid']
        origin = data.get('origin', '')
        # self.log.debug('handle_get_data', payload=hash_hex)
        try:
            tx = self.protocol.node.tx_storage.get_transaction(bytes.fromhex(txid_hex))
            self.send_data(tx, origin=origin)
        except TransactionDoesNotExist:
            # In case the tx does not exist we send a NOT-FOUND message
            self.send_message(ProtocolMessages.NOT_FOUND, txid_hex)

    def handle_data(self, payload: str) -> None:
        """ Handle a received DATA message.
        """
        if not payload:
            return
        part1, _, part2 = payload.partition(' ')
        if not part2:
            origin = None
            data = base64.b64decode(part1)
        else:
            origin = part1
            data = base64.b64decode(part2)

        try:
            tx = tx_or_block_from_bytes(data)
        except struct.error:
            # Invalid data for tx decode
            return

        if origin:
            if origin != 'mempool':
                # XXX: ban peer?
                self.protocol.send_error_and_close_connection(f'DATA {origin}: unsupported origin')
                return
            assert tx is not None
            self._on_get_data(tx, origin)
            return

        assert tx is not None
        assert tx.hash is not None
        if self.protocol.node.tx_storage.get_genesis(tx.hash):
            # We just got the data of a genesis tx/block. What should we do?
            # Will it reduce peer reputation score?
            return

        tx.storage = self.protocol.node.tx_storage
        assert tx.hash is not None

        if self.manager.tx_storage.transaction_exists(tx.hash):
            # transaction already added to the storage, ignore it
            # XXX: maybe we could add a hash blacklist and punish peers propagating known bad txs
            self.manager.tx_storage.compare_bytes_with_local_tx(tx)
            return
        else:
            self.log.info('tx received in real time from peer', tx=tx.hash_hex, peer=self.protocol.get_peer_id())
            # If we have not requested the data, it is a new transaction being propagated
            # in the network, thus, we propagate it as well.
            self.manager.on_new_tx(tx, conn=self.protocol, propagate_to_peers=True)

    # ---------------------------------
    # END: GET_DATA/DATA implementation
    # ---------------------------------


DEAFAULT_STREAMING_LIMIT = 1_000


@implementer(IPushProducer)
class _StreamingBase:
    def __init__(self, node_sync: NodeBlockSync, *, limit: int = DEAFAULT_STREAMING_LIMIT):
        self.node_sync = node_sync
        self.protocol: 'HathorProtocol' = node_sync.protocol
        assert self.protocol.transport is not None
        self.consumer = verified_cast(IConsumer, self.protocol.transport)

        self.counter = 0
        self.limit = limit

        self.is_running: bool = False
        self.is_producing: bool = False

        self.delayed_call: Optional[IDelayedCall] = None
        self.log = logger.new(peer=node_sync.protocol.get_short_peer_id())

    def schedule_if_needed(self) -> None:
        """Schedule `send_next` if needed."""
        if not self.is_running:
            return

        if not self.is_producing:
            return

        if self.delayed_call and self.delayed_call.active():
            return

        self.delayed_call = self.node_sync.reactor.callLater(0, self.send_next)

    def start(self) -> None:
        """Start pushing."""
        self.log.debug('start streaming')
        assert not self.node_sync._is_streaming
        self.node_sync._is_streaming = True
        self.is_running = True
        self.consumer.registerProducer(self, True)
        self.resumeProducing()

    def stop(self) -> None:
        """Stop pushing."""
        self.log.debug('stop streaming')
        assert self.node_sync._is_streaming
        self.is_running = False
        self.pauseProducing()
        self.consumer.unregisterProducer()
        self.node_sync._is_streaming = False

    def send_next(self) -> None:
        """Push next block to peer."""
        raise NotImplementedError

    def resumeProducing(self) -> None:
        """This method is automatically called to resume pushing data."""
        self.is_producing = True
        self.schedule_if_needed()

    def pauseProducing(self) -> None:
        """This method is automatically called to pause pushing data."""
        self.is_producing = False
        if self.delayed_call and self.delayed_call.active():
            self.delayed_call.cancel()

    def stopProducing(self) -> None:
        """This method is automatically called to stop pushing data."""
        self.pauseProducing()


class BlockchainStreaming(_StreamingBase):
    def __init__(self, node_sync: NodeBlockSync, start_block: Block, end_hash: bytes,
                 *, limit: int = DEAFAULT_STREAMING_LIMIT, reverse: bool = False):
        super().__init__(node_sync, limit=limit)

        self.start_block = start_block
        self.current_block: Optional[Block] = start_block
        self.end_hash = end_hash
        self.reverse = reverse

    def send_next(self) -> None:
        """Push next block to peer."""
        assert self.is_running
        assert self.is_producing

        cur = self.current_block
        assert cur is not None
        assert cur.hash is not None

        if cur.hash == self.end_hash:
            # only send the last when not reverse
            if not self.reverse:
                self.log.debug('send next block', blk_id=cur.hash.hex())
                self.node_sync.send_blocks(cur)
            self.stop()
            self.node_sync.send_blocks_end(StreamEnd.END_HASH_REACHED)
            return

        if self.counter >= self.limit:
            # only send the last when not reverse
            if not self.reverse:
                self.log.debug('send next block', blk_id=cur.hash.hex())
                self.node_sync.send_blocks(cur)
            self.stop()
            self.node_sync.send_blocks_end(StreamEnd.LIMIT_EXCEEDED)
            return

        if cur.get_metadata().voided_by:
            self.stop()
            self.node_sync.send_blocks_end(StreamEnd.STREAM_BECAME_VOIDED)
            return

        self.counter += 1

        self.log.debug('send next block', blk_id=cur.hash.hex())
        self.node_sync.send_blocks(cur)

        if self.reverse:
            self.current_block = cur.get_block_parent()
        else:
            self.current_block = cur.get_next_block_best_chain()

        # XXX: don't send the genesis or the current block
        if self.current_block is None or self.current_block.is_genesis:
            self.stop()
            self.node_sync.send_blocks_end(StreamEnd.NO_MORE_BLOCKS)
            return

        self.schedule_if_needed()


class TransactionsStreaming(_StreamingBase):
    """Streams all transactions confirmed by the given block, from right to left (decreasing timestamp).
    """

    def __init__(self, node_sync: NodeBlockSync, child: BaseTransaction, last_block_hash: bytes,
                 *, limit: int = DEAFAULT_STREAMING_LIMIT):
        # XXX: is limit needed for tx streaming? Or let's always send all txs for
        # a block? Very unlikely we'll reach this limit
        super().__init__(node_sync, limit=limit)

        assert child.storage is not None
        self.storage = child.storage
        self.child = child
        self.last_block_hash = last_block_hash
        self.last_block_height = 0

        self.bfs = BFSWalk(child.storage, is_dag_verifications=True, is_left_to_right=False)
        # self.iter = self.bfs.run(child, skip_root=True)
        self.iter = self.bfs.run(child, skip_root=False)

    def start(self) -> None:
        super().start()
        last_blk_meta = self.storage.get_metadata(self.last_block_hash)
        assert last_blk_meta is not None
        self.last_block_height = last_blk_meta.get_soft_height()

    # TODO: make this generic too?
    def send_next(self) -> None:
        """Push next transaction to peer."""
        assert self.is_running
        assert self.is_producing

        try:
            cur = next(self.iter)
        except StopIteration:
            # nothing more to send
            self.stop()
            self.node_sync.send_blocks_end(StreamEnd.END_HASH_REACHED)
            return

        if cur.is_block:
            if cur.hash == self.last_block_hash:
                self.bfs.skip_neighbors(cur)
            self.schedule_if_needed()
            return

        assert isinstance(cur, Transaction)
        assert cur.hash is not None

        cur_metadata = cur.get_metadata()
        if cur_metadata.voided_by:
            self.stop()
            self.node_sync.send_blocks_end(StreamEnd.STREAM_BECAME_VOIDED)
            return

        assert cur_metadata.first_block is not None
        first_blk_meta = self.storage.get_metadata(cur_metadata.first_block)
        assert first_blk_meta is not None

        confirmed_by_height = first_blk_meta.height
        if confirmed_by_height <= self.last_block_height:
            # got to a tx that is confirmed by the given last-block or an older block
            self.log.debug('tx confirmed by block older than last_block', tx=cur.hash_hex,
                           confirmed_by_height=confirmed_by_height, last_block_height=self.last_block_height)
            self.bfs.skip_neighbors(cur)
            self.schedule_if_needed()
            return

        self.log.debug('send next transaction', tx_id=cur.hash.hex())
        self.node_sync.send_transaction(cur)

        self.counter += 1
        if self.counter >= self.limit:
            self.stop()
            self.node_sync.send_blocks_end(StreamEnd.LIMIT_EXCEEDED)
            return

        self.schedule_if_needed()
