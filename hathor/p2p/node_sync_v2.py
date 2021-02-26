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
from enum import Enum, IntFlag
from typing import TYPE_CHECKING, Any, Callable, Dict, Generator, List, Optional

from structlog import get_logger
from twisted.internet.defer import Deferred, inlineCallbacks
from twisted.internet.interfaces import IDelayedCall, IProtocol, IPushProducer, IReactorCore
from twisted.internet.task import Clock
from zope.interface import implementer

from hathor.conf import HathorSettings
from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.sync_manager import SyncManager
from hathor.transaction import BaseTransaction, Block, Transaction
from hathor.transaction.base_transaction import tx_or_block_from_bytes
from hathor.transaction.exceptions import HathorError
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction.storage.traversal import BFSWalk

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol

    # from hathor.p2p.sync_checkpoints import SyncCheckpoint

settings = HathorSettings()
logger = get_logger()


class PeerState(Enum):
    ERROR = 'error'
    UNKNOWN = 'unknown'
    SYNCING_CHECKPOINTS = 'syncing-checkpoints'
    SYNCING_BLOCKS = 'syncing-blocks'
    # SYNCING_TXS = 'syncing-txs'


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

    def __init__(self, protocol: 'HathorProtocol', reactor: Clock = None) -> None:
        """
        :param protocol: Protocol of the connection.
        :type protocol: HathorProtocol

        :param reactor: Reactor to schedule later calls. (default=twisted.internet.reactor)
        :type reactor: Reactor
        """
        from hathor.transaction.genesis import BLOCK_GENESIS
        self.protocol = protocol
        self.manager = protocol.node
        self.state = PeerState.UNKNOWN

        if reactor is None:
            from twisted.internet import reactor as twisted_reactor
            reactor = twisted_reactor
        self.reactor: IReactorCore = reactor
        self._is_streaming = False

        # Create logger with context
        self.log = logger.new(peer=self.short_peer_id)

        # Extra
        self._blk_size = 0
        self._blk_end_hash = settings.GENESIS_BLOCK_HASH
        self._blk_max_quantity = 0

        # indicates whether we're receiving a stream from the peer
        self.receiving_stream = False

        self.call_later_id: Optional[IDelayedCall] = None
        self.call_later_interval: int = 5  # seconds

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
        self.synced = False

        # Indicate whether the sync manager has been started.
        self._started: bool = False

        # Saves the last received block from the block streaming # this is useful to be used when running the sync of
        # transactions in the case when I am downloading a side chain. Starts at the genesis, which is common to all
        # peers on the network
        self._last_received_block: Block = BLOCK_GENESIS

        # Saves if I am in the middle of a mempool sync
        # we don't execute any sync while in the middle of it
        self.mempool_sync_running = False

        # This exists to avoid sync-txs loop on sync-checkpoints
        self._last_sync_transactions_start_hash: Optional[bytes] = None

    def get_status(self):
        """ Return the status of the sync.
        """
        return {
            'peer_height': self.peer_height,
            'synced_height': self.synced_height,
            'synced': self.synced,
            'state': self.state.value,
        }

    def is_synced(self):
        return self.synced

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
        self.send_data(tx)

    @property
    def short_peer_id(self) -> str:
        """ Returns the id of the peer (only 7 first chars)
        """
        if self.protocol.peer is None or self.protocol.peer.id is None:
            return ''
        return self.protocol.peer.id[:7]

    @property
    def is_started(self) -> bool:
        return self._started

    def start(self) -> None:
        """ Start sync.
        """
        if self._started:
            raise Exception('NodeSyncBlock is already running')
        self._started = True
        self.reactor.callLater(0, self.run_sync)

    def stop(self) -> None:
        """ Stop sync.
        """
        if not self._started:
            raise Exception('NodeSyncBlock is already stopped')
        self._started = False
        if self.call_later_id and self.call_later_id.active():
            self.call_later_id.cancel()

    def get_cmd_dict(self) -> Dict[ProtocolMessages, Callable[[str], None]]:
        """ Return a dict of messages of the plugin.
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
            ProtocolMessages.GET_MEMPOOL: self.handle_get_mempool,
            ProtocolMessages.MEMPOOL_END: self.handle_mempool_end,
            # XXX: overriding ReadyState.handle_error
            ProtocolMessages.ERROR: self.handle_error,
            ProtocolMessages.DATA: self.handle_data,
        }

    def handle_error(self, payload: str) -> None:
        """ Override protocols original handle_error so we can recover a sync in progress.
        """
        assert self.protocol.connections is not None
        sync_checkpoints = self.protocol.connections.sync_checkpoints
        if sync_checkpoints.is_running and sync_checkpoints.peer_syncing == self:
            # Oops, we're syncing and we received an error, remove ourselves and let it recover
            sync_checkpoints.peer_syncing = None
        # forward message to overloaded handle_error:
        self.protocol.handle_error(payload)

    def update_synced(self, synced: bool) -> None:
        self.synced = synced

    def sync_checkpoints_finished(self) -> None:
        self.state = PeerState.SYNCING_BLOCKS

    @inlineCallbacks
    def run_sync(self) -> Generator[Any, Any, None]:
        """Run sync. This is the entrypoint for the sync.
        It is always safe to call this method.
        """
        if self.receiving_stream:
            # If we're receiving a stream, wait for it to finish before running sync.
            # If we're sending a stream, do the sync to update the peer's synced block
            self.log.debug('receiving stream, try again later')
            self.call_later_id = self.reactor.callLater(self.call_later_interval, self.run_sync)
            return

        if self.mempool_sync_running:
            # It's running a mempool sync, so we wait until it finishes
            self.log.debug('running mempool sync, try again later')
            self.call_later_id = self.reactor.callLater(self.call_later_interval, self.run_sync)
            return

        checkpoints = self.manager.checkpoints
        bestblock = self.manager.tx_storage.get_best_block()
        meta = bestblock.get_metadata()

        self.log.debug('run sync', height=meta.height)

        assert self.protocol.connections is not None

        if self.is_syncing_checkpoints():
            # already syncing checkpoints, nothing to do
            self.log.debug('already syncing checkpoints', height=meta.height)
        elif meta.height < checkpoints[-1].height:
            yield self.start_sync_checkpoints()
        elif self.manager.tx_storage.has_needed_tx():
            self.update_synced(False)
            # TODO: find out whether we can sync transactions from this peer to speed things up
            self.run_sync_transactions()
        else:
            # I am already in sync with all checkpoints, sync next blocks
            self.state = PeerState.SYNCING_BLOCKS
            yield self.run_sync_blocks()

        self.schedule_run_sync(self.call_later_interval)

    def schedule_run_sync(self, interval: int) -> None:
        if self.call_later_id and self.call_later_id.active():
            # First cancel the next callLater that is already scheduled
            self.call_later_id.cancel()

        self.log.debug('schedule run_sync', interval=interval)
        self.call_later_id = self.reactor.callLater(interval, self.run_sync)

    @inlineCallbacks
    def start_sync_checkpoints(self) -> Generator[Any, Any, None]:
        assert self.protocol.connections is not None
        # Start object to sync until last checkpoint
        # and request the best block height of the peer
        self.state = PeerState.SYNCING_CHECKPOINTS
        self.log.debug('run sync checkpoints')
        sync_checkpoints = self.protocol.connections.sync_checkpoints
        data = yield self.get_peer_best_block()
        peer_best_height = data['height']

        if peer_best_height >= self.manager.checkpoints[-1].height:
            # This peer has all checkpoints
            sync_checkpoints.peers_to_request.append(self)
        else:
            # This peer does not have all checkpoints
            sync_checkpoints.incomplete_peers.append(self)

        sync_checkpoints.start()

    def run_sync_transactions(self) -> None:
        assert self.protocol.connections is not None

        tx_storage = self.manager.tx_storage
        # TODO: findout what transactions we can get from this peer
        # find the tx with highest "height"
        start_hash = tx_storage.get_next_needed_tx()

        if self.is_syncing_checkpoints():
            if start_hash == self._last_sync_transactions_start_hash:
                self.log.warn('sync transactions looped, skipping', start=start_hash.hex())
                self.protocol.connections.sync_checkpoints.should_skip_sync_tx = True
                self.protocol.connections.sync_checkpoints.continue_sync()
                return
            self._last_sync_transactions_start_hash = start_hash

        self.log.debug('run sync transactions', start=start_hash.hex())

        # Start with the last received block and find the best block full validated in its chain
        if self.is_syncing_checkpoints():
            block_hash = self._blk_end_hash
        else:
            block = self._last_received_block
            while not block.get_metadata().validation.is_valid():
                block = block.get_block_parent()
            assert block.hash is not None
            block_hash = block.hash
        self.send_get_block_txs(start_hash, block_hash)

    @inlineCallbacks
    def run_sync_blocks(self) -> Generator[Any, Any, None]:
        # Find my height
        bestblock = self.manager.tx_storage.get_best_block()
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
            self.run_sync_mempool()
        else:
            # we got all the peer's blocks but aren't on the same height, nothing to do
            pass

    def run_sync_mempool(self) -> None:
        """ Simply ask for all the transactions on the remote's mempool."""
        self.send_get_mempool()

    def send_get_mempool(self) -> None:
        self.mempool_sync_running = True
        self.send_message(ProtocolMessages.GET_MEMPOOL)

    def handle_get_mempool(self, payload: str) -> None:
        if self._is_streaming:
            self.log.warn('can\'t send while streaming')  # XXX: or can we?
            self.send_message(ProtocolMessages.MEMPOOL_END)
            return
        self.log.debug('handle_get_mempool')
        # XXX: this reversal requires allocation of the complete list, for now this isn't a problem because the mempool
        #      sync algorithm will change before the final sync-v2 release
        for tx in reversed(list(self.manager.tx_storage.iter_mempool())):
            # XXX: should this be made async?
            self.send_data(tx)

        self.send_message(ProtocolMessages.MEMPOOL_END)

    def handle_mempool_end(self, payload: str) -> None:
        self.mempool_sync_running = False

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
        self._last_received_block = BLOCK_GENESIS

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
        my_best_height = self.manager.tx_storage.get_height_best_block()

        self.log.debug('find common chain', peer_height=peer_best_height, my_height=my_best_height)

        if peer_best_height <= my_best_height:
            my_block = self.manager.tx_storage.get_from_block_height_index(peer_best_height)
            if my_block == peer_best_block:
                # we have all the peer's blocks
                if peer_best_height == my_best_height:
                    # We are in sync
                    self.update_synced(True)
                else:
                    self.update_synced(False)

                self.log.debug('synced to the latest peer block', height=peer_best_height)
                self.synced_height = peer_best_height
                return
            else:
                # TODO peer is on a different best chain
                self.log.warn('peer on different chain', peer_height=peer_best_height, peer_block=peer_best_block,
                              my_block=my_block)
                pass

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
                # if block_hash == self.manager.tx_storage.get_from_block_height_index(height):
                if self.manager.tx_storage.transaction_exists(block_hash):
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

    def get_peer_block_hashes(self, heights: List[int]) -> Deferred:
        """ Returns the peer's block hashes in the given heights.
        """
        key = 'peer-block-hashes'
        if self.deferred_by_key.get(key, None) is not None:
            raise Exception('latest_deferred is not None')
        self.send_get_peer_block_hashes(heights)
        deferred = Deferred()
        self.deferred_by_key[key] = deferred
        return deferred

    def send_get_peer_block_hashes(self, heights: List[int]) -> None:
        payload = json.dumps(heights)
        self.send_message(ProtocolMessages.GET_PEER_BLOCK_HASHES, payload)

    def handle_get_peer_block_hashes(self, payload: str) -> None:
        heights = json.loads(payload)
        data = []
        for h in heights:
            block = self.manager.tx_storage.get_from_block_height_index(h)
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
        blk = self.manager.tx_storage.get_transaction(start_hash)
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
        blk = self.manager.tx_storage.get_transaction(start_hash)
        assert isinstance(blk, Block)
        self.blockchain_streaming = BlockchainStreaming(self, blk, end_hash, reverse=True)
        self.blockchain_streaming.start()

    def send_blocks(self, blk: Block) -> None:
        """Send a BLOCK message."""
        # self.log.debug('sending block to peer', block=blk.hash_hex)
        payload = bytes(blk).hex()
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
                self.protocol.connections.sync_checkpoints.sync_ended()
            else:
                self.protocol.connections.sync_checkpoints.continue_sync()
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

        blk = tx_or_block_from_bytes(bytes.fromhex(payload))
        if not isinstance(blk, Block):
            # Not a block. Punish peer?
            return
        blk.storage = self.manager.tx_storage

        assert blk.hash is not None

        self._blk_received += 1
        if self._blk_received > self._blk_max_quantity + 1:
            self.log.warn('too many blocks received', last_block=blk.hash_hex)
            # Too many blocks. Punish peer?
            if self.is_syncing_checkpoints():
                # Tell the checkpoints sync to stop syncing from this peer and ban him
                self.protocol.connections.sync_checkpoints.sync_error()

            self.state = PeerState.ERROR
            return

        if self.manager.tx_storage.transaction_exists(blk.hash):
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
                # XXX: maybe improve this, feels a bit hacky
                blk.storage = self.manager.tx_storage
                blk.set_height_hint(self._blk_height)
            self.manager.on_new_tx(blk, propagate_to_peers=False, quiet=is_syncing_checkpoints,
                                   sync_checkpoints=is_syncing_checkpoints, partial=True)
        except HathorError:
            self.handle_invalid_block(exc_info=True)
            return
        else:
            self._last_received_block = blk
            self._blk_repeated = 0
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
            self.protocol.connections.sync_checkpoints.sync_error()
        self.state = PeerState.ERROR

    def handle_many_repeated_blocks(self) -> None:
        """ Method called when a block stream received many repeated blocks
            so I must stop the stream and reschedule to continue the sync with this peer later
        """
        self.send_stop_block_streaming()
        self.receiving_stream = False

        # XXX Should I have a different value? Right now it will run the algorithm 50s later
        self.schedule_run_sync(self.call_later_interval * 10)

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
        best_block = self.manager.tx_storage.get_best_block()
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
            tx = self.manager.tx_storage.get_transaction(child_hash)
        except TransactionDoesNotExist:
            # In case the tx does not exist we send a NOT-FOUND message
            self.send_message(ProtocolMessages.NOT_FOUND, child_hash.hex())
            return
        if not self.manager.tx_storage.transaction_exists(last_block_hash):
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
        if not isinstance(tx, Transaction):
            self.log.warn('not a transaction', hash=tx.hash_hex)
            # Not a transaction. Punish peer?
            return

        # tx_storage = self.manager.tx_storage

        self._tx_received += 1
        # TODO: use a separate `self._tx_max_quantity`
        if self._tx_received > self._blk_max_quantity + 1:
            self.log.warn('too many txs received')
            # Too many blocks. Punish peer?
            if self.is_syncing_checkpoints():
                # Tell the checkpoints sync to stop syncing from this peer and ban him
                self.protocol.connections.sync_checkpoints.sync_error()

            self.state = PeerState.ERROR
            return

        try:
            # this methods takes care of checking if the tx already exists, it will take care of doing at least
            # a basic validation
            # self.log.debug('add new tx', tx=tx.hash_hex)
            is_syncing_checkpoints = self.is_syncing_checkpoints()
            self.manager.on_new_tx(tx, propagate_to_peers=False, quiet=is_syncing_checkpoints,
                                   sync_checkpoints=is_syncing_checkpoints, partial=True)
        except HathorError:
            self.log.warn('invalid new tx', exc_info=True)
            # Invalid block?!
            # Invalid transaction?!
            if self.is_syncing_checkpoints():
                assert self.protocol.connections is not None
                # Tell the checkpoints sync to stop syncing from this peer and ban him
                self.protocol.connections.sync_checkpoints.sync_error()
            # Maybe stop syncing and punish peer.
            self.state = PeerState.ERROR
            return
        else:
            # XXX: debugging log, maybe add timing info
            if self._tx_received % 100 == 0:
                self.log.debug('tx streaming in progress', txs_received=self._tx_received)

    def send_data(self, tx: BaseTransaction) -> None:
        """ Send a DATA message.
        """
        self.log.debug('send tx', tx=tx.hash_hex)
        payload = base64.b64encode(tx.get_struct()).decode('ascii')
        self.send_message(ProtocolMessages.DATA, payload)

    def handle_data(self, payload: str) -> None:
        """ Handle a received DATA message.
        """
        if not payload:
            return
        data = base64.b64decode(payload)

        try:
            tx = tx_or_block_from_bytes(data)
        except struct.error:
            # Invalid data for tx decode
            return

        assert tx is not None
        assert tx.hash is not None
        if self.protocol.node.tx_storage.get_genesis(tx.hash):
            # We just got the data of a genesis tx/block. What should we do?
            # Will it reduce peer reputation score?
            return

        tx.storage = self.protocol.node.tx_storage
        assert tx.hash is not None

        # It is a new transaction being propagated
        # in the network, thus, we propagate it as well.
        if not tx.storage.transaction_exists(tx.hash):
            self.manager.on_new_tx(tx, conn=self.protocol, propagate_to_peers=True)


DEAFAULT_STREAMING_LIMIT = 10_000


@implementer(IPushProducer)
class _StreamingBase:
    def __init__(self, node_sync: NodeBlockSync, *, limit: int = DEAFAULT_STREAMING_LIMIT):
        self.node_sync = node_sync
        self.protocol: IProtocol = node_sync.protocol
        self.consumer = self.protocol.transport

        self.counter = 0
        self.limit = limit

        self.is_running: bool = False
        self.is_producing: bool = False

        self.delayed_call = None
        self.log = logger.new(peer=node_sync.short_peer_id)

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

        if cur.hash == self.end_hash:
            # only send the last when not reverse
            if not self.reverse:
                self.node_sync.send_blocks(cur)
            self.stop()
            self.node_sync.send_blocks_end(StreamEnd.END_HASH_REACHED)
            return

        if self.counter >= self.limit:
            # only send the last when not reverse
            if not self.reverse:
                self.node_sync.send_blocks(cur)
            self.stop()
            self.node_sync.send_blocks_end(StreamEnd.LIMIT_EXCEEDED)
            return

        if cur.get_metadata().voided_by:
            self.stop()
            self.node_sync.send_blocks_end(StreamEnd.STREAM_BECAME_VOIDED)
            return

        self.counter += 1

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
        self.last_block_height = last_blk_meta.height

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

        # self.log.debug('send next transaction', tx=cur.hash_hex)
        self.node_sync.send_transaction(cur)

        self.counter += 1
        if self.counter >= self.limit:
            self.stop()
            self.node_sync.send_blocks_end(StreamEnd.LIMIT_EXCEEDED)
            return

        self.schedule_if_needed()
