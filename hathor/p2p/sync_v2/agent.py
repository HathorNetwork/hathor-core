# Copyright 2023 Hathor Labs
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
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Generator, NamedTuple, Optional

from structlog import get_logger
from twisted.internet.defer import Deferred, inlineCallbacks
from twisted.internet.task import LoopingCall

from hathor.conf.settings import HathorSettings
from hathor.exception import InvalidNewTransaction
from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.sync_agent import SyncAgent
from hathor.p2p.sync_v2.blockchain_streaming_client import BlockchainStreamingClient, StreamingError
from hathor.p2p.sync_v2.mempool import SyncMempoolManager
from hathor.p2p.sync_v2.payloads import BestBlockPayload, GetNextBlocksPayload, GetTransactionsBFSPayload
from hathor.p2p.sync_v2.streamers import (
    DEFAULT_STREAMING_LIMIT,
    BlockchainStreamingServer,
    StreamEnd,
    TransactionsStreamingServer,
)
from hathor.p2p.sync_v2.transaction_streaming_client import TransactionStreamingClient
from hathor.reactor import ReactorProtocol as Reactor
from hathor.transaction import BaseTransaction, Block, Transaction
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction.vertex_parser import VertexParser
from hathor.types import VertexId
from hathor.util import collect_n
from hathor.utils.weight import weight_to_work
from hathor.vertex_handler import VertexHandler

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol
    from hathor.transaction.storage import TransactionStorage

logger = get_logger()

MAX_GET_TRANSACTIONS_BFS_LEN: int = 8
MAX_MEMPOOL_STATUS_TIPS: int = 20

RUN_SYNC_MAIN_LOOP_INTERVAL = 1  # second(s)

# This multiplier is used to calculate the minimum score of an orphan chain to add it to the storage.
ORPHAN_CHAIN_THRESHOLD_MULTIPLIER = 0.95  # percentage


class _HeightInfo(NamedTuple):
    height: int
    id: VertexId

    def __repr__(self):
        return f'_HeightInfo({self.height}, {self.id.hex()})'

    def __str__(self):
        return f'({self.height}, {self.id.hex()})'

    def to_json(self) -> dict[str, Any]:
        return {
            'height': self.height,
            'id': self.id.hex(),
        }


class PeerState(Enum):
    ERROR = 'error'
    UNKNOWN = 'unknown'
    SYNCING_BLOCKS = 'syncing-blocks'
    SYNCING_TRANSACTIONS = 'syncing-transactions'
    SYNCING_MEMPOOL = 'syncing-mempool'


class NodeBlockSync(SyncAgent):
    """ An algorithm to sync two peers based on their blockchain.
    """
    name: str = 'node-block-sync'

    def __init__(
        self,
        settings: HathorSettings,
        protocol: 'HathorProtocol',
        reactor: Reactor,
        *,
        vertex_parser: VertexParser,
        vertex_handler: VertexHandler,
    ) -> None:
        """
        :param protocol: Protocol of the connection.
        :type protocol: HathorProtocol

        :param reactor: Reactor to schedule later calls. (default=twisted.internet.reactor)
        :type reactor: Reactor
        """
        self._settings = settings
        self.vertex_parser = vertex_parser
        self.vertex_handler = vertex_handler
        self.protocol = protocol
        self.tx_storage: 'TransactionStorage' = protocol.node.tx_storage
        self.state = PeerState.UNKNOWN

        self.DEFAULT_STREAMING_LIMIT = DEFAULT_STREAMING_LIMIT

        self.reactor: Reactor = reactor
        self._is_streaming: bool = False

        # Create logger with context
        self.log = logger.new(peer=self.protocol.get_short_peer_id())

        # indicates whether we're receiving a stream from the peer
        self.receiving_stream = False

        # highest block where we are synced
        self.synced_block: Optional[_HeightInfo] = None

        # highest block peer has
        self.peer_best_block: Optional[_HeightInfo] = None

        # Latest deferred waiting for a reply.
        self._deferred_txs: dict[VertexId, Deferred[BaseTransaction]] = {}
        self._deferred_tips: Optional[Deferred[list[bytes]]] = None
        self._deferred_best_block: Optional[Deferred[_HeightInfo]] = None
        self._deferred_peer_block_hashes: Optional[Deferred[list[_HeightInfo]]] = None

        # Clients to handle streaming messages.
        self._blk_streaming_client: Optional[BlockchainStreamingClient] = None
        self._tx_streaming_client: Optional[TransactionStreamingClient] = None

        # Streaming server objects
        self._blk_streaming_server: Optional[BlockchainStreamingServer] = None
        self._tx_streaming_server: Optional[TransactionsStreamingServer] = None

        # Whether the peers are synced, i.e. we have the same best block.
        # Notice that this flag ignores the mempool.
        self._synced = False

        # Whether the mempool is synced or not.
        self._synced_mempool = False

        # Indicate whether the sync manager has been started.
        self._started: bool = False

        # Saves if I am in the middle of a mempool sync
        # we don't execute any sync while in the middle of it
        self.mempool_manager = SyncMempoolManager(self)
        self._receiving_tips: Optional[list[VertexId]] = None
        self.max_receiving_tips: int = self._settings.MAX_MEMPOOL_RECEIVING_TIPS

        # Cache for get_tx calls
        self._get_tx_cache: OrderedDict[bytes, BaseTransaction] = OrderedDict()
        self._get_tx_cache_maxsize = 1000

        # Looping call of the main method
        self._lc_run = LoopingCall(self.run_sync)
        self._lc_run.clock = self.reactor
        self._is_running = False
        self._sync_started_at: float = 0

        # Maximum running time to consider a sync stale.
        self.max_running_time: int = 30 * 60  # seconds

        # Whether vertex relay is enabled or not.
        self._outbound_relay_enabled = False  # from us to the peer
        self._inbound_relay_enabled = False   # from the peer to us

        # Whether to sync with this peer
        self._is_enabled: bool = False

    def get_status(self) -> dict[str, Any]:
        """ Return the status of the sync.
        """
        assert self.tx_storage.indexes is not None
        assert self.tx_storage.indexes.mempool_tips is not None
        tips = self.tx_storage.indexes.mempool_tips.get()
        tips_limited, tips_has_more = collect_n(iter(tips), MAX_MEMPOOL_STATUS_TIPS)
        res = {
            'is_enabled': self.is_sync_enabled(),
            'peer_best_block': self.peer_best_block.to_json() if self.peer_best_block else None,
            'synced_block': self.synced_block.to_json() if self.synced_block else None,
            'synced': self._synced,
            'state': self.state.value,
            'mempool': {
                'tips_count': len(tips),
                'tips': [x.hex() for x in tips_limited],
                'has_more': tips_has_more,
                'is_synced': self._synced_mempool,
            }
        }
        return res

    def is_synced(self) -> bool:
        return self._synced

    def is_errored(self) -> bool:
        return self.state == PeerState.ERROR

    def is_sync_enabled(self) -> bool:
        return self._is_enabled

    def enable_sync(self) -> None:
        self._is_enabled = True

    def disable_sync(self) -> None:
        self._is_enabled = False

    def send_tx_to_peer_if_possible(self, tx: BaseTransaction) -> None:
        if not self._is_enabled:
            self.log.debug('sync is disabled')
            return

        # XXX When we start having many txs/s this become a performance issue
        # Then we could change this to be a streaming of real time data with
        # blocks as priorities to help miners get the blocks as fast as we can
        # We decided not to implement this right now because we already have some producers
        # being used in the sync algorithm and the code was becoming a bit too complex
        if self._outbound_relay_enabled:
            self.send_data(tx)

    def is_started(self) -> bool:
        return self._started

    def start(self) -> None:
        if self._started:
            raise Exception('NodeSyncBlock is already running')
        self._started = True
        self._lc_run.start(RUN_SYNC_MAIN_LOOP_INTERVAL)

    def stop(self) -> None:
        if not self._started:
            raise Exception('NodeSyncBlock is already stopped')
        self._started = False
        if self._lc_run.running:
            self._lc_run.stop()

    def get_cmd_dict(self) -> dict[ProtocolMessages, Callable[[str], None]]:
        """ Return a dict of messages of the plugin.

        For further information about each message, see the RFC.
        Link: https://github.com/HathorNetwork/rfcs/blob/master/text/0025-p2p-sync-v2.md#p2p-sync-protocol-messages
        """
        return {
            ProtocolMessages.GET_NEXT_BLOCKS: self.handle_get_next_blocks,
            ProtocolMessages.BLOCKS: self.handle_blocks,
            ProtocolMessages.BLOCKS_END: self.handle_blocks_end,
            ProtocolMessages.GET_BEST_BLOCK: self.handle_get_best_block,
            ProtocolMessages.BEST_BLOCK: self.handle_best_block,
            ProtocolMessages.GET_TRANSACTIONS_BFS: self.handle_get_transactions_bfs,
            ProtocolMessages.TRANSACTION: self.handle_transaction,
            ProtocolMessages.TRANSACTIONS_END: self.handle_transactions_end,
            ProtocolMessages.GET_PEER_BLOCK_HASHES: self.handle_get_peer_block_hashes,
            ProtocolMessages.PEER_BLOCK_HASHES: self.handle_peer_block_hashes,
            ProtocolMessages.STOP_BLOCK_STREAMING: self.handle_stop_block_streaming,
            ProtocolMessages.STOP_TRANSACTIONS_STREAMING: self.handle_stop_transactions_streaming,
            ProtocolMessages.GET_TIPS: self.handle_get_tips,
            ProtocolMessages.TIPS: self.handle_tips,
            ProtocolMessages.TIPS_END: self.handle_tips_end,
            # XXX: overriding ReadyState.handle_error
            ProtocolMessages.ERROR: self.handle_error,
            ProtocolMessages.GET_DATA: self.handle_get_data,
            ProtocolMessages.DATA: self.handle_data,
            ProtocolMessages.RELAY: self.handle_relay,
            ProtocolMessages.NOT_FOUND: self.handle_not_found,
        }

    def handle_not_found(self, payload: str) -> None:
        """ Handle a received NOT-FOUND message.
        """
        # XXX: NOT_FOUND is a valid message, but we shouldn't ever receive it unless the other peer is running with a
        #                modified code or if there is a bug
        self.log.warn('vertex not found? close connection', payload=payload)
        self.protocol.send_error_and_close_connection('Unexpected NOT_FOUND')

    def handle_error(self, payload: str) -> None:
        """ Override protocols original handle_error so we can recover a sync in progress.
        """
        assert self.protocol.connections is not None
        # forward message to overloaded handle_error:
        self.protocol.handle_error(payload)

    def update_synced(self, synced: bool) -> None:
        self._synced = synced

    def update_synced_mempool(self, value: bool) -> None:
        self._synced_mempool = value

    def watchdog(self) -> None:
        """Close connection if sync is stale."""
        if not self._is_running:
            return

        dt = self.reactor.seconds() - self._sync_started_at
        if dt > self.max_running_time:
            self.log.warn('stale syncing detected, closing connection')
            self.protocol.send_error_and_close_connection('stale syncing')

    @inlineCallbacks
    def run_sync(self) -> Generator[Any, Any, None]:
        """ Async step of the sync algorithm.

        This is the entrypoint for the sync. It is always safe to call this method.
        """
        if not self._is_enabled:
            self.log.debug('sync is disabled')
            return
        if self._is_running:
            # Already running...
            self.log.debug('already running')
            self.watchdog()
            return
        self._is_running = True
        self._sync_started_at = self.reactor.seconds()
        try:
            yield self._run_sync()
        except Exception:
            self.protocol.send_error_and_close_connection('internal error')
            self.log.error('unhandled exception', exc_info=True)
        finally:
            self._is_running = False

    @inlineCallbacks
    def _run_sync(self) -> Generator[Any, Any, None]:
        """ Actual implementation of the sync step logic in run_sync.
        """
        assert not self.receiving_stream
        assert not self.mempool_manager.is_running()
        assert self.protocol.connections is not None

        is_block_synced = yield self.run_sync_blocks()
        if is_block_synced:
            # our blocks are synced, so sync the mempool
            yield self.run_sync_mempool()

    @inlineCallbacks
    def run_sync_mempool(self) -> Generator[Any, Any, None]:
        self.state = PeerState.SYNCING_MEMPOOL
        is_mempool_synced = yield self.mempool_manager.run()
        self.update_synced_mempool(is_mempool_synced)

    def get_my_best_block(self) -> _HeightInfo:
        """Return my best block info."""
        bestblock = self.tx_storage.get_best_block()
        meta = bestblock.get_metadata()
        assert meta.validation.is_fully_connected()
        return _HeightInfo(height=bestblock.get_height(), id=bestblock.hash)

    @inlineCallbacks
    def run_sync_blocks(self) -> Generator[Any, Any, bool]:
        """Async step of the block syncing phase. Return True if we already have all other peer's blocks.

        Notice that we might already have all other peer's blocks while the other peer is still syncing.
        """
        assert self.tx_storage.indexes is not None
        self.state = PeerState.SYNCING_BLOCKS

        # Get my best block.
        my_best_block = self.get_my_best_block()

        # Get peer's best block
        self.peer_best_block = yield self.get_peer_best_block()
        assert self.peer_best_block is not None

        # Are we synced?
        if self.peer_best_block == my_best_block:
            # Yes, we are synced! \o/
            if not self.is_synced():
                self.log.info('blocks are synced', best_block=my_best_block)
            self.update_synced(True)
            self.send_relay(enable=True)
            self.synced_block = self.peer_best_block
            return True

        # Not synced but same blockchain?
        if self.peer_best_block.height <= my_best_block.height:
            # Is peer behind me at the same blockchain?
            common_block_hash = self.tx_storage.indexes.height.get(self.peer_best_block.height)
            if common_block_hash == self.peer_best_block.id:
                # If yes, nothing to sync from this peer.
                if not self.is_synced():
                    self.log.info('nothing to sync because peer is behind me at the same best blockchain',
                                  my_best_block=my_best_block, peer_best_block=self.peer_best_block)
                self.update_synced(True)
                self.send_relay(enable=True)
                self.synced_block = self.peer_best_block
                return True

        # Ok. We have blocks to sync.
        self.update_synced(False)
        self.send_relay(enable=False)

        # Find best common block
        self.synced_block = yield self.find_best_common_block(my_best_block, self.peer_best_block)
        if self.synced_block is None:
            # Find best common block failed. Try again soon.
            # This might happen if a reorg occurs during the search.
            self.log.debug('find_best_common_block failed.')
            return False

        self.log.debug('starting to sync blocks',
                       my_best_block=my_best_block,
                       peer_best_block=self.peer_best_block,
                       synced_block=self.synced_block)

        # Sync from common block
        try:
            yield self.start_blockchain_streaming(self.synced_block,
                                                  self.peer_best_block)
        except StreamingError as e:
            self.log.info('block streaming failed', reason=repr(e))
            self.send_stop_block_streaming()
            self.receiving_stream = False
            return False

        assert self._blk_streaming_client is not None
        partial_blocks = self._blk_streaming_client._partial_blocks
        if partial_blocks:
            score = self.get_partial_blocks_score(partial_blocks)
            best_block = self.tx_storage.get_best_block()
            best_block_score = best_block.get_metadata().score
            threshold = best_block_score * ORPHAN_CHAIN_THRESHOLD_MULTIPLIER
            if score < threshold:
                self.log.info('block streaming did not reach re-org threshold',
                              my_best_block=best_block.hash.hex(),
                              my_best_block_score=best_block_score,
                              orphan_chain_score=score,
                              orphan_chain_size=len(partial_blocks),
                              threshold=threshold)
                return False

            for i, blk in enumerate(partial_blocks):
                if self.tx_storage.can_validate_full(blk):
                    self.vertex_handler.on_new_block(blk, deps=[])
                else:
                    break
            partial_blocks = partial_blocks[i:]

        if partial_blocks:
            self.state = PeerState.SYNCING_TRANSACTIONS
            try:
                reason = yield self.start_transactions_streaming(partial_blocks)
            except StreamingError as e:
                self.log.info('tx streaming failed', reason=repr(e))
                self.send_stop_transactions_streaming()
                self.receiving_stream = False
                return False

            self.log.info('tx streaming finished', reason=reason)
            while reason == StreamEnd.LIMIT_EXCEEDED:
                reason = yield self.resume_transactions_streaming()

        self._blk_streaming_client = None
        self._tx_streaming_client = None
        return False

    def get_partial_blocks_score(self, partial_blocks: list[Block]) -> int:
        # XXX Handle when this block does not exist.
        score = partial_blocks[0].get_block_parent().get_metadata().score
        for blk in partial_blocks:
            score += weight_to_work(blk.weight)
        return score

    def get_tips(self) -> Deferred[list[bytes]]:
        """ Async method to request the remote peer's tips.
        """
        if self._deferred_tips is None:
            self._deferred_tips = Deferred()
            self.send_get_tips()
        else:
            assert self._receiving_tips is not None
        return self._deferred_tips

    def send_get_tips(self) -> None:
        """ Send a GET-TIPS message.
        """
        self.log.debug('get tips')
        self.send_message(ProtocolMessages.GET_TIPS)
        self._receiving_tips = []

    def handle_get_tips(self, _payload: str) -> None:
        """ Handle a GET-TIPS message.
        """
        assert self.tx_storage.indexes is not None
        assert self.tx_storage.indexes.mempool_tips is not None
        if self._is_streaming:
            self.log.warn('can\'t send while streaming')  # XXX: or can we?
            self.send_message(ProtocolMessages.MEMPOOL_END)
            return
        self.log.debug('handle_get_tips')
        # TODO Use a streaming of tips
        for tx_id in self.tx_storage.indexes.mempool_tips.get():
            self.send_tips(tx_id)
        self.log.debug('tips end')
        self.send_message(ProtocolMessages.TIPS_END)

    def send_tips(self, tx_id: bytes) -> None:
        """ Send a TIPS message.
        """
        self.send_message(ProtocolMessages.TIPS, json.dumps([tx_id.hex()]))

    def handle_tips(self, payload: str) -> None:
        """ Handle a TIPS message.
        """
        self.log.debug('tips', receiving_tips=self._receiving_tips)
        if self._receiving_tips is None:
            self.protocol.send_error_and_close_connection('TIPS not expected')
            return
        data = json.loads(payload)
        data = [bytes.fromhex(x) for x in data]
        # filter-out txs we already have
        try:
            self._receiving_tips.extend(
                VertexId(tx_id) for tx_id in data if not self.tx_storage.partial_vertex_exists(tx_id)
            )
        except ValueError:
            self.protocol.send_error_and_close_connection('Invalid trasaction ID received')
        # XXX: it's OK to do this *after* the extend because the payload is limited by the line protocol
        if len(self._receiving_tips) > self.max_receiving_tips:
            self.protocol.send_error_and_close_connection(f'Too many tips: {len(self._receiving_tips)}')

    def handle_tips_end(self, _payload: str) -> None:
        """ Handle a TIPS-END message.
        """
        assert self._receiving_tips is not None
        deferred = self._deferred_tips
        self._deferred_tips = None
        if deferred is None:
            self.protocol.send_error_and_close_connection('TIPS-END not expected')
            return
        deferred.callback(self._receiving_tips)
        self._receiving_tips = None

    def send_relay(self, *, enable: bool = True) -> None:
        """ Send a RELAY message.
        """
        self.log.debug('send_relay', enable=enable)
        self._inbound_relay_enabled = enable
        self.send_message(ProtocolMessages.RELAY, json.dumps(enable))

    def handle_relay(self, payload: str) -> None:
        """ Handle a RELAY message.
        """
        if not payload:
            # XXX: "legacy" nothing means enable
            self._outbound_relay_enabled = True
        else:
            val = json.loads(payload)
            if isinstance(val, bool):
                self._outbound_relay_enabled = val
            else:
                self.protocol.send_error_and_close_connection('RELAY: invalid value')
                return

    def start_blockchain_streaming(self,
                                   start_block: _HeightInfo,
                                   end_block: _HeightInfo) -> Deferred[StreamEnd]:
        """Request peer to start streaming blocks to us."""
        self._blk_streaming_client = BlockchainStreamingClient(self, start_block, end_block)
        quantity = self._blk_streaming_client._blk_max_quantity
        self.log.info('requesting blocks streaming',
                      start_block=start_block,
                      end_block=end_block,
                      quantity=quantity)
        self.send_get_next_blocks(start_block.id, end_block.id, quantity)
        return self._blk_streaming_client.wait()

    def stop_blk_streaming_server(self, response_code: StreamEnd) -> None:
        """Stop blockchain streaming server."""
        assert self._blk_streaming_server is not None
        self._blk_streaming_server.stop()
        self._blk_streaming_server = None
        self.send_blocks_end(response_code)

    def send_message(self, cmd: ProtocolMessages, payload: Optional[str] = None) -> None:
        """ Helper to send a message.
        """
        assert self.protocol.state is not None
        self.protocol.state.send_message(cmd, payload)

    @inlineCallbacks
    def find_best_common_block(self,
                               my_best_block: _HeightInfo,
                               peer_best_block: _HeightInfo) -> Generator[Any, Any, Optional[_HeightInfo]]:
        """ Search for the highest block/height where we're synced.
        """
        self.log.debug('find_best_common_block', peer_best_block=peer_best_block, my_best_block=my_best_block)

        # Run an n-ary search in the interval [lo, hi).
        # `lo` is always a height where we are synced.
        # `hi` is always a height where sync state is unknown.
        hi = min(peer_best_block, my_best_block, key=lambda x: x.height)
        lo = _HeightInfo(height=0, id=self._settings.GENESIS_BLOCK_HASH)

        while hi.height - lo.height > 1:
            self.log.debug('find_best_common_block n-ary search query', lo=lo, hi=hi)
            step = math.ceil((hi.height - lo.height) / 10)
            heights = list(range(lo.height, hi.height, step))
            heights.append(hi.height)

            block_info_list = yield self.get_peer_block_hashes(heights)
            block_info_list.sort(key=lambda x: x.height, reverse=True)

            # As we are supposed to be always synced at `lo`, we expect to receive a response
            # with at least one item equals to lo. If it does not happen, we stop the search
            # and return None. This might be caused when a reorg occurs during the search.
            if not block_info_list:
                self.log.info('n-ary search failed because it got a response with no lo_block_info',
                              lo=lo,
                              hi=hi)
                return None
            lo_block_info = block_info_list[-1]
            if lo_block_info != lo:
                self.log.info('n-ary search failed because lo != lo_block_info',
                              lo=lo,
                              hi=hi,
                              lo_block_info=lo_block_info)
                return None

            for info in block_info_list:
                try:
                    # We must check only fully validated transactions.
                    blk = self.tx_storage.get_transaction(info.id)
                except TransactionDoesNotExist:
                    hi = info
                else:
                    assert blk.get_metadata().validation.is_fully_connected()
                    assert isinstance(blk, Block)
                    assert info.height == blk.get_height()
                    lo = info
                    break

        self.log.debug('find_best_common_block n-ary search finished', lo=lo, hi=hi)
        return lo

    @inlineCallbacks
    def on_block_complete(self, blk: Block, vertex_list: list[Transaction]) -> Generator[Any, Any, None]:
        """This method is called when a block and its transactions are downloaded."""
        # Note: Any vertex and block could have already been added by another concurrent syncing peer.
        try:
            yield self.vertex_handler.on_new_block(blk, deps=vertex_list)
        except InvalidNewTransaction:
            self.protocol.send_error_and_close_connection('invalid vertex received')

    def get_peer_block_hashes(self, heights: list[int]) -> Deferred[list[_HeightInfo]]:
        """ Returns the peer's block hashes in the given heights.
        """
        if self._deferred_peer_block_hashes is not None:
            raise Exception('latest_deferred is not None')
        self.send_get_peer_block_hashes(heights)
        self._deferred_peer_block_hashes = Deferred()
        return self._deferred_peer_block_hashes

    def send_get_peer_block_hashes(self, heights: list[int]) -> None:
        """ Send a GET-PEER-BLOCK-HASHES message.
        """
        payload = json.dumps(heights)
        self.send_message(ProtocolMessages.GET_PEER_BLOCK_HASHES, payload)

    def handle_get_peer_block_hashes(self, payload: str) -> None:
        """ Handle a GET-PEER-BLOCK-HASHES message.
        """
        assert self.tx_storage.indexes is not None
        heights = json.loads(payload)
        if len(heights) > 20:
            self.log.info('too many heights', heights_qty=len(heights))
            self.protocol.send_error_and_close_connection('GET-PEER-BLOCK-HASHES: too many heights')
            return
        data = []
        for h in heights:
            blk_hash = self.tx_storage.indexes.height.get(h)
            if blk_hash is None:
                break
            blk = self.tx_storage.get_transaction(blk_hash)
            if blk.get_metadata().voided_by:
                break
            data.append((h, blk_hash.hex()))
        payload = json.dumps(data)
        self.send_message(ProtocolMessages.PEER_BLOCK_HASHES, payload)

    def handle_peer_block_hashes(self, payload: str) -> None:
        """ Handle a PEER-BLOCK-HASHES message.
        """
        data = json.loads(payload)
        data = [_HeightInfo(height=h, id=bytes.fromhex(block_hash)) for (h, block_hash) in data]
        deferred = self._deferred_peer_block_hashes
        self._deferred_peer_block_hashes = None
        if deferred:
            deferred.callback(data)

    def send_get_next_blocks(self, start_hash: bytes, end_hash: bytes, quantity: int) -> None:
        """ Send a PEER-BLOCK-HASHES message.
        """
        payload = GetNextBlocksPayload(
            start_hash=start_hash,
            end_hash=end_hash,
            quantity=quantity,
        )
        self.send_message(ProtocolMessages.GET_NEXT_BLOCKS, payload.json())
        self.receiving_stream = True

    def handle_get_next_blocks(self, payload: str) -> None:
        """ Handle a GET-NEXT-BLOCKS message.
        """
        self.log.debug('handle GET-NEXT-BLOCKS', payload=payload)
        if self._is_streaming:
            self.protocol.send_error_and_close_connection('GET-NEXT-BLOCKS received before previous one finished')
            return
        data = GetNextBlocksPayload.parse_raw(payload)
        start_block = self._validate_block(data.start_hash)
        if start_block is None:
            return
        end_block = self._validate_block(data.end_hash)
        if end_block is None:
            return
        self.send_next_blocks(
            start_block=start_block,
            end_hash=data.end_hash,
            quantity=data.quantity,
        )

    def _validate_block(self, _hash: VertexId) -> Optional[Block]:
        """Validate block given in the GET-NEXT-BLOCKS and GET-TRANSACTIONS-BFS messages."""
        try:
            blk = self.tx_storage.get_transaction(_hash)
        except TransactionDoesNotExist:
            self.log.debug('requested block not found', blk_id=_hash.hex())
            self.send_message(ProtocolMessages.NOT_FOUND, _hash.hex())
            return None

        if not isinstance(blk, Block):
            self.log.debug('request block is not a block', blk_id=_hash.hex())
            self.send_message(ProtocolMessages.NOT_FOUND, _hash.hex())
            return None

        return blk

    def send_next_blocks(self, start_block: Block, end_hash: bytes, quantity: int) -> None:
        """ Send a NEXT-BLOCKS message.
        """
        self.log.debug('start NEXT-BLOCKS stream')
        if self._blk_streaming_server is not None and self._blk_streaming_server.is_running:
            self.stop_blk_streaming_server(StreamEnd.PER_REQUEST)
        limit = min(quantity, self.DEFAULT_STREAMING_LIMIT)
        self._blk_streaming_server = BlockchainStreamingServer(self, start_block, end_hash, limit=limit)
        self._blk_streaming_server.start()

    def send_blocks(self, blk: Block) -> None:
        """ Send a BLOCKS message.

        This message is called from a streamer for each block to being sent.
        """
        payload = base64.b64encode(bytes(blk)).decode('ascii')
        self.send_message(ProtocolMessages.BLOCKS, payload)

    def send_blocks_end(self, response_code: StreamEnd) -> None:
        """ Send a BLOCKS-END message.

        This message marks the end of a stream of BLOCKS messages. It is mandatory to send any BLOCKS messages before,
        in which case it would be an "empty" stream.
        """
        payload = str(int(response_code))
        self.log.debug('send BLOCKS-END', payload=payload)
        self.send_message(ProtocolMessages.BLOCKS_END, payload)

    def handle_blocks_end(self, payload: str) -> None:
        """ Handle a BLOCKS-END message.

        This is important to know that the other peer will not send any BLOCKS messages anymore as a response to a
        previous command.
        """
        self.log.debug('recv BLOCKS-END', payload=payload)

        response_code = StreamEnd(int(payload))
        self.receiving_stream = False
        assert self.protocol.connections is not None

        if self.state is not PeerState.SYNCING_BLOCKS:
            self.log.error('unexpected BLOCKS-END', state=self.state, response_code=response_code.name)
            self.protocol.send_error_and_close_connection('Not expecting to receive BLOCKS-END message')
            return

        assert self._blk_streaming_client is not None
        self._blk_streaming_client.handle_blocks_end(response_code)
        self.log.debug('block streaming ended', reason=str(response_code))

    def handle_blocks(self, payload: str) -> None:
        """ Handle a BLOCKS message.
        """
        if self.state is not PeerState.SYNCING_BLOCKS:
            self.log.error('unexpected BLOCK', state=self.state)
            self.protocol.send_error_and_close_connection('Not expecting to receive BLOCK message')
            return

        assert self.protocol.connections is not None

        blk_bytes = base64.b64decode(payload)
        blk = self.vertex_parser.deserialize(blk_bytes)
        if not isinstance(blk, Block):
            # Not a block. Punish peer?
            return
        blk.storage = self.tx_storage

        assert self._blk_streaming_client is not None
        self._blk_streaming_client.handle_blocks(blk)

    def send_stop_block_streaming(self) -> None:
        """ Send a STOP-BLOCK-STREAMING message.

        This asks the other peer to stop a running block stream.
        """
        self.send_message(ProtocolMessages.STOP_BLOCK_STREAMING)

    def handle_stop_block_streaming(self, payload: str) -> None:
        """ Handle a STOP-BLOCK-STREAMING message.

        This means the remote peer wants to stop the current block stream.
        """
        if not self._blk_streaming_server or not self._is_streaming:
            self.log.debug('got stop streaming message with no streaming running')
            return

        self.log.debug('got stop streaming message')
        self.stop_blk_streaming_server(StreamEnd.PER_REQUEST)

    def send_stop_transactions_streaming(self) -> None:
        """ Send a STOP-TRANSACTIONS-STREAMING message.

        This asks the other peer to stop a running block stream.
        """
        self.send_message(ProtocolMessages.STOP_TRANSACTIONS_STREAMING)

    def handle_stop_transactions_streaming(self, payload: str) -> None:
        """ Handle a STOP-TRANSACTIONS-STREAMING message.

        This means the remote peer wants to stop the current block stream.
        """
        if not self._tx_streaming_server or not self._is_streaming:
            self.log.debug('got stop streaming message with no streaming running')
            return

        self.log.debug('got stop streaming message')
        self.stop_tx_streaming_server(StreamEnd.PER_REQUEST)

    def get_peer_best_block(self) -> Deferred[_HeightInfo]:
        """ Async call to get the remote peer's best block.
        """
        if self._deferred_best_block is not None:
            raise Exception('latest_deferred is not None')

        self.send_get_best_block()
        self._deferred_best_block = Deferred()
        return self._deferred_best_block

    def send_get_best_block(self) -> None:
        """ Send a GET-BEST-BLOCK messsage.
        """
        self.send_message(ProtocolMessages.GET_BEST_BLOCK)

    def handle_get_best_block(self, _payload: str) -> None:
        """ Handle a GET-BEST-BLOCK message.
        """
        best_block = self.tx_storage.get_best_block()
        meta = best_block.get_metadata()
        assert meta.validation.is_fully_connected()
        payload = BestBlockPayload(
            block=best_block.hash,
            height=best_block.static_metadata.height,
        )
        self.send_message(ProtocolMessages.BEST_BLOCK, payload.json())

    def handle_best_block(self, payload: str) -> None:
        """ Handle a BEST-BLOCK message.
        """
        data = BestBlockPayload.parse_raw(payload)
        best_block = _HeightInfo(height=data.height, id=data.block)

        deferred = self._deferred_best_block
        self._deferred_best_block = None
        if deferred:
            deferred.callback(best_block)

    def start_transactions_streaming(self, partial_blocks: list[Block]) -> Deferred[StreamEnd]:
        """Request peer to start streaming transactions to us."""
        self._tx_streaming_client = TransactionStreamingClient(self,
                                                               partial_blocks,
                                                               limit=self.DEFAULT_STREAMING_LIMIT)

        start_from: list[bytes] = []
        first_block_hash = partial_blocks[0].hash
        last_block_hash = partial_blocks[-1].hash
        self.log.info('requesting transactions streaming',
                      start_from=[x.hex() for x in start_from],
                      first_block=first_block_hash.hex(),
                      last_block=last_block_hash.hex())
        self.send_get_transactions_bfs(start_from, first_block_hash, last_block_hash)
        return self._tx_streaming_client.wait()

    def resume_transactions_streaming(self) -> Deferred[StreamEnd]:
        """Resume transaction streaming."""
        assert self._tx_streaming_client is not None
        idx = self._tx_streaming_client._idx
        partial_blocks = self._tx_streaming_client.partial_blocks[idx:]
        assert partial_blocks
        start_from = list(self._tx_streaming_client._waiting_for)
        first_block_hash = partial_blocks[0].hash
        last_block_hash = partial_blocks[-1].hash
        self.log.info('requesting transactions streaming',
                      start_from=[x.hex() for x in start_from],
                      first_block=first_block_hash.hex(),
                      last_block=last_block_hash.hex())
        self.send_get_transactions_bfs(start_from, first_block_hash, last_block_hash)
        return self._tx_streaming_client.resume()

    def stop_tx_streaming_server(self, response_code: StreamEnd) -> None:
        """Stop transaction streaming server."""
        assert self._tx_streaming_server is not None
        self._tx_streaming_server.stop()
        self._tx_streaming_server = None
        self.send_transactions_end(response_code)

    def send_get_transactions_bfs(self,
                                  start_from: list[bytes],
                                  first_block_hash: bytes,
                                  last_block_hash: bytes) -> None:
        """ Send a GET-TRANSACTIONS-BFS message.

        This will request a BFS of all transactions starting from start_from list and walking back into parents/inputs.

        The start_from list can contain blocks, but they won't be sent. For example if a block B1 has T1 and T2 as
        transaction parents, start_from=[B1] and start_from=[T1, T2] will have the same result.

        The stop condition is reaching transactions/inputs that have a first_block of height less or equal than the
        height of until_first_block. The other peer will return an empty response if it doesn't have any of the
        transactions in start_from or if it doesn't have the until_first_block block.
        """
        start_from_hexlist = [tx.hex() for tx in start_from]
        first_block_hash_hex = first_block_hash.hex()
        last_block_hash_hex = last_block_hash.hex()
        self.log.debug('send_get_transactions_bfs',
                       start_from=start_from_hexlist,
                       first_block_hash=first_block_hash_hex,
                       last_block_hash=last_block_hash_hex)
        payload = GetTransactionsBFSPayload(
            start_from=start_from,
            first_block_hash=first_block_hash,
            last_block_hash=last_block_hash,
        )
        self.send_message(ProtocolMessages.GET_TRANSACTIONS_BFS, payload.json())
        self.receiving_stream = True

    def handle_get_transactions_bfs(self, payload: str) -> None:
        """ Handle a GET-TRANSACTIONS-BFS message.
        """
        if self._is_streaming:
            self.log.warn('ignore GET-TRANSACTIONS-BFS, already streaming')
            return
        data = GetTransactionsBFSPayload.parse_raw(payload)

        if len(data.start_from) > MAX_GET_TRANSACTIONS_BFS_LEN:
            self.log.error('too many transactions in GET-TRANSACTIONS-BFS', state=self.state)
            self.protocol.send_error_and_close_connection('Too many transactions in GET-TRANSACTIONS-BFS')
            return

        first_block = self._validate_block(data.first_block_hash)
        if first_block is None:
            return

        last_block = self._validate_block(data.last_block_hash)
        if last_block is None:
            return

        start_from_txs = []
        for start_from_hash in data.start_from:
            try:
                tx = self.tx_storage.get_transaction(start_from_hash)
            except TransactionDoesNotExist:
                # In case the tx does not exist we send a NOT-FOUND message
                self.log.debug('requested start_from_hash not found', start_from_hash=start_from_hash.hex())
                self.send_message(ProtocolMessages.NOT_FOUND, start_from_hash.hex())
                return
            meta = tx.get_metadata()
            if meta.first_block != first_block.hash:
                self.log.debug('requested start_from not confirmed by first_block',
                               vertex_id=tx.hash.hex(),
                               first_block=first_block.hash.hex(),
                               vertex_first_block=meta.first_block)
                self.send_transactions_end(StreamEnd.INVALID_PARAMS)
                return
            start_from_txs.append(tx)

        self.send_transactions_bfs(start_from_txs, first_block, last_block)

    def send_transactions_bfs(self,
                              start_from: list[BaseTransaction],
                              first_block: Block,
                              last_block: Block) -> None:
        """ Start a transactions BFS stream.
        """
        if self._tx_streaming_server is not None and self._tx_streaming_server.is_running:
            self.stop_tx_streaming_server(StreamEnd.PER_REQUEST)
        self._tx_streaming_server = TransactionsStreamingServer(self,
                                                                start_from,
                                                                first_block,
                                                                last_block,
                                                                limit=self.DEFAULT_STREAMING_LIMIT)
        self._tx_streaming_server.start()

    def send_transaction(self, tx: Transaction) -> None:
        """ Send a TRANSACTION message.
        """
        # payload = bytes(tx).hex()  # fails for big transactions
        payload = base64.b64encode(bytes(tx)).decode('ascii')
        self.send_message(ProtocolMessages.TRANSACTION, payload)

    def send_transactions_end(self, response_code: StreamEnd) -> None:
        """ Send a TRANSACTIONS-END message.
        """
        payload = str(int(response_code))
        self.log.debug('send TRANSACTIONS-END', payload=payload)
        self.send_message(ProtocolMessages.TRANSACTIONS_END, payload)

    def handle_transactions_end(self, payload: str) -> None:
        """ Handle a TRANSACTIONS-END message.
        """
        self.log.debug('recv TRANSACTIONS-END', payload=payload)

        response_code = StreamEnd(int(payload))
        self.receiving_stream = False
        assert self.protocol.connections is not None

        if self.state is not PeerState.SYNCING_TRANSACTIONS:
            self.log.error('unexpected TRANSACTIONS-END', state=self.state, response_code=response_code.name)
            self.protocol.send_error_and_close_connection('Not expecting to receive TRANSACTIONS-END message')
            return

        assert self._tx_streaming_client is not None
        self._tx_streaming_client.handle_transactions_end(response_code)
        self.log.debug('transaction streaming ended', reason=str(response_code))

    def handle_transaction(self, payload: str) -> None:
        """ Handle a TRANSACTION message.
        """
        assert self.protocol.connections is not None

        # tx_bytes = bytes.fromhex(payload)
        tx_bytes = base64.b64decode(payload)
        tx = self.vertex_parser.deserialize(tx_bytes)
        if not isinstance(tx, Transaction):
            self.log.warn('not a transaction', hash=tx.hash_hex)
            # Not a transaction. Punish peer?
            return
        tx.storage = self.tx_storage

        assert self._tx_streaming_client is not None
        assert isinstance(tx, Transaction)
        self._tx_streaming_client.handle_transaction(tx)

    @inlineCallbacks
    def get_tx(self, tx_id: bytes) -> Generator[Deferred, Any, BaseTransaction]:
        """ Async method to get a transaction from the db/cache or to download it.
        """
        tx = self._get_tx_cache.get(tx_id)
        if tx is not None:
            self.log.debug('tx in cache', tx=tx_id.hex())
            return tx
        try:
            tx = self.tx_storage.get_transaction(tx_id)
        except TransactionDoesNotExist:
            tx = yield self.get_data(tx_id, 'mempool')
            assert tx is not None
            if tx.hash != tx_id:
                self.protocol.send_error_and_close_connection(f'DATA mempool {tx_id.hex()} hash mismatch')
                raise
        return tx

    def get_data(self, tx_id: bytes, origin: str) -> Deferred[BaseTransaction]:
        """ Async method to request a tx by id.
        """
        # TODO: deal with stale `get_data` calls
        if origin != 'mempool':
            raise ValueError(f'origin={origin} not supported, only origin=mempool is supported')
        deferred = self._deferred_txs.get(tx_id, None)
        if deferred is None:
            deferred = self._deferred_txs[tx_id] = Deferred()
            self.send_get_data(tx_id, origin=origin)
            self.log.debug('get_data of new tx_id', deferred=deferred, key=tx_id.hex())
        else:
            # XXX: can we re-use deferred objects like this?
            self.log.debug('get_data of same tx_id, reusing deferred', deferred=deferred, key=tx_id.hex())
        return deferred

    def _on_get_data(self, tx: BaseTransaction, origin: str) -> None:
        """ Called when a requested tx is received.
        """
        deferred = self._deferred_txs.pop(tx.hash, None)
        if deferred is None:
            # Peer sent the wrong transaction?!
            # XXX: ban peer?
            self.protocol.send_error_and_close_connection(f'DATA {origin}: with tx that was not requested')
            return
        self.log.debug('get_data fulfilled', deferred=deferred, key=tx.hash.hex())
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
        """ Send a GET-DATA message for a given txid.
        """
        data = {
            'txid': txid.hex(),
        }
        if origin is not None:
            data['origin'] = origin
        payload = json.dumps(data)
        self.send_message(ProtocolMessages.GET_DATA, payload)

    def handle_get_data(self, payload: str) -> None:
        """ Handle a GET-DATA message.
        """
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
        """ Handle a DATA message.
        """
        if not self._inbound_relay_enabled:
            # Unsolicited vertex.
            # Should we have a grace period when incoming relay is disabled? Is the decay mechanism enough?
            self.protocol.increase_misbehavior_score(weight=1)
            return

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
            tx = self.vertex_parser.deserialize(data)
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
        if self.protocol.node.tx_storage.get_genesis(tx.hash):
            # We just got the data of a genesis tx/block. What should we do?
            # Will it reduce peer reputation score?
            return

        tx.storage = self.protocol.node.tx_storage

        if self.tx_storage.partial_vertex_exists(tx.hash):
            # transaction already added to the storage, ignore it
            # XXX: maybe we could add a hash blacklist and punish peers propagating known bad txs
            self.tx_storage.compare_bytes_with_local_tx(tx)
            return

        # Unsolicited vertices must be fully validated.
        if not self.tx_storage.can_validate_full(tx):
            self.log.debug('skipping tx received in real time from peer',
                           tx=tx.hash_hex, peer=self.protocol.get_peer_id())
            return

        # Finally, it is either an unsolicited new transaction or block.
        self.log.debug('tx received in real time from peer', tx=tx.hash_hex, peer=self.protocol.get_peer_id())
        try:
            success = self.vertex_handler.on_new_relayed_vertex(tx)
            if success:
                self.protocol.connections.send_tx_to_peers(tx)
        except InvalidNewTransaction:
            self.protocol.send_error_and_close_connection('invalid vertex received')
