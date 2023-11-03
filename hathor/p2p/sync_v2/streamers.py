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

from enum import IntFlag
from typing import TYPE_CHECKING, Optional

from structlog import get_logger
from twisted.internet.interfaces import IConsumer, IDelayedCall, IPushProducer
from zope.interface import implementer

from hathor.transaction import BaseTransaction, Block, Transaction
from hathor.transaction.storage.traversal import BFSOrderWalk
from hathor.utils.zope import asserted_cast

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol
    from hathor.p2p.sync_v2.agent import NodeBlockSync

logger = get_logger()

DEFAULT_STREAMING_LIMIT = 1000


class StreamEnd(IntFlag):
    END_HASH_REACHED = 0
    NO_MORE_BLOCKS = 1
    LIMIT_EXCEEDED = 2
    STREAM_BECAME_VOIDED = 3  # this will happen when the current chain becomes voided while it is being sent
    TX_NOT_CONFIRMED = 4

    def __str__(self):
        if self is StreamEnd.END_HASH_REACHED:
            return 'end hash reached'
        elif self is StreamEnd.NO_MORE_BLOCKS:
            return 'end of blocks, no more blocks to download from this peer'
        elif self is StreamEnd.LIMIT_EXCEEDED:
            return 'streaming limit exceeded'
        elif self is StreamEnd.STREAM_BECAME_VOIDED:
            return 'streamed block chain became voided'
        elif self is StreamEnd.TX_NOT_CONFIRMED:
            return 'streamed reached a tx that is not confirmed'
        else:
            raise ValueError(f'invalid StreamEnd value: {self.value}')


@implementer(IPushProducer)
class _StreamingServerBase:
    def __init__(self, node_sync: 'NodeBlockSync', *, limit: int = DEFAULT_STREAMING_LIMIT):
        self.node_sync = node_sync
        self.protocol: 'HathorProtocol' = node_sync.protocol
        assert self.protocol.transport is not None
        consumer = asserted_cast(IConsumer, self.protocol.transport)
        self.consumer = consumer

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


class BlockchainStreamingServer(_StreamingServerBase):
    def __init__(self, node_sync: 'NodeBlockSync', start_block: Block, end_hash: bytes,
                 *, limit: int = DEFAULT_STREAMING_LIMIT, reverse: bool = False):
        super().__init__(node_sync, limit=limit)

        self.start_block = start_block
        self.current_block: Optional[Block] = start_block
        self.end_hash = end_hash
        self.reverse = reverse

    def send_next(self) -> None:
        """Push next block to peer."""
        assert self.is_running
        assert self.is_producing
        assert self.current_block is not None

        cur = self.current_block
        assert cur is not None
        assert cur.hash is not None

        meta = cur.get_metadata()
        if meta.voided_by:
            self.stop()
            self.node_sync.send_blocks_end(StreamEnd.STREAM_BECAME_VOIDED)
            return

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


class TransactionsStreamingServer(_StreamingServerBase):
    """Streams all transactions confirmed by the given block, from right to left (decreasing timestamp).
    """

    def __init__(self,
                 node_sync: 'NodeBlockSync',
                 start_from: list[BaseTransaction],
                 first_block_hash: bytes,
                 last_block_hash: bytes,
                 *,
                 limit: int = DEFAULT_STREAMING_LIMIT) -> None:
        # XXX: is limit needed for tx streaming? Or let's always send all txs for
        # a block? Very unlikely we'll reach this limit
        super().__init__(node_sync, limit=limit)

        assert len(start_from) > 0
        assert start_from[0].storage is not None
        self.storage = start_from[0].storage
        self.first_block_hash = first_block_hash
        self.last_block_hash = last_block_hash
        self.last_block_height = 0

        self.bfs = BFSOrderWalk(self.storage, is_dag_verifications=True, is_dag_funds=True, is_left_to_right=False)
        self.iter = self.bfs.run(start_from, skip_root=False)

    def start(self) -> None:
        super().start()
        last_blk = self.storage.get_transaction(self.last_block_hash)
        assert isinstance(last_blk, Block)
        self.last_block_height = last_blk.get_height()

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
            self.node_sync.send_transactions_end(StreamEnd.END_HASH_REACHED)
            return

        if cur.is_block:
            if cur.hash == self.last_block_hash:
                self.bfs.skip_neighbors(cur)
            self.schedule_if_needed()
            return

        assert isinstance(cur, Transaction)
        assert cur.hash is not None

        cur_metadata = cur.get_metadata()
        if cur_metadata.first_block is None:
            self.log.debug('reached a tx that is not confirming, continuing anyway')
            # XXX: related to issue #711
            # self.stop()
            # self.node_sync.send_transactions_end(StreamEnd.TX_NOT_CONFIRMED)
            # return
        else:
            assert cur_metadata.first_block is not None
            first_blk_meta = self.storage.get_metadata(cur_metadata.first_block)
            assert first_blk_meta is not None
            confirmed_by_height = first_blk_meta.height
            assert confirmed_by_height is not None
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
            self.node_sync.send_transactions_end(StreamEnd.LIMIT_EXCEEDED)
            return

        self.schedule_if_needed()
