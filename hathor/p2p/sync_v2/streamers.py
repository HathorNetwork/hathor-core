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
from typing import TYPE_CHECKING, Iterable, Iterator, Optional, Union

from structlog import get_logger
from twisted.internet.interfaces import IConsumer, IDelayedCall, IPushProducer
from zope.interface import implementer

from hathor.transaction import BaseTransaction, Block, Transaction
from hathor.transaction.storage.traversal import BFSOrderWalk
from hathor.util import not_none
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
    INVALID_PARAMS = 5
    INTERNAL_ERROR = 6
    PER_REQUEST = 7

    def __str__(self):
        if self == StreamEnd.END_HASH_REACHED:
            return 'end hash reached'
        elif self == StreamEnd.NO_MORE_BLOCKS:
            return 'end of blocks, no more blocks to download from this peer'
        elif self == StreamEnd.LIMIT_EXCEEDED:
            return 'streaming limit exceeded'
        elif self == StreamEnd.STREAM_BECAME_VOIDED:
            return 'streamed block chain became voided'
        elif self == StreamEnd.TX_NOT_CONFIRMED:
            return 'streamed reached a tx that is not confirmed'
        elif self == StreamEnd.INVALID_PARAMS:
            return 'streamed with invalid parameters'
        elif self == StreamEnd.INTERNAL_ERROR:
            return 'internal error'
        elif self == StreamEnd.PER_REQUEST:
            return 'stopped per request'
        else:
            raise ValueError(f'invalid StreamEnd value: {self.value}')


@implementer(IPushProducer)
class _StreamingServerBase:
    def __init__(self, sync_agent: 'NodeBlockSync', *, limit: int = DEFAULT_STREAMING_LIMIT):
        self.sync_agent = sync_agent
        self.tx_storage = self.sync_agent.tx_storage
        self.protocol: 'HathorProtocol' = sync_agent.protocol

        assert self.protocol.transport is not None
        consumer = asserted_cast(IConsumer, self.protocol.transport)
        self.consumer = consumer

        self.counter = 0
        self.limit = limit

        self.is_running: bool = False
        self.is_producing: bool = False

        self.delayed_call: Optional[IDelayedCall] = None
        self.log = logger.new(peer=sync_agent.protocol.get_short_peer_id())

    def schedule_if_needed(self) -> None:
        """Schedule `send_next` if needed."""
        if not self.is_running:
            return

        if not self.is_producing:
            return

        if self.delayed_call and self.delayed_call.active():
            return

        self.delayed_call = self.sync_agent.reactor.callLater(0, self.safe_send_next)

    def safe_send_next(self) -> None:
        """Call send_next() and schedule next call."""
        try:
            self.send_next()
        except Exception:
            self._stop_streaming_server(StreamEnd.INTERNAL_ERROR)
            raise
        else:
            self.schedule_if_needed()

    def _stop_streaming_server(self, response_code: StreamEnd) -> None:
        """Stop streaming server."""
        raise NotImplementedError

    def start(self) -> None:
        """Start pushing."""
        self.log.debug('start streaming')
        assert not self.sync_agent._is_streaming
        self.sync_agent._is_streaming = True
        self.is_running = True
        self.consumer.registerProducer(self, True)
        self.resumeProducing()

    def stop(self) -> None:
        """Stop pushing."""
        self.log.debug('stop streaming')
        assert self.sync_agent._is_streaming
        self.is_running = False
        self.pauseProducing()
        self.consumer.unregisterProducer()
        self.sync_agent._is_streaming = False

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
    def __init__(self, sync_agent: 'NodeBlockSync', start_block: Block, end_hash: bytes,
                 *, limit: int = DEFAULT_STREAMING_LIMIT, reverse: bool = False):
        super().__init__(sync_agent, limit=limit)

        self.start_block = start_block
        self.current_block: Optional[Block] = start_block
        self.end_hash = end_hash
        self.reverse = reverse

    def _stop_streaming_server(self, response_code: StreamEnd) -> None:
        self.sync_agent.stop_blk_streaming_server(response_code)

    def send_next(self) -> None:
        """Push next block to peer."""
        assert self.is_running
        assert self.is_producing
        assert self.current_block is not None

        cur = self.current_block
        assert cur is not None

        meta = cur.get_metadata()
        if meta.voided_by:
            self.sync_agent.stop_blk_streaming_server(StreamEnd.STREAM_BECAME_VOIDED)
            return

        if cur.hash == self.end_hash:
            # only send the last when not reverse
            if not self.reverse:
                self.log.debug('send next block', height=cur.get_height(), blk_id=cur.hash.hex())
                self.sync_agent.send_blocks(cur)
            self.sync_agent.stop_blk_streaming_server(StreamEnd.END_HASH_REACHED)
            return

        self.counter += 1

        self.log.debug('send next block', height=cur.get_height(), blk_id=cur.hash.hex())
        self.sync_agent.send_blocks(cur)

        if self.reverse:
            self.current_block = cur.get_block_parent()
        else:
            self.current_block = cur.get_next_block_best_chain()

        # XXX: don't send the genesis or the current block
        if self.current_block is None or self.current_block.is_genesis:
            self.sync_agent.stop_blk_streaming_server(StreamEnd.NO_MORE_BLOCKS)
            return

        if self.counter >= self.limit:
            self.sync_agent.stop_blk_streaming_server(StreamEnd.LIMIT_EXCEEDED)
            return


class TransactionsStreamingServer(_StreamingServerBase):
    """Streams all transactions confirmed by the given block, from right to left (decreasing timestamp).

    If the start_from parameter is not empty, the BFS (Breadth-First Search) for the first block will commence
    using the provided hashes. This mechanism enables streaming requests to continue from a specific point
    should there be interruptions or issues.
    """

    def __init__(self,
                 sync_agent: 'NodeBlockSync',
                 start_from: list[BaseTransaction],
                 first_block: Block,
                 last_block: Block,
                 *,
                 limit: int = DEFAULT_STREAMING_LIMIT) -> None:
        # XXX: is limit needed for tx streaming? Or let's always send all txs for
        # a block? Very unlikely we'll reach this limit
        super().__init__(sync_agent, limit=limit)

        self.first_block: Block = first_block
        self.last_block: Block = last_block
        self.start_from = start_from

        # Validate that all transactions in `start_from` are confirmed by the first block.
        for tx in start_from:
            assert tx.get_metadata().first_block == self.first_block.hash

        self.current_block: Optional[Block] = self.first_block
        self.bfs = BFSOrderWalk(self.tx_storage, is_dag_verifications=True, is_dag_funds=True, is_left_to_right=False)
        self.iter = self.get_iter()

    def _stop_streaming_server(self, response_code: StreamEnd) -> None:
        self.sync_agent.stop_tx_streaming_server(response_code)

    def get_iter(self) -> Iterator[BaseTransaction]:
        """Return an iterator that yields all transactions confirmed by each block in sequence."""
        root: Union[BaseTransaction, Iterable[BaseTransaction]]
        skip_root: bool
        while self.current_block:
            if not self.start_from:
                root = self.current_block
                skip_root = True
            else:
                root = self.start_from
                skip_root = False
            self.log.debug('iterating over transactions from block',
                           block=self.current_block.hash.hex(),
                           height=self.current_block.get_height(),
                           start_from=self.start_from,
                           skip_root=skip_root)
            it = self.bfs.run(root, skip_root=skip_root)
            yield from it
            if self.current_block == self.last_block:
                break

            # Check if this block is still in the best blockchain.
            if self.current_block.get_metadata().voided_by:
                self.sync_agent.stop_tx_streaming_server(StreamEnd.STREAM_BECAME_VOIDED)
                return

            self.current_block = self.current_block.get_next_block_best_chain()
            self.start_from.clear()

    def send_next(self) -> None:
        """Push next transaction to peer."""
        assert self.is_running
        assert self.is_producing

        try:
            cur = next(self.iter)
        except StopIteration:
            # nothing more to send
            self.log.debug('no more transactions, stopping streaming')
            self.sync_agent.stop_tx_streaming_server(StreamEnd.END_HASH_REACHED)
            return

        # Skip blocks.
        if cur.is_block:
            self.bfs.skip_neighbors()
            return

        assert isinstance(cur, Transaction)

        cur_metadata = cur.get_metadata()
        if cur_metadata.first_block is None:
            self.log.debug('reached a tx that is not confirmed, stopping streaming')
            self.sync_agent.stop_tx_streaming_server(StreamEnd.TX_NOT_CONFIRMED)
            self.bfs.add_neighbors()
            return

        # Check if tx is confirmed by the `self.current_block` or any next block.
        assert cur_metadata.first_block is not None
        assert self.current_block is not None
        first_block = self.tx_storage.get_block(cur_metadata.first_block)
        if not_none(first_block.static_metadata.height) < not_none(self.current_block.static_metadata.height):
            self.log.debug('skipping tx: out of current block')
            self.bfs.skip_neighbors()
            return

        self.log.debug('send next transaction', tx_id=cur.hash.hex())
        self.sync_agent.send_transaction(cur)

        self.counter += 1
        if self.counter >= self.limit:
            self.log.debug('limit exceeded, stopping streaming')
            self.sync_agent.stop_tx_streaming_server(StreamEnd.LIMIT_EXCEEDED)
        self.bfs.add_neighbors()
