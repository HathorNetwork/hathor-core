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

from typing import TYPE_CHECKING, Iterator

from structlog import get_logger
from twisted.internet.defer import Deferred

from hathor.p2p.sync_v2.exception import InvalidVertexError, StreamingError, TooManyVerticesReceivedError
from hathor.p2p.sync_v2.streamers import StreamEnd
from hathor.transaction import BaseTransaction
from hathor.transaction.exceptions import HathorError, TxValidationError
from hathor.types import VertexId

if TYPE_CHECKING:
    from hathor.p2p.sync_v2.agent import NodeBlockSync
    from hathor.transaction import Block

logger = get_logger()


class TransactionStreamingClient:
    def __init__(self,
                 sync_agent: 'NodeBlockSync',
                 partial_blocks: list['Block'],
                 *,
                 limit: int) -> None:
        self.sync_agent = sync_agent
        self.protocol = self.sync_agent.protocol
        self.tx_storage = self.sync_agent.tx_storage
        self.manager = self.sync_agent.manager

        self.log = logger.new(peer=self.protocol.get_short_peer_id())

        self.partial_blocks = partial_blocks

        self._deferred: Deferred[StreamEnd] = Deferred()

        self._tx_received: int = 0

        self._tx_max_quantity = limit

        self._idx: int = 0
        self._buffer: list[VertexId] = []
        self._waiting_for: set[VertexId] = set()
        self._db: dict[VertexId, BaseTransaction] = {}

        self._prepare_block(self.partial_blocks[0])

    def wait(self) -> Deferred[StreamEnd]:
        """Return the deferred."""
        return self._deferred

    def resume(self) -> Deferred[StreamEnd]:
        """Resume receiving vertices."""
        assert self._deferred.called
        self._tx_received = 0
        self._deferred = Deferred()
        return self._deferred

    def fails(self, reason: 'StreamingError') -> None:
        """Fail the execution by resolving the deferred with an error."""
        self._deferred.errback(reason)

    def handle_transaction(self, tx: BaseTransaction) -> None:
        """This method is called by the sync agent when a TRANSACTION message is received."""
        if self._deferred.called:
            return

        self._tx_received += 1
        if self._tx_received > self._tx_max_quantity:
            self.log.warn('too many transactions received',
                          tx_received=self._tx_received,
                          tx_max_quantity=self._tx_max_quantity)
            self.fails(TooManyVerticesReceivedError())
            return

        assert tx.hash is not None

        self.log.debug('tx received', tx_id=tx.hash.hex())

        # Run basic verification.
        if not tx.is_genesis:
            try:
                self.manager.verification_service.verify_basic(tx)
            except TxValidationError as e:
                self.fails(InvalidVertexError(repr(e)))
                return

        # Any repeated transaction will fail this check because they will
        # not belong to the waiting list.
        if tx.hash not in self._waiting_for:
            if tx.hash in self._db:
                # This case might happen during a resume, so we just log and keep syncing.
                self.log.info('duplicated vertex received', tx_id=tx.hash.hex())
            else:
                # TODO Uncomment the following code to fail on receiving unexpected vertices.
                # self.fails(UnexpectedVertex(tx.hash.hex()))
                self.log.info('unexpected vertex received', tx_id=tx.hash.hex())
            return
        self._waiting_for.remove(tx.hash)

        for dep in self.get_missing_deps(tx):
            self.log.debug('adding dependency', tx_id=tx.hash.hex(), dep=dep.hex())
            self._waiting_for.add(dep)

        self._db[tx.hash] = tx
        self._buffer.append(tx.hash)

        if not self._waiting_for:
            self.log.debug('no pending dependencies, processing buffer')
            self._execute_and_prepare_next()
        else:
            self.log.debug('pending dependencies', counter=len(self._waiting_for))

        if self._tx_received % 100 == 0:
            self.log.debug('tx streaming in progress', txs_received=self._tx_received)

    def get_missing_deps(self, tx: BaseTransaction) -> Iterator[bytes]:
        """Return missing dependencies."""
        for dep in tx.get_all_dependencies():
            if self.tx_storage.transaction_exists(dep):
                continue
            if dep in self._db:
                continue
            yield dep

    def handle_transactions_end(self, response_code: StreamEnd) -> None:
        """This method is called by the sync agent when a TRANSACTIONS-END message is received."""
        if self._deferred.called:
            return
        self.log.info('transactions streaming ended', waiting_for=len(self._waiting_for))
        self._deferred.callback(response_code)

    def _execute_and_prepare_next(self) -> None:
        """Add the block and its vertices to the DAG."""
        assert not self._waiting_for

        blk = self.partial_blocks[self._idx]
        vertex_list = [self._db[_id] for _id in self._buffer]
        vertex_list.sort(key=lambda v: v.timestamp)

        try:
            self.sync_agent.on_block_complete(blk, vertex_list)
        except HathorError as e:
            self.fails(InvalidVertexError(repr(e)))
            return

        self._idx += 1
        if self._idx < len(self.partial_blocks):
            self._prepare_block(self.partial_blocks[self._idx])

    def _prepare_block(self, blk: 'Block') -> None:
        """Reset everything for the next block. It also adds blocks that have no dependencies."""
        self._buffer.clear()
        self._waiting_for.clear()
        self._db.clear()

        # Add pending dependencies from block.
        for dep in blk.get_all_dependencies():
            if not self.tx_storage.transaction_exists(dep):
                self._waiting_for.add(dep)

        # If block is ready to be added then do it.
        if not self._waiting_for:
            self._execute_and_prepare_next()
