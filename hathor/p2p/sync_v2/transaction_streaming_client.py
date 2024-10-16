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

from collections import deque
from typing import TYPE_CHECKING, Optional

from structlog import get_logger
from twisted.internet.defer import Deferred

from hathor.p2p import P2PDependencies
from hathor.p2p.sync_v2.exception import (
    InvalidVertexError,
    StreamingError,
    TooManyVerticesReceivedError,
    UnexpectedVertex,
)
from hathor.p2p.sync_v2.streamers import StreamEnd
from hathor.transaction import BaseTransaction
from hathor.transaction.exceptions import HathorError, TxValidationError
from hathor.types import VertexId
from hathor.utils.twisted import call_coro_later

if TYPE_CHECKING:
    from hathor.p2p.sync_v2.agent import NodeBlockSync
    from hathor.transaction import Block

logger = get_logger()


class TransactionStreamingClient:
    def __init__(
        self,
        sync_agent: 'NodeBlockSync',
        partial_blocks: list['Block'],
        *,
        limit: int,
        dependencies: P2PDependencies,
    ) -> None:
        self.dependencies = dependencies
        self.sync_agent = sync_agent
        self.protocol = self.sync_agent.protocol
        self.reactor = self.dependencies.reactor

        self.log = logger.new(peer=self.protocol.get_short_peer_id())

        # List of blocks from which we will receive transactions.
        self.partial_blocks = partial_blocks

        # True if we are processing a transaction.
        self._is_processing: bool = False

        # Deferred return to the sync agent.
        self._deferred: Deferred[StreamEnd] = Deferred()

        # Number of transactions received.
        self._tx_received: int = 0

        # Maximum number of transactions to be received.
        self._tx_max_quantity = limit

        # Queue of transactions waiting to be processed.
        self._queue: deque[BaseTransaction] = deque()

        # Keeps the response code if the streaming has ended.
        self._response_code: Optional[StreamEnd] = None

        # Index to the current block.
        self._idx: int = 0

        # Set of hashes we are waiting to receive.
        self._waiting_for: set[VertexId] = set()

        # In-memory database of transactions already received but still
        # waiting for dependencies.
        self._db: dict[VertexId, BaseTransaction] = {}
        self._existing_deps: set[VertexId] = set()

    async def wait(self) -> StreamEnd:
        """Return the deferred."""
        await self._prepare_block(self.partial_blocks[0])
        return await self._deferred

    def resume(self) -> Deferred[StreamEnd]:
        """Resume receiving vertices."""
        assert self._deferred.called
        self._tx_received = 0
        self._response_code = None
        self._deferred = Deferred()
        return self._deferred

    def fails(self, reason: 'StreamingError') -> None:
        """Fail the execution by resolving the deferred with an error."""
        if self._deferred.called:
            self.log.warn('already failed before', new_reason=repr(reason))
            return
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

        self.log.debug('tx received', tx_id=tx.hash.hex())
        self._queue.append(tx)
        assert len(self._queue) <= self._tx_max_quantity

        if not self._is_processing:
            call_coro_later(self.reactor, 0, self.process_queue)

    async def process_queue(self) -> None:
        """Process next transaction in the queue."""
        if self._deferred.called:
            return

        if self._is_processing:
            return

        if not self._queue:
            self.check_end()
            return

        self._is_processing = True
        try:
            tx = self._queue.popleft()
            self.log.debug('processing tx', tx_id=tx.hash.hex())
            await self._process_transaction(tx)
        finally:
            self._is_processing = False

        call_coro_later(self.reactor, 0, self.process_queue)

    async def _process_transaction(self, tx: BaseTransaction) -> None:
        """Process transaction."""

        # Run basic verification.
        if not tx.is_genesis:
            try:
                self.dependencies.verify_basic(tx)
            except TxValidationError as e:
                self.fails(InvalidVertexError(repr(e)))
                return

        # Any repeated transaction will fail this check because they will
        # not belong to the waiting list.
        if tx.hash not in self._waiting_for:
            if tx.hash in self._db:
                # This case might happen during a resume, so we just log and keep syncing.
                self.log.debug('duplicated vertex received', tx_id=tx.hash.hex())
                await self._update_dependencies(tx)
            elif tx.hash in self._existing_deps:
                # This case might happen if we already have the transaction from another sync.
                self.log.debug('existing vertex received', tx_id=tx.hash.hex())
                await self._update_dependencies(tx)
            else:
                self.log.info('unexpected vertex received', tx_id=tx.hash.hex())
                self.fails(UnexpectedVertex(tx.hash.hex()))
            return
        self._waiting_for.remove(tx.hash)

        await self._update_dependencies(tx)

        self._db[tx.hash] = tx

        if not self._waiting_for:
            self.log.debug('no pending dependencies, processing buffer')
            while not self._waiting_for:
                result = await self._execute_and_prepare_next()
                if not result:
                    break
        else:
            self.log.debug('pending dependencies', counter=len(self._waiting_for))

        if self._tx_received % 100 == 0:
            self.log.debug('tx streaming in progress', txs_received=self._tx_received)

    async def _update_dependencies(self, tx: BaseTransaction) -> None:
        """Update _existing_deps and _waiting_for with the dependencies."""
        for dep in tx.get_all_dependencies():
            if await self.dependencies.vertex_exists(dep) or dep in self._db:
                self._existing_deps.add(dep)
            else:
                self._waiting_for.add(dep)

    def handle_transactions_end(self, response_code: StreamEnd) -> None:
        """This method is called by the sync agent when a TRANSACTIONS-END message is received."""
        if self._deferred.called:
            return
        assert self._response_code is None
        self._response_code = response_code
        self.check_end()

    def check_end(self) -> None:
        """Check if the streaming has ended."""
        if self._response_code is None:
            return

        if self._queue:
            return

        self.log.info('transactions streaming ended', reason=self._response_code, waiting_for=len(self._waiting_for))
        self._deferred.callback(self._response_code)

    async def _execute_and_prepare_next(self) -> bool:
        """Add the block and its vertices to the DAG."""
        assert not self._waiting_for

        blk = self.partial_blocks[self._idx]
        vertex_list = list(self._db.values())
        vertex_list.sort(key=lambda v: v.timestamp)

        try:
            await self.sync_agent.on_block_complete(blk, vertex_list)
        except HathorError as e:
            self.fails(InvalidVertexError(repr(e)))
            return False

        self._idx += 1
        if self._idx >= len(self.partial_blocks):
            return False

        await self._prepare_block(self.partial_blocks[self._idx])
        return True

    async def _prepare_block(self, blk: 'Block') -> None:
        """Reset everything for the next block. It also adds blocks that have no dependencies."""
        self._waiting_for.clear()
        self._db.clear()
        self._existing_deps.clear()

        await self._update_dependencies(blk)
