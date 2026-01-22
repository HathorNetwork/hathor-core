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
from typing import TYPE_CHECKING, Any, Generator, Optional

from structlog import get_logger
from twisted.internet.defer import Deferred, inlineCallbacks

from hathor.feature_activation.utils import Features
from hathor.p2p.sync_v2.exception import (
    InvalidVertexError,
    StreamingError,
    TooManyVerticesReceivedError,
    UnexpectedVertex,
)
from hathor.p2p.sync_v2.streamers import StreamEnd
from hathor.transaction import BaseTransaction, Transaction
from hathor.transaction.exceptions import HathorError, TxValidationError
from hathor.types import VertexId
from hathor.verification.verification_params import VerificationParams

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
        self.verification_service = self.protocol.node.verification_service

        # XXX: Since it's not straightforward to get the correct block, it's OK to just disable checkdatasig counting,
        #      it will be correctly enabled when doing a full validation anyway.
        #      We can also set the `nc_block_root_id` to `None` because we only call `verify_basic`,
        #      which doesn't need it.
        self.verification_params = VerificationParams(
            nc_block_root_id=None,
            features=Features(
                count_checkdatasig_op=False,
                nano=False,
                fee_tokens=False,
            )
        )

        self.reactor = sync_agent.reactor
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
        self._queue: deque[Transaction] = deque()

        # Keeps the response code if the streaming has ended.
        self._response_code: Optional[StreamEnd] = None

        # Index to the current block.
        self._idx: int = 0

        # Set of hashes we are waiting to receive.
        self._waiting_for: set[VertexId] = set()

        # In-memory database of transactions already received but still
        # waiting for dependencies.
        self._db: dict[VertexId, Transaction] = {}
        self._existing_deps: set[VertexId] = set()

        self._prepare_block(self.partial_blocks[0])

    def wait(self) -> Deferred[StreamEnd]:
        """Return the deferred."""
        return self._deferred

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

    def handle_transaction(self, tx: Transaction) -> None:
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
            self.reactor.callLater(0, self.process_queue)

    @inlineCallbacks
    def process_queue(self) -> Generator[Any, Any, None]:
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
            yield self._process_transaction(tx)
        finally:
            self._is_processing = False

        self.reactor.callLater(0, self.process_queue)

    @inlineCallbacks
    def _process_transaction(self, tx: Transaction) -> Generator[Any, Any, None]:
        """Process transaction."""

        # Run basic verification.
        if not tx.is_genesis:
            try:
                self.verification_service.verify_basic(tx, self.verification_params)
            except TxValidationError as e:
                self.fails(InvalidVertexError(repr(e)))
                return

        # Any repeated transaction will fail this check because they will
        # not belong to the waiting list.
        if tx.hash not in self._waiting_for:
            if tx.hash in self._db:
                # This case might happen during a resume, so we just log and keep syncing.
                self.log.debug('duplicated vertex received', tx_id=tx.hash.hex())
                self._update_dependencies(tx)
            elif tx.hash in self._existing_deps:
                # This case might happen if we already have the transaction from another sync.
                self.log.debug('existing vertex received', tx_id=tx.hash.hex())
                self._update_dependencies(tx)
            else:
                self.log.info('unexpected vertex received', tx_id=tx.hash.hex())
                self.fails(UnexpectedVertex(tx.hash.hex()))
            return
        self._waiting_for.remove(tx.hash)

        self._update_dependencies(tx)

        assert isinstance(tx, Transaction)
        self._db[tx.hash] = tx

        if not self._waiting_for:
            self.log.debug('no pending dependencies, processing buffer')
            while not self._waiting_for:
                result = yield self._execute_and_prepare_next()
                if not result:
                    break
        else:
            self.log.debug('pending dependencies', counter=len(self._waiting_for))

        if self._tx_received % 100 == 0:
            self.log.debug('tx streaming in progress', txs_received=self._tx_received)

    def _update_dependencies(self, vertex: BaseTransaction) -> None:
        """Update _existing_deps and _waiting_for with the dependencies."""
        for dep in vertex.get_all_dependencies():
            if self.tx_storage.transaction_exists(dep) or dep in self._db:
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

    @inlineCallbacks
    def _execute_and_prepare_next(self) -> Generator[Any, Any, bool]:
        """Add the block and its vertices to the DAG."""
        assert not self._waiting_for

        blk = self.partial_blocks[self._idx]
        vertex_list = list(self._db.values())
        vertex_list.sort(key=lambda v: v.timestamp)

        try:
            yield self.sync_agent.on_block_complete(blk, vertex_list)
        except HathorError as e:
            self.fails(InvalidVertexError(repr(e)))
            return False

        self._idx += 1
        if self._idx >= len(self.partial_blocks):
            return False

        self._prepare_block(self.partial_blocks[self._idx])
        return True

    def _prepare_block(self, blk: 'Block') -> None:
        """Reset everything for the next block. It also adds blocks that have no dependencies."""
        self._waiting_for.clear()
        self._db.clear()
        self._existing_deps.clear()

        self._update_dependencies(blk)
