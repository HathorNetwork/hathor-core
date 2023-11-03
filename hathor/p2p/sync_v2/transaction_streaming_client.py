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

from typing import TYPE_CHECKING

from structlog import get_logger
from twisted.internet.defer import Deferred

from hathor.p2p.sync_v2.exception import (
    InvalidVertexError,
    StreamingError,
    TooManyRepeatedVerticesError,
    TooManyVerticesReceivedError,
)
from hathor.p2p.sync_v2.streamers import DEFAULT_STREAMING_LIMIT, StreamEnd
from hathor.transaction import BaseTransaction
from hathor.transaction.exceptions import HathorError
from hathor.types import VertexId

if TYPE_CHECKING:
    from hathor.p2p.sync_v2.agent import NodeBlockSync

logger = get_logger()


class TransactionStreamingClient:
    def __init__(self,
                 sync_agent: 'NodeBlockSync',
                 start_from: list[bytes],
                 start_block: bytes,
                 end_block: bytes) -> None:
        self.sync_agent = sync_agent
        self.protocol = self.sync_agent.protocol
        self.tx_storage = self.sync_agent.tx_storage
        self.manager = self.sync_agent.manager

        self.log = logger.new(peer=self.protocol.get_short_peer_id())

        self.start_from = start_from
        self.start_block = start_block
        self.end_block = end_block

        # Let's keep it at "infinity" until a known issue is fixed.
        self.max_repeated_transactions = 1_000_000

        self._deferred: Deferred[StreamEnd] = Deferred()

        self._tx_received: int = 0
        self._tx_repeated: int = 0

        self._tx_max_quantity = DEFAULT_STREAMING_LIMIT

    def wait(self) -> Deferred[StreamEnd]:
        """Return the deferred."""
        return self._deferred

    def fails(self, reason: 'StreamingError') -> None:
        """Fail the execution by resolving the deferred with an error."""
        self._deferred.errback(reason)

    def partial_vertex_exists(self, vertex_id: VertexId) -> bool:
        """Return true if the vertex exists no matter its validation state."""
        with self.tx_storage.allow_partially_validated_context():
            return self.tx_storage.transaction_exists(vertex_id)

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
        is_duplicated = False
        if self.partial_vertex_exists(tx.hash):
            # We reached a block we already have. Skip it.
            self._tx_repeated += 1
            is_duplicated = True
            if self._tx_repeated > self.max_repeated_transactions:
                self.log.debug('too many repeated transactions received', total_repeated=self._tx_repeated)
                self.fails(TooManyRepeatedVerticesError())

        try:
            # this methods takes care of checking if the block already exists,
            # it will take care of doing at least a basic validation
            if is_duplicated:
                self.log.debug('tx early terminate?', tx_id=tx.hash.hex())
            else:
                self.log.debug('tx received', tx_id=tx.hash.hex())
            self.sync_agent.on_new_tx(tx, propagate_to_peers=False, quiet=True, reject_locked_reward=True)
        except HathorError:
            self.fails(InvalidVertexError())
            return
        else:
            # XXX: debugging log, maybe add timing info
            if self._tx_received % 100 == 0:
                self.log.debug('tx streaming in progress', txs_received=self._tx_received)

    def handle_transactions_end(self, response_code: StreamEnd) -> None:
        """This method is called by the sync agent when a TRANSACTIONS-END message is received."""
        if self._deferred.called:
            return
        self._deferred.callback(response_code)
