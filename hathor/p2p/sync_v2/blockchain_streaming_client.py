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

from typing import TYPE_CHECKING, Optional

from structlog import get_logger
from twisted.internet.defer import Deferred

from hathor.p2p.sync_v2.exception import (
    BlockNotConnectedToPreviousBlock,
    InvalidVertexError,
    StreamingError,
    TooManyRepeatedVerticesError,
    TooManyVerticesReceivedError,
)
from hathor.p2p.sync_v2.streamers import StreamEnd
from hathor.transaction import Block
from hathor.transaction.exceptions import HathorError

if TYPE_CHECKING:
    from hathor.p2p.sync_v2.agent import NodeBlockSync, _HeightInfo

logger = get_logger()


class BlockchainStreamingClient:
    def __init__(self, sync_agent: 'NodeBlockSync', start_block: '_HeightInfo', end_block: '_HeightInfo') -> None:
        self.sync_agent = sync_agent
        self.protocol = self.sync_agent.protocol
        self.tx_storage = self.sync_agent.tx_storage
        self.vertex_handler = self.sync_agent.vertex_handler

        self.log = logger.new(peer=self.protocol.get_short_peer_id())

        self.start_block = start_block
        self.end_block = end_block

        # When syncing blocks we start streaming with all peers
        # so the moment I get some repeated blocks, I stop the download
        # because it's probably a streaming that I've already received
        self.max_repeated_blocks = 10

        self._deferred: Deferred[StreamEnd] = Deferred()

        self._blk_received: int = 0
        self._blk_repeated: int = 0

        self._blk_max_quantity = self.end_block.height - self.start_block.height + 1
        self._reverse: bool = False
        if self._blk_max_quantity < 0:
            self._blk_max_quantity = -self._blk_max_quantity
            self._reverse = True

        self._last_received_block: Optional[Block] = None

        self._partial_blocks: list[Block] = []

    def wait(self) -> Deferred[StreamEnd]:
        """Return the deferred."""
        return self._deferred

    def fails(self, reason: 'StreamingError') -> None:
        """Fail the execution by resolving the deferred with an error."""
        self._deferred.errback(reason)

    def handle_blocks(self, blk: Block) -> None:
        """This method is called by the sync agent when a BLOCKS message is received."""
        if self._deferred.called:
            return

        self._blk_received += 1
        if self._blk_received > self._blk_max_quantity:
            self.log.warn('too many blocks received',
                          blk_received=self._blk_received,
                          blk_max_quantity=self._blk_max_quantity)
            self.fails(TooManyVerticesReceivedError())
            return

        # TODO Run basic verification. We will uncomment these lines after we finish
        # refactoring our verification services.
        #
        # if not blk.is_genesis:
        #     try:
        #         self.manager.verification_service.validate_basic(blk)
        #     except TxValidationError as e:
        #         self.fails(InvalidVertexError(repr(e)))
        #         return

        # Check for repeated blocks.
        is_duplicated = False
        if self.tx_storage.partial_vertex_exists(blk.hash):
            # We reached a block we already have. Skip it.
            self._blk_repeated += 1
            is_duplicated = True
            if self._blk_repeated > self.max_repeated_blocks:
                self.log.info('too many repeated block received', total_repeated=self._blk_repeated)
                self.fails(TooManyRepeatedVerticesError())
            self._last_received_block = blk
            return

        # basic linearity validation, crucial for correctly predicting the next block's height
        if self._reverse:
            if self._last_received_block and blk.hash != self._last_received_block.get_block_parent_hash():
                self.fails(BlockNotConnectedToPreviousBlock())
                return
        else:
            if self._last_received_block and blk.get_block_parent_hash() != self._last_received_block.hash:
                self.fails(BlockNotConnectedToPreviousBlock())
                return

        if is_duplicated:
            self.log.debug('block early terminate?', blk_id=blk.hash.hex())
        else:
            self.log.debug('block received', blk_id=blk.hash.hex())

        if self.tx_storage.can_validate_full(blk):
            best_block = self.tx_storage.get_best_block()
            is_orphan_block = (blk.get_block_parent() != best_block)
            if is_orphan_block:
                self.log.debug('orphan block, deferring processing', blk=blk.hash.hex())
                self._partial_blocks.append(blk)
            else:
                try:
                    self.vertex_handler.on_new_block(blk, deps=[])
                except HathorError:
                    self.fails(InvalidVertexError(blk.hash.hex()))
                    return
        else:
            self._partial_blocks.append(blk)

        self._last_received_block = blk
        self._blk_repeated = 0
        # XXX: debugging log, maybe add timing info
        if self._blk_received % 500 == 0:
            self.log.debug('block streaming in progress', blocks_received=self._blk_received)

    def handle_blocks_end(self, response_code: StreamEnd) -> None:
        """This method is called by the sync agent when a BLOCKS-END message is received."""
        if self._deferred.called:
            return
        self._deferred.callback(response_code)
