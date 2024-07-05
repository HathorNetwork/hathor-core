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

from typing import TYPE_CHECKING, Optional

from structlog import get_logger

from hathor.pubsub import PubSubManager
from hathor.transaction import BaseTransaction, Block

if TYPE_CHECKING:
    from hathor.consensus.block_consensus import BlockConsensusAlgorithm
    from hathor.consensus.consensus import ConsensusAlgorithm
    from hathor.consensus.transaction_consensus import TransactionConsensusAlgorithm

logger = get_logger()

_base_transaction_log = logger.new()


class ConsensusAlgorithmContext:
    """ An instance of this class holds all the relevant information related to a single run of a consensus update.
    """

    consensus: 'ConsensusAlgorithm'
    pubsub: PubSubManager
    block_algorithm: 'BlockConsensusAlgorithm'
    transaction_algorithm: 'TransactionConsensusAlgorithm'
    txs_affected: set[BaseTransaction]
    reorg_common_block: Optional[Block]

    def __init__(self, consensus: 'ConsensusAlgorithm', pubsub: PubSubManager) -> None:
        self.consensus = consensus
        self.pubsub = pubsub
        self.block_algorithm = self.consensus.block_algorithm_factory(self)
        self.transaction_algorithm = self.consensus.transaction_algorithm_factory(self)
        self.txs_affected = set()
        self.reorg_common_block = None

    def save(self, tx: BaseTransaction) -> None:
        """Only metadata is ever saved in a consensus update."""
        assert tx.storage is not None
        self.txs_affected.add(tx)
        tx.storage.save_transaction(tx, only_metadata=True)

    def mark_as_reorg(self, common_block: Block) -> None:
        """Must only be called once, will raise an assert error if called twice."""
        assert self.reorg_common_block is None
        self.reorg_common_block = common_block
