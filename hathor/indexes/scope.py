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

from typing import TYPE_CHECKING, Iterator, NamedTuple

from hathor.transaction.base_transaction import BaseTransaction
from hathor.vertex_metadata import VertexMetadataService

if TYPE_CHECKING:  # pragma: no cover
    from hathor.transaction.storage import TransactionStorage


class Scope(NamedTuple):
    """ This class models the scope of transactions that an index is interested in.

    It is used for both selecting the optimal iterator for all the indexes that need to be initialized and for
    filtering which transactions are fed to the index.
    """
    include_blocks: bool
    include_txs: bool
    include_voided: bool
    # XXX: these have a default value since it should be really rare to have it different
    include_partial: bool = False
    topological_order: bool = True  # if False than ordering doesn't matter

    # XXX: this is used to join the scope of multiple indexes to get an overall scope that includes everything that
    #      each individual scope needs, the OR operator was chosen because it represents well the operation of keeping
    #      a property if either A or B needs it
    def __or__(self, other):
        # XXX: note that this doesn't necessarily have to be OR operations between properties, we want the operations
        #      that broaden the scope, and not narrow it.
        # XXX: in the case of topological_order, we want to keep the "topological" ordering if any of them requires it,
        #      so it also is an OR operator
        return Scope(
            include_blocks=self.include_blocks | other.include_blocks,
            include_txs=self.include_txs | other.include_txs,
            include_voided=self.include_voided | other.include_voided,
            include_partial=self.include_partial | other.include_partial,
            topological_order=self.topological_order | other.topological_order,
        )

    def matches(self, tx: BaseTransaction, *, metadata_service: VertexMetadataService) -> bool:
        """ Check if a transaction matches this scope, True means the index is interested in this transaction.
        """
        if tx.is_block and not self.include_blocks:
            return False
        if tx.is_transaction and not self.include_txs:
            return False
        tx_meta = metadata_service.get(tx)
        if tx_meta.voided_by and not self.include_voided:
            return False
        if not tx_meta.validation.is_fully_connected() and not self.include_partial:
            return False
        # XXX: self.topologial_order doesn't affect self.match()
        # passed all checks
        return True

    def get_iterator(self, tx_storage: 'TransactionStorage') -> Iterator[BaseTransaction]:
        """ This method returns an iterator that only yields transaction that match the current scope.
        """
        iterator: Iterator[BaseTransaction]
        # XXX: this is to mark if the chosen iterator will yield partial transactions
        iterator_covers_partial: bool
        if self.topological_order:
            iterator = tx_storage.topological_iterator()
            iterator_covers_partial = False
        else:
            iterator = tx_storage.get_all_transactions()
            iterator_covers_partial = True
        for tx in iterator:
            if self.matches(tx, metadata_service=tx_storage.metadata_service):
                yield tx
        if self.include_partial and not iterator_covers_partial:
            # if partial transactions are needed and were not already covered, we use get_all_transactions, which
            # includes partial transactions, to yield them, skipping all that aren't partial
            for tx in tx_storage.get_all_transactions():
                tx_meta = tx_storage.metadata_service.get(tx)
                if tx_meta.validation.is_fully_connected():
                    continue
                if self.matches(tx, metadata_service=tx_storage.metadata_service):
                    yield tx
