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

from abc import abstractmethod
from typing import TYPE_CHECKING, Iterator

from hathor.indexes.base_index import BaseIndex
from hathor.indexes.scope import Scope
from hathor.transaction import BaseTransaction, Block

if TYPE_CHECKING:  # pragma: no cover
    from hathor.transaction.storage import TransactionStorage


# XXX: this arbitrary height limit must fit in a u32 (4-bytes unsigned), so it can be stored easily on rocksdb
INF_HEIGHT: int = 2**32 - 1

SCOPE = Scope(
    include_blocks=True,
    include_txs=True,
    include_voided=True,
    include_partial=True
)


def get_requested_from_height(tx: BaseTransaction) -> int:
    """Return the height of the block that requested (directly or indirectly) the download of this transaction.

    If this value cannot be determined (either for the lack of a metadata or otherwise), the INF_HEIGHT constant is
    returned instead. So there will always be a value (it's never None).

    This is used to help prioritize which transaction to start from next on sync-v2 when syncing the transactions
    after downloading a chain of blocks.
    """
    assert tx.storage is not None
    if tx.is_block:
        assert isinstance(tx, Block)
        return tx.get_height()
    first_block = tx.get_metadata().first_block
    if first_block is None:
        # XXX: consensus did not run yet to update first_block, what should we do?
        #      I'm defaulting the height to `inf` (practically), this should make it heightest priority when
        #      choosing which transactions to fetch next
        return INF_HEIGHT
    block = tx.storage.get_transaction(first_block)
    assert isinstance(block, Block)
    return block.get_height()


class DepsIndex(BaseIndex):
    """ Index of dependencies between transactions

    This index exists to accelerate queries related to the partial validation mechanism needed by sync-v2. More
    specifically these queries:

    - Which transactions need to be downloaded next? That is, all the transactions which are a reverse dependency of
      all the transactions that aren't fully validated;
    - Which transactions can we validate next? That is, all the transactions which are not fully validated but can be
      fully validated because all of its dependencies have been downloaded and are now fully validated;

    These queries would normally need traversals that are at the very **least** O(N) with N being the total number of
    transactions in the blockchain. The specific speed up with the index varies but should at **most** O(M) with M
    being the total number of transactions in the index.

    Terminology:

    - a tx is ready: said when all of its dependencies are in storage and are fully-valid
    - (direct) dependencies of tx: all transactions that tx needs to be validated, which are its parents and its inputs
    - reverse dependencies of tx: all transactions that depend on tx for being validated, that is if tx1 depends on tx2
      and tx3, and tx4 depends on tx3 and tx5, the reverse dependencies of tx3 would be tx1 and tx4.
    - needed transactions: all transactions which need to be downloaded (we also store which tx asked for a transaction
      to be downloaded)


    Examples:

    - Consider the following complete DAG (it doesn't matter if a tx is a block or not):

               +----------------v
      A -----> B -----> C ----> D
      +--> E --^        ^
           +------------+

      These are all the dependency relations (direct/directly is implied, as shown on the first examples):

      - A does not have any (direct) dependency
      - A is a reverse dependency of B and E
      - B (directly) depends on A and E
      - B is a reverse dependency of C and D
      - C depends on B and E
      - C is a reverse dependency of D
      - D depends on B and C
      - D does not have any reverse dependency
      - E depends on A
      - E is a reverse dependency of B and C

      These are some alternative ways to express some of those relations:

      - the list of reverse dependencies of A is [B, E]
      - the list of (direct) dependencies of B is [A, E]

    - The "needed" and "ready" concepts should be easier to understand, but are harder to ascii-draw, thus I skipped
      them.
    """

    def get_scope(self) -> Scope:
        return SCOPE

    def init_loop_step(self, tx: BaseTransaction) -> None:
        tx_meta = tx.get_metadata()
        if tx_meta.voided_by:
            return
        self.add_tx(tx, partial=False)

    def update(self, tx: BaseTransaction) -> None:
        assert tx.hash is not None
        tx_meta = tx.get_metadata()
        if tx_meta.validation.is_fully_connected():
            self.remove_ready_for_validation(tx.hash)

    @abstractmethod
    def add_tx(self, tx: BaseTransaction, partial: bool = True) -> None:
        """Update 'deps' and 'needed' sub-indexes, removing them when necessary (i.e. validation is complete).

        Note: this method is idempotent.
        """
        raise NotImplementedError

    @abstractmethod
    def del_tx(self, tx: BaseTransaction) -> None:
        """Update 'deps' and 'needed' sub-indexes, removing them when necessary (i.e. validation is complete).

        Note: this method is idempotent.
        """
        raise NotImplementedError

    @abstractmethod
    def remove_ready_for_validation(self, tx: bytes) -> None:
        """Removes from ready for validation set.
        """
        raise NotImplementedError

    @abstractmethod
    def next_ready_for_validation(self, tx_storage: 'TransactionStorage', *, dry_run: bool = False) -> Iterator[bytes]:
        """Yields and removes all txs ready for validation even if they become ready while iterating.
        """
        raise NotImplementedError

    @abstractmethod
    def iter(self) -> Iterator[bytes]:
        """Iterate through all hashes depended by any tx or block."""
        raise NotImplementedError

    @abstractmethod
    def _iter_needed_txs(self) -> Iterator[bytes]:
        """Iterate through all txs that need to be downloaded, this is only used in tests, and thus is 'internal'."""
        raise NotImplementedError

    @abstractmethod
    def known_children(self, tx: BaseTransaction) -> list[bytes]:
        """Return the hashes of all reverse dependencies that are children of the given tx.

        That is, they depend on `tx` because they are children of `tx`, and not because `tx` is an input. This is
        useful for pre-filling the children metadata, which would otherwise only be updated when
        `update_initial_metadata` is called on the child-tx.
        """
        raise NotImplementedError

    @abstractmethod
    def has_needed_tx(self) -> bool:
        """Whether there is any tx on the needed tx index."""
        raise NotImplementedError

    @abstractmethod
    def is_tx_needed(self, tx: bytes) -> bool:
        """Whether a tx is in the requested tx list."""
        raise NotImplementedError

    @abstractmethod
    def remove_from_needed_index(self, tx: bytes) -> None:
        """Remove tx from needed txs index, tx doesn't need to be in the index."""
        raise NotImplementedError

    @abstractmethod
    def get_next_needed_tx(self) -> bytes:
        """Choose the start hash for downloading the needed txs"""
        raise NotImplementedError
