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
from collections.abc import Collection
from itertools import chain
from typing import TYPE_CHECKING, Iterable, Iterator, Optional, cast

import structlog

from hathor.indexes.base_index import BaseIndex
from hathor.indexes.scope import Scope
from hathor.transaction import BaseTransaction, Transaction
from hathor.util import not_none

if TYPE_CHECKING:  # pragma: no cover
    from hathor.transaction.storage import TransactionStorage

SCOPE = Scope(
    include_blocks=False,
    include_txs=True,
    include_voided=True,
    topological_order=False,
)


def any_non_voided(tx_storage: 'TransactionStorage', hashes: Iterable[bytes]) -> bool:
    """
    If there's any vertex with hash in hashes that is not voided, this function returns True, otherwise False.

    Notice that this means that an empty `hashes` also returns False.
    """
    for tx_hash in hashes:
        tx = tx_storage.get_transaction(tx_hash)
        tx_meta = tx.get_metadata()
        if not tx_meta.voided_by:
            return True
    return False


class MempoolTipsIndex(BaseIndex):
    """Index to access the tips of the mempool transactions, which haven't been confirmed by a block."""

    def get_scope(self) -> Scope:
        return SCOPE

    @abstractmethod
    def update(self, tx: BaseTransaction, *, force_remove: bool = False) -> None:
        """
        This should be called when a new `tx/block` is added to the best chain.

        `remove` will be implied from the tx state but can be set explicitly.
        """
        raise NotImplementedError

    @abstractmethod
    def iter(self, tx_storage: 'TransactionStorage', max_timestamp: Optional[float] = None) -> Iterator[Transaction]:
        """
        Iterate over txs that are tips, a subset of the mempool (i.e. not tx-parent of another tx on the mempool).
        """
        raise NotImplementedError

    @abstractmethod
    def iter_all(self, tx_storage: 'TransactionStorage') -> Iterator[Transaction]:
        """
        Iterate over the transactions on the "mempool", even the ones that are not tips.
        """
        raise NotImplementedError

    @abstractmethod
    def get(self) -> set[bytes]:
        """
        Get the set of mempool tips indexed.
        """
        raise NotImplementedError


class ByteCollectionMempoolTipsIndex(MempoolTipsIndex):
    # NEEDS:

    log: 'structlog.stdlib.BoundLogger'
    _index: 'Collection[bytes]'

    def init_loop_step(self, tx: BaseTransaction) -> None:
        assert tx.hash is not None
        assert tx.storage is not None
        tx_meta = tx.get_metadata()
        # do not include voided transactions
        if tx_meta.voided_by:
            return
        # do not include transactions that have been confirmed
        if tx_meta.first_block:
            return
        tx_storage = tx.storage
        # do not include transactions that have a non-voided child
        if any_non_voided(tx_storage, tx.get_children()):
            return
        # do not include transactions that have a non-voided spent output
        if any_non_voided(tx_storage, chain(*tx_meta.spent_outputs.values())):
            return
        # include them otherwise
        self._add(tx.hash)

    @abstractmethod
    def _discard(self, tx: bytes) -> None:
        raise NotImplementedError()

    def _discard_many(self, txs: Iterable[bytes]) -> None:
        for tx in iter(txs):
            self._discard(tx)

    @abstractmethod
    def _add(self, tx: bytes) -> None:
        raise NotImplementedError()

    def _add_many(self, txs: Iterable[bytes]) -> None:
        for tx in iter(txs):
            self._add(tx)

    # PROVIDES:

    def _is_tip(self, tx_storage: 'TransactionStorage', tx: BaseTransaction) -> bool:
        """Whether `tx` currently satisfies the mempool-tip predicate (same rules as `init_loop_step`):
        an unconfirmed, non-voided transaction with no non-voided child or spender."""
        if not tx.is_transaction:
            return False
        meta = tx.get_metadata()
        if meta.voided_by or meta.validation.is_invalid():
            return False
        if meta.first_block is not None:
            return False
        if any_non_voided(tx_storage, tx.get_children()):
            return False
        if any_non_voided(tx_storage, chain(*meta.spent_outputs.values())):
            return False
        return True

    def update(self, tx: BaseTransaction, *, force_remove: bool = False) -> None:
        """Incrementally sync the index for one affected tx.

        Consensus calls this for *every* vertex whose metadata changed (the new vertex, its parents and
        spent txs, conflict winners/losers, newly confirmed txs), so only `tx` itself and its direct
        dependencies can change tip-ness here — tip-ness depends solely on a tx's own state and its
        children/spenders, and any tx whose children/spenders changed is itself in the affected set.
        This replaces a full scan of every tip per call (O(mempool) per added tx, quadratic under load)
        with O(dependencies) work.
        """
        assert tx.storage is not None
        tx_storage = tx.storage
        tx_meta = tx.get_metadata()
        voided_or_invalid = bool(tx_meta.voided_by) or tx_meta.validation.is_invalid()

        if force_remove and not voided_or_invalid:
            self.log.warn('removing tx even though it isn\'t voided or invalid, some tests can do this')

        if not force_remove and self._is_tip(tx_storage, tx):
            self._add(tx.hash)
            # its dependencies now have a non-voided child/spender (this tx), so they cannot be tips
            self._discard_many(tx.get_all_dependencies())
            return

        self._discard(tx.hash)
        if not tx.is_transaction and not voided_or_invalid:
            # a connected block: its tx parents (and everything below) just got confirmed
            self._discard_many(tx.get_all_dependencies())
            return

        # `tx` left the mempool view (voided/invalid/confirmed/removed): each of its dependencies may
        # have just lost its only non-voided child/spender and become a tip again — or may have ceased
        # being one. Re-evaluate exactly them.
        from hathor.transaction.storage.exceptions import TransactionDoesNotExist
        for dep_hash in tx.get_all_dependencies():
            try:
                dep = tx_storage.get_transaction(dep_hash)
            except TransactionDoesNotExist:
                # the dependency itself was removed from storage (e.g. a removal cascade during a reorg)
                self._discard(dep_hash)
                continue
            if self._is_tip(tx_storage, dep):
                self._add(dep_hash)
            else:
                self._discard(dep_hash)

    def iter(self, tx_storage: 'TransactionStorage', max_timestamp: Optional[float] = None) -> Iterator[Transaction]:
        it: Iterator[BaseTransaction] = map(tx_storage.get_transaction, self._index)
        if max_timestamp is not None:
            it = filter(lambda tx: tx.timestamp < not_none(max_timestamp), it)
        yield from cast(Iterator[Transaction], it)

    def iter_all(self, tx_storage: 'TransactionStorage') -> Iterator[Transaction]:
        from hathor.transaction.storage.traversal import BFSTimestampWalk
        bfs = BFSTimestampWalk(tx_storage, is_dag_verifications=True, is_dag_funds=True, is_left_to_right=False)
        for tx in bfs.run(self.iter(tx_storage), skip_root=False):
            if not isinstance(tx, Transaction):
                bfs.skip_neighbors()
                continue
            if tx.get_metadata().first_block is not None:
                bfs.skip_neighbors()
            else:
                yield tx
                bfs.add_neighbors()

    def get(self) -> set[bytes]:
        return set(iter(self._index))
