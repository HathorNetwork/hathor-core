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
from typing import TYPE_CHECKING, Iterable, Iterator, Optional, Set, cast

import structlog

from hathor.indexes.base_index import BaseIndex
from hathor.indexes.scope import Scope
from hathor.transaction import BaseTransaction, Transaction
from hathor.util import not_none

if TYPE_CHECKING:  # pragma: no cover
    from hathor.transaction.storage import TransactionStorage

SCOPE = Scope(
    include_blocks=True,
    include_txs=True,
    include_voided=True,
)


class MempoolTipsIndex(BaseIndex):
    """Index to access the tips of the mempool transactions, which haven't been confirmed by a block."""

    def get_scope(self) -> Scope:
        return SCOPE

    def init_loop_step(self, tx: BaseTransaction) -> None:
        self.update(tx)

    # originally tx_storage.update_mempool_tips
    @abstractmethod
    def update(self, tx: BaseTransaction, *, remove: Optional[bool] = None) -> None:
        """
        This should be called when a new `tx/block` is added to the best chain.

        `remove` will be implied from the tx state but can be set explicitly.
        """
        raise NotImplementedError

    # originally tx_storage.iter_mempool_tips
    @abstractmethod
    def iter(self, tx_storage: 'TransactionStorage', max_timestamp: Optional[float] = None) -> Iterator[Transaction]:
        """
        Iterate over txs that are tips, a subset of the mempool (i.e. not tx-parent of another tx on the mempool).
        """
        raise NotImplementedError

    # originally tx_storage.iter_mempool
    @abstractmethod
    def iter_all(self, tx_storage: 'TransactionStorage') -> Iterator[Transaction]:
        """
        Iterate over the transactions on the "mempool", even the ones that are not tips.
        """
        raise NotImplementedError

    # originally tx_storage.get_mempool_tips_index
    @abstractmethod
    def get(self) -> Set[bytes]:
        """
        Get the set of mempool tips indexed.

        What to do with `get_tx_tips()`? They kind of do the same thing and it might be really confusing in the future.
        """
        raise NotImplementedError


class ByteCollectionMempoolTipsIndex(MempoolTipsIndex):
    # NEEDS:

    log: 'structlog.stdlib.BoundLogger'
    _index: 'Collection[bytes]'

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

    def update(self, tx: BaseTransaction, *, remove: Optional[bool] = None) -> None:
        assert tx.hash is not None
        assert tx.storage is not None
        tx_meta = tx.get_metadata()
        to_remove: Set[bytes] = set()
        to_remove_parents: Set[bytes] = set()
        tx_storage = tx.storage
        for tip_tx in self.iter(tx_storage):
            assert tip_tx.hash is not None
            meta = tip_tx.get_metadata()
            # a new tx/block added might cause a tx in the tips to become voided. For instance, there might be a tx1 a
            # double spending tx2, where tx1 is valid and tx2 voided. A new block confirming tx2 will make it valid
            # while tx1 becomes voided, so it has to be removed from the tips. The txs confirmed by tx1 need to be
            # double checked, as they might themselves become tips (hence we use to_remove_parents)
            if meta.voided_by or meta.validation.is_invalid():
                to_remove.add(tip_tx.hash)
                to_remove_parents.update(tip_tx.parents)
                continue

            # might also happen that a tip has a child that became valid, so it's not a tip anymore
            confirmed = False
            for child_meta in filter(None, map(tx_storage.get_metadata, meta.children)):
                if not child_meta.voided_by:
                    confirmed = True
                    break
            if confirmed:
                to_remove.add(tip_tx.hash)

        if to_remove:
            self._discard_many(to_remove)
            self.log.debug('removed voided txs from tips', txs=[tx.hex() for tx in to_remove])

        # Check if any of the txs being confirmed by the voided txs is a tip again. This happens
        # if it doesn't have any other valid child.
        to_add = set()
        for tx_hash in to_remove_parents:
            confirmed = False
            # check if it has any valid children
            meta = not_none(tx_storage.get_metadata(tx_hash))
            if meta.voided_by:
                continue
            children = meta.children
            for child_meta in filter(None, map(tx_storage.get_metadata, children)):
                if not child_meta.voided_by:
                    confirmed = True
                    break
            if not confirmed:
                to_add.add(tx_hash)

        if to_add:
            self._add_many(to_add)
            self.log.debug('added txs to tips', txs=[tx.hex() for tx in to_add])

        actually_remove: bool
        voided_or_invalid = bool(tx_meta.voided_by) or tx_meta.validation.is_invalid()
        if remove is None:
            actually_remove = voided_or_invalid
        else:
            actually_remove = remove
            if remove and not voided_or_invalid:
                self.log.warn('removing tx even though it isn\'t voided or invalid, some tests can do this')
            if not remove and voided_or_invalid:
                raise ValueError('cannot add voided or invalid tx to mempool')

        if actually_remove:
            self.log.debug('remove from mempool', tx=tx.hash_hex, validation=tx_meta.validation,
                           is_voided=bool(tx_meta.voided_by))
            return

        self._discard_many(set(tx.parents))

        if tx.is_transaction and tx_meta.first_block is None:
            assert tx.hash is not None
            self._add(tx.hash)

    def iter(self, tx_storage: 'TransactionStorage', max_timestamp: Optional[float] = None) -> Iterator[Transaction]:
        it: Iterator[BaseTransaction] = map(tx_storage.get_transaction, self._index)
        if max_timestamp is not None:
            it = filter(lambda tx: tx.timestamp < not_none(max_timestamp), it)
        yield from cast(Iterator[Transaction], it)

    def iter_all(self, tx_storage: 'TransactionStorage') -> Iterator[Transaction]:
        from hathor.transaction.storage.traversal import BFSWalk
        bfs = BFSWalk(tx_storage, is_dag_verifications=True, is_left_to_right=False)
        for tx in bfs.run(self.iter(tx_storage), skip_root=False):
            assert isinstance(tx, Transaction)
            if tx.get_metadata().first_block is not None:
                bfs.skip_neighbors(tx)
            else:
                yield tx

    def get(self) -> Set[bytes]:
        return set(iter(self._index))
