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

    def update(self, tx: BaseTransaction, *, force_remove: bool = False) -> None:
        assert tx.storage is not None
        tx_meta = tx.get_metadata()
        to_remove: set[bytes] = set()
        deps_to_check: set[bytes] = set()
        tx_storage = tx.storage
        for tip_tx in self.iter(tx_storage):
            meta = tip_tx.get_metadata()
            # a new tx/block added might cause a tx in the tips to become voided. For instance, there might be a tx1
            # double spending tx2, where tx1 is valid and tx2 voided. A new block confirming tx2 will make it valid
            # while tx1 becomes voided, so it has to be removed from the tips. The txs confirmed by tx1 need to be
            # double checked, as they might themselves become tips (hence we use deps_to_check)
            if meta.voided_by or meta.validation.is_invalid():
                to_remove.add(tip_tx.hash)
                deps_to_check.update(tip_tx.get_all_dependencies())
                continue

            # might also happen that a tip has a child or a spender that became valid, so it's not a tip anymore
            has_non_voided_child = lambda: any_non_voided(tx_storage, tip_tx.get_children())
            has_non_voided_spender = lambda: any_non_voided(tx_storage, chain(*meta.spent_outputs.values()))
            if has_non_voided_child() or has_non_voided_spender():
                to_remove.add(tip_tx.hash)

        if to_remove:
            self._discard_many(to_remove)
            self.log.debug('removed txs from tips', txs=[tx.hex() for tx in to_remove])

        # Check if any of the txs pointed by the removed tips is a tip again. This happens
        # if it doesn't have any other valid child or spender.
        to_add = set()
        for tx_hash in deps_to_check:
            meta = not_none(tx_storage.get_metadata(tx_hash))
            if meta.voided_by:
                continue
            to_remove_parent = tx_storage.get_transaction(tx_hash)
            # check if it has any valid children or spenders
            has_non_voided_child = lambda: any_non_voided(tx_storage, to_remove_parent.get_children())
            has_non_voided_spender = lambda: any_non_voided(tx_storage, chain(*meta.spent_outputs.values()))
            if not has_non_voided_child() and not has_non_voided_spender():
                to_add.add(tx_hash)

        if to_add:
            self._add_many(to_add)
            self.log.debug('added txs to tips', txs=[tx.hex() for tx in to_add])

        voided_or_invalid = bool(tx_meta.voided_by) or tx_meta.validation.is_invalid()
        remove = force_remove or voided_or_invalid

        if force_remove and not voided_or_invalid:
            self.log.warn('removing tx even though it isn\'t voided or invalid, some tests can do this')

        if remove:
            self.log.debug('remove from mempool', tx=tx.hash_hex, validation=tx_meta.validation,
                           is_voided=bool(tx_meta.voided_by))
            return

        self._discard_many(tx.get_all_dependencies())

        if tx.is_transaction and tx_meta.first_block is None:
            self._add(tx.hash)

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
                continue
            if tx.get_metadata().first_block is not None:
                bfs.skip_neighbors(tx)
            else:
                yield tx

    def get(self) -> set[bytes]:
        return set(iter(self._index))
