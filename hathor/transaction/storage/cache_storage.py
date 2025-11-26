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

from __future__ import annotations

from collections import OrderedDict
from typing import TYPE_CHECKING, Any, Iterator, Optional

from twisted.internet import threads
from typing_extensions import override

from hathor.indexes import IndexesManager
from hathor.reactor import ReactorProtocol as Reactor
from hathor.transaction import BaseTransaction
from hathor.transaction.storage.migrations import MigrationState
from hathor.transaction.storage.transaction_storage import BaseTransactionStorage
from hathor.transaction.storage.tx_allow_scope import TxAllowScope
from hathor.transaction.vertex_children import VertexChildrenService

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.nanocontracts.storage import NCStorageFactory


class TransactionCacheStorage(BaseTransactionStorage):
    """Caching storage to be used 'on top' of other storages.
    """

    cache: OrderedDict[bytes, BaseTransaction]
    dirty_txs: set[bytes]

    def __init__(
        self,
        store: 'BaseTransactionStorage',
        reactor: Reactor,
        interval: int = 5,
        capacity: int = 10000,
        *,
        settings: 'HathorSettings',
        nc_storage_factory: NCStorageFactory,
        vertex_children_service: VertexChildrenService,
        indexes: Optional[IndexesManager],
        _clone_if_needed: bool = False,
    ) -> None:
        """
        :param store: a subclass of BaseTransactionStorage
        :type store: :py:class:`hathor.transaction.storage.BaseTransactionStorage`

        :param reactor: Twisted reactor which handles the mainloop and the events.
        :type reactor: :py:class:`twisted.internet.Reactor`

        :param interval: the cache flush interval. Writes will happen every interval seconds
        :type interval: int

        :param capacity: cache capacity
        :type capacity: int

        :param _clone_if_needed: *private parameter*, defaults to True, controls whether to clone
                                 transaction/blocks/metadata when returning those objects.
        :type _clone_if_needed: bool
        """
        if store.indexes is not None:
            raise ValueError('internal storage cannot have indexes enabled')

        store.remove_cache()
        self.store = store
        self.reactor = reactor
        self.interval = interval
        self.capacity = capacity
        self.flush_deferred = None
        self._clone_if_needed = _clone_if_needed
        self.cache = OrderedDict()
        # dirty_txs has the txs that have been modified but are not persisted yet
        self.dirty_txs = set()
        self.stats = dict(hit=0, miss=0)

        # we need to use only one weakref dict, so we must first initialize super, and then
        # attribute the same weakref for both.
        super().__init__(
            indexes=indexes,
            settings=settings,
            nc_storage_factory=nc_storage_factory,
            vertex_children_service=vertex_children_service,
        )

        self._tx_weakref = store._tx_weakref
        # XXX: just to make sure this isn't being used anywhere, setters/getters should be used instead
        del self._allow_scope

    def set_allow_scope(self, allow_scope: TxAllowScope) -> None:
        self.store._allow_scope = allow_scope

    def get_allow_scope(self) -> TxAllowScope:
        return self.store._allow_scope

    def set_capacity(self, capacity: int) -> None:
        """Change the max number of items in cache."""
        assert capacity >= 0
        self.capacity = capacity
        while len(self.cache) > self.capacity:
            self._cache_popitem()

    def _clone(self, x: BaseTransaction) -> BaseTransaction:
        if self._clone_if_needed:
            return x.clone()
        else:
            return x

    def get_migration_state(self, migration_name: str) -> MigrationState:
        # forward to internal store
        return self.store.get_migration_state(migration_name)

    def set_migration_state(self, migration_name: str, state: MigrationState) -> None:
        # forward to internal store
        self.store.set_migration_state(migration_name, state)

    def pre_init(self) -> None:
        # XXX: not calling self.store.pre_init() because it would run `BaseTransactionStorage.pre_init` twice.
        super().pre_init()
        self.reactor.callLater(self.interval, self._start_flush_thread)

    def _enable_weakref(self) -> None:
        super()._enable_weakref()
        self.store._enable_weakref()

    def _disable_weakref(self) -> None:
        super()._disable_weakref()
        self.store._disable_weakref()

    def _start_flush_thread(self) -> None:
        if self.flush_deferred is None:
            deferred = threads.deferToThread(self._flush_to_storage, self.dirty_txs.copy())
            deferred.addCallback(self._cb_flush_thread)
            deferred.addErrback(self._err_flush_thread)
            self.flush_deferred = deferred

    def _cb_flush_thread(self, flushed_txs: set[bytes]) -> None:
        self.reactor.callLater(self.interval, self._start_flush_thread)
        self.flush_deferred = None

    def _err_flush_thread(self, reason: Any) -> None:
        self.log.error('error flushing transactions', reason=reason)
        self.reactor.callLater(self.interval, self._start_flush_thread)
        self.flush_deferred = None

    def _flush_to_storage(self, dirty_txs_copy: set[bytes]) -> None:
        """Write dirty pages to disk."""
        for tx_hash in dirty_txs_copy:
            # a dirty tx might be removed from self.cache outside this thread: if _update_cache is called
            # and we need to save the tx to disk immediately. So it might happen that the tx which was
            # in the dirty set when the flush thread began is not in cache anymore, hence this `if` check
            if tx_hash in self.cache:
                tx = self._clone(self.cache[tx_hash])
                self.dirty_txs.discard(tx_hash)
                self.store._save_transaction(tx)

    def remove_transaction(self, tx: BaseTransaction) -> None:
        super().remove_transaction(tx)
        self.cache.pop(tx.hash, None)
        self.dirty_txs.discard(tx.hash)
        self.store.remove_transaction(tx)
        self._remove_from_weakref(tx)

    def save_transaction(self, tx: 'BaseTransaction', *, only_metadata: bool = False) -> None:
        self._save_transaction(tx)
        self._save_to_weakref(tx)

        # call super which adds to index if needed
        super().save_transaction(tx, only_metadata=only_metadata)

    @override
    def _save_static_metadata(self, tx: BaseTransaction) -> None:
        self.store._save_static_metadata(tx)

    def get_all_genesis(self) -> set[BaseTransaction]:
        return self.store.get_all_genesis()

    def _save_transaction(self, tx: BaseTransaction, *, only_metadata: bool = False) -> None:
        """Saves the transaction without modifying TimestampIndex entries (in superclass)."""
        self._update_cache(tx)
        self.dirty_txs.add(tx.hash)

    def _cache_popitem(self) -> BaseTransaction:
        """Pop the last recently used cache item."""
        (_, removed_tx) = self.cache.popitem(last=False)
        if removed_tx.hash in self.dirty_txs:
            # write to disk so we don't lose the last update
            self.dirty_txs.discard(removed_tx.hash)
            self.store.save_transaction(removed_tx)
        return removed_tx

    def _update_cache(self, tx: BaseTransaction) -> None:
        """Updates the cache making sure it has at most the number of elements configured
        as its capacity.

        If we need to evict a tx from cache and it's dirty, write it to disk immediately.
        """
        _tx = self.cache.get(tx.hash, None)
        if not _tx:
            if len(self.cache) >= self.capacity:
                self._cache_popitem()
            self.cache[tx.hash] = self._clone(tx)
        else:
            # Tx might have been updated
            self.cache[tx.hash] = self._clone(tx)
            self.cache.move_to_end(tx.hash, last=True)

    def transaction_exists(self, hash_bytes: bytes) -> bool:
        if hash_bytes in self.cache:
            return True
        return self.store.transaction_exists(hash_bytes)

    def _get_transaction(self, hash_bytes: bytes) -> BaseTransaction:
        tx: Optional[BaseTransaction]
        if hash_bytes in self.cache:
            tx = self._clone(self.cache[hash_bytes])
            self.cache.move_to_end(hash_bytes, last=True)
            self.stats['hit'] += 1
        else:
            tx = self.get_transaction_from_weakref(hash_bytes)
            if tx is not None:
                self.stats['hit'] += 1
            else:
                tx = self.store.get_transaction(hash_bytes)
                tx.storage = self
                self.stats['miss'] += 1
            self._update_cache(tx)
        self._save_to_weakref(tx)
        assert tx is not None
        return tx

    def _get_all_transactions(self) -> Iterator[BaseTransaction]:
        self._flush_to_storage(self.dirty_txs.copy())
        # XXX: explicitly use _get_all_transaction instead of get_all_transactions because there will already be a
        #      TransactionCacheStorage.get_all_transactions outer method
        for tx in self.store._get_all_transactions():
            tx.storage = self
            self._save_to_weakref(tx)
            yield tx

    def is_empty(self) -> bool:
        self._flush_to_storage(self.dirty_txs.copy())
        return self.store.is_empty()

    def add_value(self, key: str, value: str) -> None:
        self.store.add_value(key, value)

    def remove_value(self, key: str) -> None:
        self.store.remove_value(key)

    def get_value(self, key: str) -> Optional[str]:
        return self.store.get_value(key)

    def flush(self):
        self._flush_to_storage(self.dirty_txs.copy())

    @override
    def migrate_vertex_children(self) -> None:
        self.store.migrate_vertex_children()
