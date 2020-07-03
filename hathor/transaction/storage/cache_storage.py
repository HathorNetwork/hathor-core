from collections import OrderedDict
from typing import TYPE_CHECKING, Any, Generator, Iterator, Optional, Set

from twisted.internet import threads
from twisted.internet.defer import Deferred, inlineCallbacks, succeed
from twisted.logger import Logger

from hathor.transaction import BaseTransaction
from hathor.transaction.storage.transaction_storage import BaseTransactionStorage

if TYPE_CHECKING:
    from twisted.internet import Reactor


class TransactionCacheStorage(BaseTransactionStorage):
    """Caching storage to be used 'on top' of other storages.
    """
    log = Logger()

    cache: 'OrderedDict[bytes, BaseTransaction]'
    dirty_txs: Set[bytes]

    def __init__(self, store: 'BaseTransactionStorage', reactor: 'Reactor', interval: int = 5,
                 capacity: int = 10000, *, _clone_if_needed: bool = False):
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
        store.remove_cache()
        self.store = store
        self.reactor = reactor
        self.interval = interval
        self.capacity = capacity
        self.flush_deferred = None
        self._clone_if_needed = _clone_if_needed
        self.cache = OrderedDict()
        # dirty_txs has the txs that have been modified but are not persisted yet
        self.dirty_txs = set()  # Set[bytes(hash)]
        self.stats = dict(hit=0, miss=0)

        # we need to use only one weakref dict, so we must first initialize super, and then
        # attribute the same weakref for both.
        super().__init__()
        self._tx_weakref = store._tx_weakref

    def _clone(self, x: BaseTransaction) -> BaseTransaction:
        if self._clone_if_needed:
            return x.clone()
        else:
            return x

    def start(self) -> None:
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

    def _cb_flush_thread(self, flushed_txs: Set[bytes]) -> None:
        self.reactor.callLater(self.interval, self._start_flush_thread)
        self.flush_deferred = None

    def _err_flush_thread(self, reason: Any) -> None:
        self.log.error('Error flushing transactions: {reason}', reason=reason)
        self.reactor.callLater(self.interval, self._start_flush_thread)
        self.flush_deferred = None

    def _flush_to_storage(self, dirty_txs_copy: Set[bytes]) -> None:
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
        assert tx.hash is not None
        super().remove_transaction(tx)
        self.cache.pop(tx.hash, None)
        self.dirty_txs.discard(tx.hash)
        self._remove_from_weakref(tx)

    def save_transaction(self, tx: BaseTransaction, *, only_metadata: bool = False) -> None:
        self._save_transaction(tx)
        self._save_to_weakref(tx)

        # call super which adds to index if needed
        super().save_transaction(tx, only_metadata=only_metadata)

    def get_all_genesis(self) -> Set[BaseTransaction]:
        return self.store.get_all_genesis()

    def _save_transaction(self, tx: BaseTransaction, *, only_metadata: bool = False) -> None:
        """Saves the transaction without modifying TimestampIndex entries (in superclass)."""
        assert tx.hash is not None
        self._update_cache(tx)
        self.dirty_txs.add(tx.hash)

    def _update_cache(self, tx: BaseTransaction) -> None:
        """Updates the cache making sure it has at most the number of elements configured
        as its capacity.

        If we need to evict a tx from cache and it's dirty, write it to disk immediately.
        """
        assert tx.hash is not None
        _tx = self.cache.get(tx.hash, None)
        if not _tx:
            if len(self.cache) >= self.capacity:
                (_, removed_tx) = self.cache.popitem(last=False)
                if removed_tx.hash in self.dirty_txs:
                    # write to disk so we don't lose the last update
                    self.dirty_txs.discard(removed_tx.hash)
                    self.store.save_transaction(removed_tx)
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

    def get_all_transactions(self):
        self._flush_to_storage(self.dirty_txs.copy())
        for tx in self.store.get_all_transactions():
            tx.storage = self
            self._save_to_weakref(tx)
            yield tx

    def get_count_tx_blocks(self) -> int:
        self._flush_to_storage(self.dirty_txs.copy())
        return self.store.get_count_tx_blocks()

    @inlineCallbacks
    def save_transaction_deferred(self, tx: BaseTransaction, *, only_metadata: bool = False) -> Iterator[Deferred]:
        # TODO: yield self._save_transaction_deferred
        self._save_transaction(tx)

        # call super which adds to index if needed
        yield super().save_transaction_deferred(tx)

    @inlineCallbacks
    def remove_transaction_deferred(self, tx: BaseTransaction) -> Iterator[Deferred]:
        yield super().remove_transaction_deferred(tx)

    def transaction_exists_deferred(self, hash_bytes: bytes) -> Deferred:
        if hash_bytes in self.cache:
            return succeed(True)
        return self.store.transaction_exists_deferred(hash_bytes)

    @inlineCallbacks
    def get_transaction_deferred(self, hash_bytes: bytes) -> Generator[Deferred, Any, BaseTransaction]:
        if hash_bytes in self.cache:
            tx = self._clone(self.cache[hash_bytes])
            self.cache.move_to_end(hash_bytes, last=True)
            self.stats['hit'] += 1
            return tx
        else:
            tx = yield self.store.get_transaction_deferred(hash_bytes)
            # TODO: yield self._update_cache_deferred(tx)
            self._update_cache(tx)
            self.stats['miss'] += 1
            return tx

    @inlineCallbacks
    def get_all_transactions_deferred(self):
        # TODO: yield self._flush_to_storage_deferred(self.dirty_txs.copy())
        self._flush_to_storage(self.dirty_txs.copy())
        all_transactions = yield self.store.get_all_transactions_deferred()

        def _mygenerator():
            for tx in all_transactions:
                tx.storage = self
                yield tx
        return _mygenerator()

    @inlineCallbacks
    def get_count_tx_blocks_deferred(self):
        # TODO: yield self._flush_to_storage_deferred(self.dirty_txs.copy())
        self._flush_to_storage(self.dirty_txs.copy())
        res = yield self.store.get_count_tx_blocks_deferred()
        return res
