# encoding: utf-8
from twisted.internet import threads
from twisted.internet.defer import inlineCallbacks, succeed
from twisted.logger import Logger

from hathor.transaction.storage.transaction_storage import BaseTransactionStorage
from hathor.util import deprecated, skip_warning

import collections


class TransactionCacheStorage(BaseTransactionStorage):
    """Caching storage to be used 'on top' of other storages.
    """
    log = Logger()

    def __init__(self, store, reactor, interval=5, capacity=10000, *, _clone_if_needed=True):
        """
        :param store: a subclass of TransactionStorage
        :type store: :py:class:`hathor.transaction.storage.TransactionStorage`

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
        self.cache = collections.OrderedDict()
        # dirty_txs has the txs that have been modified but are not persisted yet
        self.dirty_txs = set()          # Set[bytes(hash)]
        self.stats = dict(hit=0, miss=0)
        super().__init__()

    def _clone(self, x):
        if self._clone_if_needed:
            return x.clone()
        else:
            return x

    def start(self):
        self.reactor.callLater(self.interval, self._start_flush_thread)

    def _start_flush_thread(self):
        if self.flush_deferred is None:
            deferred = threads.deferToThread(self._flush_to_storage, self.dirty_txs.copy())
            deferred.addCallback(self._cb_flush_thread)
            deferred.addErrback(self._err_flush_thread)
            self.flush_deferred = deferred

    def _cb_flush_thread(self, flushed_txs):
        self.reactor.callLater(self.interval, self._start_flush_thread)
        self.flush_deferred = None

    def _err_flush_thread(self, reason):
        self.log.info('Error flushing transactions: {}'.format(reason))
        self.reactor.callLater(self.interval, self._start_flush_thread)
        self.flush_deferred = None

    def _flush_to_storage(self, dirty_txs_copy):
        """Write dirty pages to disk."""
        for tx_hash in dirty_txs_copy:
            # a dirty tx might be removed from self.cache outside this thread: if _update_cache is called
            # and we need to save the tx to disk immediately. So it might happen that the tx which was
            # in the dirty set when the flush thread began is not in cache anymore, hence this `if` check
            if tx_hash in self.cache:
                tx = self._clone(self.cache[tx_hash])
                skip_warning(self.store.save_transaction)(tx)
                self.dirty_txs.discard(tx_hash)

    @deprecated('Use save_transaction_deferred instead')
    def save_transaction(self, tx, *, only_metadata=False):
        # genesis txs and metadata are kept in memory
        if tx.is_genesis and only_metadata:
            return

        self._save_transaction(tx)

        # call super which adds to index if needed
        skip_warning(super().save_transaction)(tx, only_metadata=only_metadata)

    def _save_transaction(self, tx):
        """Saves the transaction without modifying TimestampIndex entries (in superclass)."""
        self._update_cache(tx)
        self.dirty_txs.add(tx.hash)

    def _update_cache(self, tx):
        """Updates the cache making sure it has at most the number of elements configured
        as its capacity.

        If we need to evict a tx from cache and it's dirty, write it to disk immediately.
        """
        _tx = self.cache.get(tx.hash, None)
        if not _tx:
            if len(self.cache) >= self.capacity:
                (_, removed_tx) = self.cache.popitem(last=False)
                if removed_tx.hash in self.dirty_txs:
                    # write to disk so we don't lose the last update
                    skip_warning(self.store.save_transaction)(removed_tx)
                    self.dirty_txs.remove(removed_tx.hash)
            self.cache[tx.hash] = self._clone(tx)
        else:
            # Tx might have been updated
            self.cache[tx.hash] = self._clone(tx)
            self.cache.move_to_end(tx.hash, last=False)

    @deprecated('Use transaction_exists_deferred instead')
    def transaction_exists(self, hash_bytes):
        if hash_bytes in self.cache:
            return True
        return skip_warning(self.store.transaction_exists)(hash_bytes)

    @deprecated('Use get_transaction_deferred instead')
    def get_transaction(self, hash_bytes):
        if hash_bytes in self.cache:
            tx = self._clone(self.cache[hash_bytes])
            self.cache.move_to_end(hash_bytes, last=False)
            self.stats['hit'] += 1
            return tx
        else:
            tx = skip_warning(self.store.get_transaction)(hash_bytes)
            self._update_cache(tx)
            self.stats['miss'] += 1
            return tx

    @deprecated('Use get_all_transactions_deferred instead')
    def get_all_transactions(self):
        self._flush_to_storage(self.dirty_txs.copy())
        return skip_warning(self.store.get_all_transactions)()

    @deprecated('Use get_count_tx_blocks_deferred instead')
    def get_count_tx_blocks(self):
        self._flush_to_storage(self.dirty_txs.copy())
        return skip_warning(self.store.get_count_tx_blocks)()

    @inlineCallbacks
    def save_transaction_deferred(self, tx, *, only_metadata=False):
        if tx.is_genesis and only_metadata:
            return

        # TODO: yield self._save_transaction_deferred
        self._save_transaction(tx)

        # call super which adds to index if needed
        yield super().save_transaction_deferred(tx)

    def transaction_exists_deferred(self, hash_bytes):
        if hash_bytes in self.cache:
            return succeed(True)
        return self.store.transaction_exists_deferred(hash_bytes)

    @inlineCallbacks
    def get_transaction_deferred(self, hash_bytes):
        if hash_bytes in self.cache:
            tx = self._clone(self.cache[hash_bytes])
            self.cache.move_to_end(hash_bytes, last=False)
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
        res = yield self.store.get_all_transactions_deferred()
        return res

    @inlineCallbacks
    def get_count_tx_blocks_deferred(self):
        # TODO: yield self._flush_to_storage_deferred(self.dirty_txs.copy())
        self._flush_to_storage(self.dirty_txs.copy())
        res = yield self.store.get_count_tx_blocks_deferred()
        return res
