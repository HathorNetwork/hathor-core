# encoding: utf-8
from twisted.internet import threads
from twisted.logger import Logger

from hathor.transaction.storage.transaction_storage import TransactionStorage
from hathor.transaction.storage.exceptions import TransactionMetadataDoesNotExist

import collections


class TransactionCacheStorage(TransactionStorage):
    """Caching storage to be used 'on top' of other storages.
    """
    log = Logger()

    def __init__(self, store, reactor, interval=5, capacity=10000):
        """
        :param store: a subclass of TransactionStorage
        :type store: :py:class:`hathor.transaction.storage.transaction_storage.TransactionStorage`

        :param reactor: Twisted reactor which handles the mainloop and the events.
        :type reactor: :py:class:`twisted.internet.Reactor`

        :param interval: the cache flush interval. Writes will happen every interval seconds
        :type interval: int

        :param capacity: cache capacity
        :type capacity: int
        """
        store.remove_cache()
        self.store = store
        self.reactor = reactor
        self.interval = interval
        self.capacity = capacity
        self.flush_deferred = None
        self.cache = collections.OrderedDict()
        # dirty_txs has the txs that have been modified but are not persisted yet
        self.dirty_txs = set()          # Set[bytes(hash)]
        self.stats = dict(hit=0, miss=0)
        super().__init__()

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
        """Write dirty pages to disk
        """
        for tx_hash in dirty_txs_copy:
            # a dirty tx might be removed from self.cache outside this thread: if _update_cache is called
            # and we need to save the tx to disk immediately. So it might happen that the tx which was
            # in the dirty set when the flush thread began is not in cache anymore, hence this `if` check
            if tx_hash in self.cache:
                tx = self.cache[tx_hash]
                self.store.save_transaction(tx)
                self.dirty_txs.discard(tx_hash)

    def save_transaction(self, tx):
        """Saves the tx and calls superclass save, which adds to timestamp index
        """
        super().save_transaction(tx)
        self._save_transaction(tx)

    def _save_transaction(self, tx):
        """Saves the transaction without modifying TimestampIndex entries (in superclass)
        """
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
                    self.store.save_transaction(removed_tx)
                    self.dirty_txs.remove(removed_tx.hash)
            self.cache[tx.hash] = tx
        else:
            self.cache.move_to_end(tx.hash, last=False)

    def transaction_exists_by_hash(self, hash_hex):
        hash_bytes = bytes.fromhex(hash_hex)
        return self.transaction_exists_by_hash_bytes(hash_bytes)

    def transaction_exists_by_hash_bytes(self, hash_bytes):
        if hash_bytes in self.cache:
            return True
        return self.store.transaction_exists_by_hash_bytes(hash_bytes)

    def get_transaction_by_hash_bytes(self, hash_bytes):
        if hash_bytes in self.cache:
            tx = self.cache[hash_bytes]
            self.cache.move_to_end(hash_bytes, last=False)
            self.stats['hit'] += 1
            return tx
        else:
            tx = self.store.get_transaction_by_hash_bytes(hash_bytes)
            self._update_cache(tx)
            self.stats['miss'] += 1
            return tx

    def get_transaction_by_hash(self, hash_hex):
        hash_bytes = bytes.fromhex(hash_hex)
        return self.get_transaction_by_hash_bytes(hash_bytes)

    def save_metadata(self, tx):
        if not tx.is_genesis:
            self._save_transaction(tx)

    def _get_metadata_by_hash(self, hash_hex):
        tx = self.get_transaction_by_hash(hash_hex)
        meta = getattr(tx, '_metadata', None)
        if meta:
            return meta
        else:
            raise TransactionMetadataDoesNotExist

    def get_all_transactions(self):
        self._flush_to_storage(self.dirty_txs.copy())
        return self.store.get_all_transactions()

    def get_count_tx_blocks(self):
        self._flush_to_storage(self.dirty_txs.copy())
        return self.store.get_count_tx_blocks()
