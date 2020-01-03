from abc import ABC, abstractmethod, abstractproperty
from collections import deque
from typing import Any, Dict, Generator, Iterator, List, Optional, Set, Tuple
from weakref import WeakValueDictionary

from intervaltree.interval import Interval
from twisted.internet.defer import Deferred, inlineCallbacks, succeed

from hathor.indexes import IndexesManager, TokensIndex, TransactionsIndex, WalletIndex
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.transaction.block import Block
from hathor.transaction.storage.exceptions import TransactionDoesNotExist, TransactionIsNotABlock
from hathor.transaction.transaction import BaseTransaction
from hathor.transaction.transaction_metadata import TransactionMetadata
from hathor.util import deprecated, skip_warning


class TransactionStorage(ABC):
    """Legacy sync interface, please copy @deprecated decorator when implementing methods."""

    pubsub: Optional[PubSubManager]
    with_index: bool  # noqa: E701
    wallet_index: Optional[WalletIndex]
    tokens_index: Optional[TokensIndex]
    block_index: Optional[IndexesManager]
    tx_index: Optional[IndexesManager]
    all_index: Optional[IndexesManager]

    def __init__(self):
        # Weakref is used to guarantee that there is only one instance of each transaction in memory.
        self._tx_weakref: WeakValueDictionary[bytes, BaseTransaction] = WeakValueDictionary()
        self._tx_weakref_disabled: bool = False

    def _save_to_weakref(self, tx: BaseTransaction) -> None:
        """ Save transaction to weakref.
        """
        if self._tx_weakref_disabled:
            return
        assert tx.hash is not None
        tx2 = self._tx_weakref.get(tx.hash, None)
        if tx2 is None:
            self._tx_weakref[tx.hash] = tx
        else:
            assert tx is tx2, 'There are two instance of the same transaction in memory ({})'.format(tx.hash_hex)

    def _remove_from_weakref(self, tx: BaseTransaction) -> None:
        """Remove transaction from weakref.
        """
        if self._tx_weakref_disabled:
            return
        assert tx.hash is not None
        self._tx_weakref.pop(tx.hash, None)

    def get_transaction_from_weakref(self, hash_bytes: bytes) -> Optional[BaseTransaction]:
        """ Get a transaction from weakref if it exists. Otherwise, returns None.
        """
        if self._tx_weakref_disabled:
            return None
        return self._tx_weakref.get(hash_bytes, None)

    def _enable_weakref(self) -> None:
        """ Weakref should never be disabled unless you know exactly what you are doing.
        """
        self._tx_weakref_disabled = False

    def _disable_weakref(self) -> None:
        """ Weakref should never be disabled unless you know exactly what you are doing.
        """
        self._tx_weakref_disabled = True

    @abstractmethod
    @deprecated('Use save_transaction_deferred instead')
    def save_transaction(self: 'TransactionStorage', tx: BaseTransaction, *, only_metadata: bool = False) -> None:
        # XXX: although this method is abstract (because a subclass must implement it) the implementer
        #      should call the base implementation for correctly interacting with the index
        """Saves the tx.

        :param tx: Transaction to save
        :param only_metadata: Don't save the transaction, only the metadata of this transaction
        """
        meta = tx.get_metadata()
        if self.pubsub:
            if not meta.voided_by:
                self.pubsub.publish(HathorEvents.STORAGE_TX_WINNER, tx=tx)
            else:
                self.pubsub.publish(HathorEvents.STORAGE_TX_VOIDED, tx=tx)

        if self.with_index and not only_metadata:
            self._add_to_cache(tx)

    @abstractmethod
    @deprecated('Use remove_transaction_deferred instead')
    def remove_transaction(self, tx: BaseTransaction) -> None:
        """Remove the tx.

        :param tx: Trasaction to be removed
        """
        if self.with_index:
            assert self.all_index is not None

            self._del_from_cache(tx, relax_assert=True)
            # TODO Move it to self._del_from_cache. We cannot simply do it because
            #      this method is used by the consensus algorithm which does not
            #      expect to have it removed from self.all_index.
            self.all_index.del_tx(tx, relax_assert=True)

            if self.wallet_index:
                self.wallet_index.remove_tx(tx)

    @abstractmethod
    @deprecated('Use transaction_exists_deferred instead')
    def transaction_exists(self, hash_bytes: bytes) -> bool:
        """Returns `True` if transaction with hash `hash_bytes` exists.

        :param hash_bytes: Hash in bytes that will be checked.
        """
        raise NotImplementedError

    @abstractmethod
    @deprecated('Use get_transaction_deferred instead')
    def get_transaction(self, hash_bytes: bytes) -> BaseTransaction:
        """Returns the transaction with hash `hash_bytes`.

        :param hash_bytes: Hash in bytes that will be checked.
        """
        raise NotImplementedError

    @deprecated('Use get_metadata_deferred instead')
    def get_metadata(self, hash_bytes: bytes) -> Optional[TransactionMetadata]:
        """Returns the transaction metadata with hash `hash_bytes`.

        :param hash_bytes: Hash in bytes that will be checked.
        :rtype :py:class:`hathor.transaction.TransactionMetadata`
        """
        try:
            tx = self.get_transaction(hash_bytes)
            return tx.get_metadata(use_storage=False)
        except TransactionDoesNotExist:
            return None

    @abstractmethod
    @deprecated('Use get_all_transactions_deferred instead')
    def get_all_transactions(self) -> Iterator[BaseTransaction]:
        # TODO: verify the following claim:
        """Return all transactions that are not blocks.

        :rtype :py:class:`typing.Iterable[hathor.transaction.BaseTransaction]`
        """
        raise NotImplementedError

    @abstractmethod
    @deprecated('Use get_count_tx_blocks_deferred instead')
    def get_count_tx_blocks(self) -> int:
        # TODO: verify the following claim:
        """Return the number of transactions/blocks stored.

        :rtype int
        """
        raise NotImplementedError

    """Async interface, all methods mirrorred from TransactionStorageSync, but suffixed with `_deferred`."""

    @abstractmethod
    def save_transaction_deferred(self, tx: BaseTransaction, *, only_metadata: bool = False) -> None:
        """Saves the tx.

        :param tx: Transaction to save
        :type tx: :py:class:`hathor.transaction.BaseTransaction`

        :param only_metadata: Don't save the transaction, only the metadata of this transaction
        :type only_metadata: bool

        :rtype :py:class:`twisted.internet.defer.Deferred[None]`
        """
        if self.with_index:
            self._add_to_cache(tx)
        return succeed(None)

    @abstractmethod
    def remove_transaction_deferred(self, tx: BaseTransaction) -> None:
        """Remove the tx.

        :param tx: Transaction to be removed

        :rtype :py:class:`twisted.internet.defer.Deferred[None]`
        """
        if self.with_index:
            self._del_from_cache(tx)
        return succeed(None)

    @abstractmethod
    def transaction_exists_deferred(self, hash_bytes: bytes) -> bool:
        """Returns `True` if transaction with hash `hash_bytes` exists.

        :param hash_bytes: Hash in bytes that will be checked.
        :type hash_bytes: bytes

        :rtype :py:class:`twisted.internet.defer.Deferred[bool]`
        """
        raise NotImplementedError

    @abstractmethod
    def get_transaction_deferred(self, hash_bytes: bytes) -> BaseTransaction:
        """Returns the transaction with hash `hash_bytes`.

        :param hash_bytes: Hash in bytes that will be checked.
        :type hash_bytes: bytes

        :rtype :py:class:`twisted.internet.defer.Deferred[hathor.transaction.BaseTransaction]`
        """
        raise NotImplementedError

    @inlineCallbacks
    def get_metadata_deferred(self, hash_bytes: bytes) -> Generator[Any, Any, Optional[TransactionMetadata]]:
        """Returns the transaction metadata with hash `hash_bytes`.

        :param hash_bytes: Hash in bytes that will be checked.
        :type hash_bytes: bytes

        :rtype :py:class:`twisted.internet.defer.Deferred[hathor.transaction.TransactionMetadata]`
        """
        try:
            tx = yield self.get_transaction_deferred(hash_bytes)
            return tx.get_metadata(use_storage=False)
        except TransactionDoesNotExist:
            return None

    @abstractmethod
    def get_all_transactions_deferred(self) -> Iterator[BaseTransaction]:
        # TODO: find an `async generator` type
        # TODO: verify the following claim:
        """Return all transactions that are not blocks.

        :rtype :py:class:`twisted.internet.defer.Deferred[typing.Iterable[hathor.transaction.BaseTransaction]]`
        """
        raise NotImplementedError

    @abstractmethod
    def get_count_tx_blocks_deferred(self) -> int:
        # TODO: verify the following claim:
        """Return the number of transactions/blocks stored.

        :rtype :py:class:`twisted.internet.defer.Deferred[int]`
        """
        raise NotImplementedError

    @abstractproperty
    def latest_timestamp(self) -> int:
        raise NotImplementedError

    @abstractproperty
    def first_timestamp(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def get_best_block_tips(self, timestamp: Optional[float] = None) -> List[bytes]:
        """ Return a list of blocks that are heads in a best chain. It must be used when mining.

        When more than one block is returned, it means that there are multiple best chains and
        you can choose any of them.
        """
        best_score = 0
        best_tip_blocks = []  # List[bytes(hash)]
        tip_blocks = [x.data for x in self.get_block_tips(timestamp)]
        for block_hash in tip_blocks:
            meta = self.get_metadata(block_hash)
            if meta.voided_by and meta.voided_by != set([block_hash]):
                # If anyone but the block itself is voiding this block, then it must be skipped.
                continue
            if abs(meta.score - best_score) < 1e-10:
                best_tip_blocks.append(block_hash)
            elif meta.score > best_score:
                best_score = meta.score
                best_tip_blocks = [block_hash]
        return best_tip_blocks

    def get_weight_best_block(self) -> float:
        heads = [self.get_transaction(h) for h in self.get_best_block_tips()]
        highest_weight = 0
        for head in heads:
            if head.weight > highest_weight:
                highest_weight = head.weight

        return highest_weight

    @abstractmethod
    def get_block_tips(self, timestamp: Optional[float] = None) -> Set[Interval]:
        raise NotImplementedError

    @abstractmethod
    def get_all_tips(self, timestamp: Optional[float] = None) -> Set[Interval]:
        raise NotImplementedError

    @abstractmethod
    def get_tx_tips(self, timestamp: Optional[float] = None) -> Set[Interval]:
        raise NotImplementedError

    @abstractmethod
    def get_newest_blocks(self, count: int) -> Tuple[List[Block], bool]:
        """ Get blocks from the newest to the oldest

        :param count: Number of blocks to be returned
        :return: List of blocks and a boolean indicating if has more blocks
        """
        raise NotImplementedError

    @abstractmethod
    def get_newest_txs(self, count: int) -> Tuple[List[BaseTransaction], bool]:
        """ Get transactions from the newest to the oldest

        :param count: Number of transactions to be returned
        :return: List of transactions and a boolean indicating if has more txs
        """
        raise NotImplementedError

    @abstractmethod
    def get_older_blocks_after(self, timestamp: int, hash_bytes: bytes,
                               count: int) -> Tuple[List[Block], bool]:
        """ Get blocks from the timestamp/hash_bytes reference to the oldest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of blocks to be returned
        :return: List of blocks and a boolean indicating if has more blocks
        """
        raise NotImplementedError

    @abstractmethod
    def get_newer_blocks_after(self, timestamp: int, hash_bytes: bytes,
                               count: int) -> Tuple[List[BaseTransaction], bool]:
        """ Get blocks from the timestamp/hash_bytes reference to the newest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of blocks to be returned
        :return: List of blocks and a boolean indicating if has more blocks
        """
        raise NotImplementedError

    @abstractmethod
    def get_older_txs_after(self, timestamp: int, hash_bytes: bytes, count: int) -> Tuple[List[BaseTransaction], bool]:
        """ Get transactions from the timestamp/hash_bytes reference to the oldest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of transactions to be returned
        :return: List of transactions and a boolean indicating if has more txs
        """
        raise NotImplementedError

    @abstractmethod
    def get_newer_txs_after(self, timestamp: int, hash_bytes: bytes, count: int) -> Tuple[List[BaseTransaction], bool]:
        """ Get transactions from the timestamp/hash_bytes reference to the newest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of transactions to be returned
        :return: List of transactions and a boolean indicating if has more txs
        """
        raise NotImplementedError

    @abstractmethod
    def _manually_initialize(self) -> None:
        # XXX: maybe refactor, this is actually part of the public interface
        """Caches must be initialized. This function should not be called, because
        usually the HathorManager will handle all this initialization.
        """
        pass

    @abstractmethod
    def _topological_sort(self) -> Iterator[BaseTransaction]:
        """Return an iterable of the transactions in topological ordering, i.e., from
        genesis to the most recent transactions. The order is important because the
        transactions are always valid---their parents and inputs exist.

        :return: An iterable with the sorted transactions
        """
        raise NotImplementedError

    @abstractmethod
    def _add_to_cache(self, tx: BaseTransaction) -> None:
        raise NotImplementedError

    @abstractmethod
    def _del_from_cache(self, tx: BaseTransaction, *, relax_assert: bool = False) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_block_count(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def get_tx_count(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def get_genesis(self, hash_bytes: bytes) -> Optional[BaseTransaction]:
        """Returning hardcoded genesis block and transactions."""
        raise NotImplementedError

    @abstractmethod
    def get_all_genesis(self) -> Set[BaseTransaction]:
        raise NotImplementedError

    @abstractmethod
    def get_transactions_before(self, hash_bytes: bytes, num_blocks: int = 100) -> List[BaseTransaction]:
        """Run a BFS starting from the giving `hash_bytes`.

        :param hash_bytes: Starting point of the BFS, either a block or a transaction.
        :param num_blocks: Number of blocks to be return.
        :return: List of transactions
        """
        raise NotImplementedError

    @abstractmethod
    def get_blocks_before(self, hash_bytes: bytes, num_blocks: int = 100) -> List[Block]:
        """Run a BFS starting from the giving `hash_bytes`.

        :param hash_bytes: Starting point of the BFS.
        :param num_blocks: Number of blocks to be return.
        :return: List of transactions
        """
        raise NotImplementedError

    @abstractmethod
    def get_all_sorted_txs(self, timestamp: int, count: int, offset: int) -> TransactionsIndex:
        """ Returns ordered blocks and txs in a TransactionIndex
        """
        raise NotImplementedError


class TransactionStorageAsyncFromSync(TransactionStorage):
    """Implement async interface from sync interface, for legacy implementations."""

    def save_transaction_deferred(self, tx: BaseTransaction, *, only_metadata: bool = False) -> Deferred:
        return succeed(skip_warning(self.save_transaction)(tx, only_metadata=only_metadata))

    def remove_transaction_deferred(self, tx: BaseTransaction) -> Deferred:
        return succeed(skip_warning(self.remove_transaction)(tx))

    def transaction_exists_deferred(self, hash_bytes: bytes) -> Deferred:
        return succeed(skip_warning(self.transaction_exists)(hash_bytes))

    def get_transaction_deferred(self, hash_bytes: bytes) -> Deferred:
        return succeed(skip_warning(self.get_transaction)(hash_bytes))

    def get_all_transactions_deferred(self) -> Deferred:
        return succeed(skip_warning(self.get_all_transactions)())

    def get_count_tx_blocks_deferred(self) -> Deferred:
        return succeed(skip_warning(self.get_count_tx_blocks)())


class BaseTransactionStorage(TransactionStorage):
    def __init__(self, with_index: bool = True, pubsub: Optional[Any] = None) -> None:
        super().__init__()

        self.with_index = with_index
        if with_index:
            self._reset_cache()
        self._genesis_cache: Optional[Dict[bytes, BaseTransaction]] = None

        # Pubsub is used to publish tx voided and winner but it's optional
        self.pubsub = pubsub

    @property
    def latest_timestamp(self) -> int:
        return self._latest_timestamp

    @property
    def first_timestamp(self) -> int:
        return self._first_timestamp

    @abstractmethod
    def _save_transaction(self, tx: BaseTransaction, *, only_metadata: bool = False) -> None:
        raise NotImplementedError

    def _reset_cache(self) -> None:
        """Reset all caches. This function should not be called unless you know what you are doing."""
        if not self.with_index:
            raise NotImplementedError
        self._cache_block_count = 0
        self._cache_tx_count = 0

        self.block_index = IndexesManager()
        self.tx_index = IndexesManager()
        self.all_index = IndexesManager()
        self.wallet_index = None
        self.tokens_index = None

        self._latest_timestamp = 0
        from hathor.transaction.genesis import get_genesis_transactions
        self._first_timestamp = min(x.timestamp for x in get_genesis_transactions(self))

    def remove_cache(self) -> None:
        """Remove all caches in case we don't need it."""
        self.with_index = False
        self.block_index = None
        self.tx_index = None
        self.all_index = None

    def get_best_block_tips(self, timestamp: Optional[float] = None) -> List[bytes]:
        return super().get_best_block_tips(timestamp)

    def get_weight_best_block(self) -> float:
        return super().get_weight_best_block()

    def get_block_tips(self, timestamp: Optional[float] = None) -> Set[Interval]:
        if not self.with_index:
            raise NotImplementedError
        assert self.block_index is not None
        if timestamp is None:
            timestamp = self.latest_timestamp
        return self.block_index.tips_index[timestamp]

    def get_tx_tips(self, timestamp: Optional[float] = None) -> Set[Interval]:
        if not self.with_index:
            raise NotImplementedError
        assert self.tx_index is not None
        if timestamp is None:
            timestamp = self.latest_timestamp
        tips = self.tx_index.tips_index[timestamp]

        # This `for` is for assert only. How to skip it when running with `-O` parameter?
        for interval in tips:
            meta = self.get_metadata(interval.data)
            assert not meta.voided_by

        return tips

    def get_all_tips(self, timestamp: Optional[float] = None) -> Set[Interval]:
        if not self.with_index:
            raise NotImplementedError
        assert self.all_index is not None
        if timestamp is None:
            timestamp = self.latest_timestamp
        tips = self.all_index.tips_index[timestamp]
        return tips

    def get_newest_blocks(self, count: int) -> Tuple[List[Block], bool]:
        if not self.with_index:
            raise NotImplementedError
        assert self.block_index is not None
        block_hashes, has_more = self.block_index.get_newest(count)
        blocks = [self.get_transaction(block_hash) for block_hash in block_hashes]
        return blocks, has_more

    def get_newest_txs(self, count: int) -> Tuple[List[BaseTransaction], bool]:
        if not self.with_index:
            raise NotImplementedError
        assert self.tx_index is not None
        tx_hashes, has_more = self.tx_index.get_newest(count)
        txs = [self.get_transaction(tx_hash) for tx_hash in tx_hashes]
        return txs, has_more

    def get_older_blocks_after(self, timestamp: int, hash_bytes: bytes, count: int) -> Tuple[List[Block], bool]:
        if not self.with_index:
            raise NotImplementedError
        assert self.block_index is not None
        block_hashes, has_more = self.block_index.get_older(timestamp, hash_bytes, count)
        blocks = [self.get_transaction(block_hash) for block_hash in block_hashes]
        return blocks, has_more

    def get_newer_blocks_after(self, timestamp: int, hash_bytes: bytes,
                               count: int) -> Tuple[List[BaseTransaction], bool]:
        if not self.with_index:
            raise NotImplementedError
        assert self.block_index is not None
        block_hashes, has_more = self.block_index.get_newer(timestamp, hash_bytes, count)
        blocks = [self.get_transaction(block_hash) for block_hash in block_hashes]
        return blocks, has_more

    def get_older_txs_after(self, timestamp: int, hash_bytes: bytes, count: int) -> Tuple[List[BaseTransaction], bool]:
        if not self.with_index:
            raise NotImplementedError
        assert self.tx_index is not None
        tx_hashes, has_more = self.tx_index.get_older(timestamp, hash_bytes, count)
        txs = [self.get_transaction(tx_hash) for tx_hash in tx_hashes]
        return txs, has_more

    def get_newer_txs_after(self, timestamp: int, hash_bytes: bytes, count: int) -> Tuple[List[BaseTransaction], bool]:
        if not self.with_index:
            raise NotImplementedError
        assert self.tx_index is not None
        tx_hashes, has_more = self.tx_index.get_newer(timestamp, hash_bytes, count)
        txs = [self.get_transaction(tx_hash) for tx_hash in tx_hashes]
        return txs, has_more

    def _manually_initialize(self) -> None:
        self._reset_cache()

        # We need to construct a topological sort, then iterate from
        # genesis to tips.
        for tx in self._topological_sort():
            self._add_to_cache(tx)

    def _topological_sort(self) -> Iterator[BaseTransaction]:
        # TODO We must optimize this algorithm to remove the `visited` set.
        #      It will consume too much memory when the number of transactions is big.
        #      A solution would be to store the ordering in disk, probably indexing by tx's height.
        #      Sorting the vertices by the lengths of their longest incoming paths produces a topological
        #      ordering (Dekel, Nassimi & Sahni 1981). See: https://epubs.siam.org/doi/10.1137/0210049
        #      See also: https://gitlab.com/HathorNetwork/hathor-python/merge_requests/31
        visited: Dict[bytes, int] = dict()  # Dict[bytes, int]
        for tx in self.get_all_transactions():
            if not tx.is_block:
                continue
            yield from self._topological_sort_dfs(tx, visited)
        for tx in self.get_all_transactions():
            yield from self._topological_sort_dfs(tx, visited)

    def _topological_sort_dfs(self, root: BaseTransaction, visited: Dict[bytes, int]) -> Iterator[BaseTransaction]:
        if root.hash in visited:
            return

        stack = [root]
        while stack:
            tx = stack[-1]
            assert tx.hash is not None
            if tx.hash in visited:
                if visited[tx.hash] == 0:
                    visited[tx.hash] = 1  # 1 = Visited
                    yield tx
                assert tx == stack.pop()
                continue

            visited[tx.hash] = 0  # 0 = Visit in progress

            # The parents are reversed to go first through the blocks and only then
            # go through the transactions. It works because blocks must have the
            # previous block as the first parent. For transactions, the order does not
            # matter.
            for parent_hash in tx.parents[::-1]:
                if parent_hash not in visited:
                    parent = self.get_transaction(parent_hash)
                    stack.append(parent)

            for txin in tx.inputs:
                if txin.tx_id not in visited:
                    txinput = self.get_transaction(txin.tx_id)
                    stack.append(txinput)

    def _add_to_cache(self, tx: BaseTransaction) -> None:
        if not self.with_index:
            raise NotImplementedError
        assert self.all_index is not None
        assert self.block_index is not None
        assert self.tx_index is not None
        self._latest_timestamp = max(self.latest_timestamp, tx.timestamp)
        self.all_index.add_tx(tx)
        if self.wallet_index:
            self.wallet_index.add_tx(tx)
        if self.tokens_index:
            self.tokens_index.add_tx(tx)
        if tx.is_block:
            self._cache_block_count += 1
            self.block_index.add_tx(tx)
        else:
            self._cache_tx_count += 1
            self.tx_index.add_tx(tx)

    def _del_from_cache(self, tx: BaseTransaction, *, relax_assert: bool = False) -> None:
        if not self.with_index:
            raise NotImplementedError
        assert self.block_index is not None
        assert self.tx_index is not None
        if self.tokens_index:
            self.tokens_index.del_tx(tx)
        if tx.is_block:
            self._cache_block_count -= 1
            self.block_index.del_tx(tx, relax_assert=relax_assert)
        else:
            self._cache_tx_count -= 1
            self.tx_index.del_tx(tx, relax_assert=relax_assert)

    def get_block_count(self) -> int:
        if not self.with_index:
            raise NotImplementedError
        return self._cache_block_count

    def get_tx_count(self) -> int:
        if not self.with_index:
            raise NotImplementedError
        return self._cache_tx_count

    def get_genesis(self, hash_bytes: bytes) -> Optional[BaseTransaction]:
        if not self._genesis_cache:
            self._create_genesis_cache()
        assert self._genesis_cache is not None
        return self._genesis_cache.get(hash_bytes, None)

    def get_all_genesis(self) -> Set[BaseTransaction]:
        if not self._genesis_cache:
            self._create_genesis_cache()
        assert self._genesis_cache is not None
        return set(self._genesis_cache.values())

    def _create_genesis_cache(self) -> None:
        from hathor.transaction.genesis import get_genesis_transactions
        self._genesis_cache = {}
        assert self._genesis_cache is not None
        for genesis in get_genesis_transactions(self):
            assert genesis.hash is not None
            self._genesis_cache[genesis.hash] = genesis

    def get_transactions_before(self, hash_bytes: bytes,
                                num_blocks: int = 100) -> List[BaseTransaction]:  # pragma: no cover
        ref_tx = self.get_transaction(hash_bytes)
        visited: Dict[bytes, int] = dict()  # Dict[bytes, int]
        result = [x for x in self._topological_sort_dfs(ref_tx, visited) if not x.is_block]
        result = result[-num_blocks:]
        return result

    def get_blocks_before(self, hash_bytes: bytes, num_blocks: int = 100) -> List[Block]:
        ref_tx = self.get_transaction(hash_bytes)
        if not ref_tx.is_block:
            raise TransactionIsNotABlock
        result = []  # List[Block]
        pending_visits = deque(ref_tx.parents)  # List[bytes]
        used = set(pending_visits)  # Set[bytes]
        while pending_visits:
            tx_hash = pending_visits.popleft()
            tx = self.get_transaction(tx_hash)
            if not tx.is_block:
                continue
            assert isinstance(tx, Block)
            result.append(tx)
            if len(result) >= num_blocks:
                break
            for parent_hash in tx.parents:
                if parent_hash not in used:
                    used.add(parent_hash)
                    pending_visits.append(parent_hash)
        return result

    def get_all_sorted_txs(self, timestamp: int, count: int, offset: int) -> TransactionsIndex:
        """ Returns ordered blocks and txs in a TransactionIndex
        """
        assert self.all_index is not None

        idx = self.all_index.txs_index.find_first_at_timestamp(timestamp)
        txs = self.all_index.txs_index[idx:idx+offset+count]

        # merge sorted txs and blocks
        all_sorted = TransactionsIndex()
        all_sorted.update(txs)
        return all_sorted
