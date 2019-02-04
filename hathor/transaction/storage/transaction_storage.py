from abc import ABC, abstractmethod, abstractproperty
from collections import deque
from itertools import chain
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from graphviz.dot import Digraph
from intervaltree.interval import Interval
from twisted.internet.defer import inlineCallbacks, succeed

from hathor.indexes import IndexesManager, TipsIndex
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.transaction.block import Block
from hathor.transaction.storage.exceptions import TransactionDoesNotExist, TransactionIsNotABlock
from hathor.transaction.transaction import BaseTransaction, Transaction
from hathor.transaction.transaction_metadata import TransactionMetadata
from hathor.util import deprecated, skip_warning


class TransactionStorage(ABC):
    """Legacy sync interface, please copy @deprecated decorator when implementing methods."""

    pubsub: Optional[PubSubManager]
    with_index: bool  # noqa: E701

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
    @deprecated('Use transaction_exists_deferred instead')
    def transaction_exists(self, hash_bytes):
        """Returns `True` if transaction with hash `hash_bytes` exists.

        :param hash_bytes: Hash in bytes that will be checked.
        """
        raise NotImplementedError

    @abstractmethod
    @deprecated('Use get_transaction_deferred instead')
    def get_transaction(self, hash_bytes):
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
    def save_transaction_deferred(self, tx, *, only_metadata=False):
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
    def transaction_exists_deferred(self, hash_bytes):
        """Returns `True` if transaction with hash `hash_bytes` exists.

        :param hash_bytes: Hash in bytes that will be checked.
        :type hash_bytes: bytes

        :rtype :py:class:`twisted.internet.defer.Deferred[bool]`
        """
        raise NotImplementedError

    @abstractmethod
    def get_transaction_deferred(self, hash_bytes):
        """Returns the transaction with hash `hash_bytes`.

        :param hash_bytes: Hash in bytes that will be checked.
        :type hash_bytes: bytes

        :rtype :py:class:`twisted.internet.defer.Deferred[hathor.transaction.BaseTransaction]`
        """
        raise NotImplementedError

    @inlineCallbacks
    def get_metadata_deferred(self, hash_bytes):
        """Returns the transaction metadata with hash `hash_bytes`.

        :param hash_bytes: Hash in bytes that will be checked.
        :type hash_bytes: bytes

        :rtype :py:class:`twisted.internet.defer.Deferred[hathor.transaction.TransactionMetadata]`
        """
        try:
            tx = yield self.get_transaction_deferred(hash_bytes)
            return tx.get_metadata(use_storage=False)
        except TransactionDoesNotExist:
            pass

    @abstractmethod
    def get_all_transactions_deferred(self):
        # TODO: find an `async generator` type
        # TODO: verify the following claim:
        """Return all transactions that are not blocks.

        :rtype :py:class:`twisted.internet.defer.Deferred[typing.Iterable[hathor.transaction.BaseTransaction]]`
        """
        raise NotImplementedError

    @abstractmethod
    def get_count_tx_blocks_deferred(self):
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
                               count: int) -> Tuple[List[BaseTransaction], bool]:
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
    def _manually_initialize(self):
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
    def iter_bfs_children(self, root) -> Iterator[BaseTransaction]:
        """Run a BFS starting from the given transaction to the tips (left-to-right)

        :param root: Starting point of the BFS, either a block or a transaction.
        :return: An iterable with the transactions (without the root)
        """
        raise NotImplementedError

    @abstractmethod
    def iter_bfs_spent_by(self, root: Transaction) -> Iterator[BaseTransaction]:
        """Run a BFS starting from the given transaction (left-to-right)

        :param root: Starting point of the BFS, either a block or a transaction.
        :return: An iterable with the transactions (without the root)
        """
        raise NotImplementedError

    @abstractmethod
    def _add_to_cache(self, tx):
        raise NotImplementedError

    @abstractmethod
    def _del_from_cache(self, tx):
        raise NotImplementedError

    @abstractmethod
    def get_block_count(self):
        raise NotImplementedError

    @abstractmethod
    def get_tx_count(self):
        raise NotImplementedError

    @abstractmethod
    def get_genesis(self, hash_bytes):
        """Returning hardcoded genesis block and transactions."""
        raise NotImplementedError

    @abstractmethod
    def get_all_genesis(self):
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
    def iter_bfs_ascendent_blocks(self, root: Block, max_depth: int) -> Iterator[Block]:
        """Iterate through all ascendents in a BFS algorithm, starting from `root` until reach `max_depth`.

        Only blocks are yielded.

        :param root: Start point of the BSF
        :return: An iterable of transactions
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

    def graphviz(self, format: str = 'pdf', weight: bool = False, acc_weight: bool = False,
                 block_only: bool = False, version: bool = False) -> Digraph:
        """Return a Graphviz object that can be rendered to generate a visualization of the DAG.

        :param format: Format of the visualization (pdf, png, or jpg)
        :param weight: Whether to display or not the tx weight
        :param acc_weight: Whether to display or not the tx accumulated weight
        :return: A Graphviz object
        """
        from graphviz import Digraph

        dot = Digraph(format=format)

        g_blocks = dot.subgraph(name='blocks')
        g_txs = dot.subgraph(name='txs')
        g_genesis = dot.subgraph(name='genesis')

        tx_tips_attrs = dict(style='filled', fillcolor='#F5D76E')
        block_attrs = dict(shape='box', style='filled', fillcolor='#EC644B')

        voided_attrs = dict(style='dashed,filled', penwidth='0.25', fillcolor='#BDC3C7')
        conflict_attrs = dict(style='dashed,filled', penwidth='2.0', fillcolor='#BDC3C7')

        dot.attr('node', shape='oval', style='')
        nodes_iter = self._topological_sort()

        blocks_set = set()  # Set[bytes(hash)]
        txs_set = set()  # Set[bytes(hash)]

        # block_tips = set(x.data for x in self.get_block_tips())
        tx_tips = set(x.data for x in self.get_tx_tips())

        with g_genesis as g_g, g_txs as g_t, g_blocks as g_b:
            for i, tx in enumerate(nodes_iter):
                assert tx.hash is not None
                name = tx.hash.hex()
                attrs_node = {'label': tx.hash.hex()[-4:]}
                attrs_edge = {}

                if block_only and not tx.is_block:
                    continue

                if tx.is_block:
                    attrs_node.update(block_attrs)
                    blocks_set.add(tx.hash)
                else:
                    txs_set.add(tx.hash)

                if tx.hash in tx_tips:
                    attrs_node.update(tx_tips_attrs)

                if weight:
                    attrs_node.update(dict(label='{}\nw: {:.2f}'.format(attrs_node['label'], tx.weight)))

                if acc_weight:
                    metadata = tx.get_metadata()
                    attrs_node.update(
                        dict(label='{}\naw: {:.2f}'.format(attrs_node['label'], metadata.accumulated_weight)))

                if version:
                    attrs_node.update(
                        dict(label='{}\nv{}'.format(attrs_node['label'], tx.version)))

                if tx.is_genesis:
                    attrs_node.update(dict(fillcolor='#87D37C', style='filled'))
                    g_g.node(name, **attrs_node)
                else:
                    meta = tx.get_metadata()
                    if len(meta.voided_by) > 0:
                        attrs_node.update(voided_attrs)
                        if tx.hash in meta.voided_by:
                            attrs_node.update(conflict_attrs)

                    if tx.is_block:
                        g_b.node(name, **attrs_node)
                    else:
                        g_t.node(name, **attrs_node)

                for parent_hash in tx.parents:
                    if block_only and parent_hash not in blocks_set:
                        continue
                    if parent_hash in blocks_set:
                        attrs_edge.update(dict(penwidth='3'))
                    else:
                        attrs_edge.update(dict(penwidth='1'))
                    dot.edge(name, parent_hash.hex(), **attrs_edge)

        dot.attr(rankdir='RL')
        return dot

    def graphviz_funds(self, format: str = 'pdf', weight: bool = False, acc_weight: bool = False):
        """Return a Graphviz object that can be rendered to generate a visualization of the DAG.

        :param format: Format of the visualization (pdf, png, or jpg)
        :param weight: Whether to display or not the tx weight
        :param acc_weight: Whether to display or not the tx accumulated weight
        :return: A Graphviz object
        """
        from graphviz import Digraph

        dot = Digraph(format=format)

        g_blocks = dot.subgraph(name='blocks')
        g_txs = dot.subgraph(name='txs')
        g_genesis = dot.subgraph(name='genesis')

        tx_tips_attrs = dict(style='filled', fillcolor='#F5D76E')
        block_attrs = dict(shape='box', style='filled', fillcolor='#EC644B')

        voided_attrs = dict(style='dashed,filled', penwidth='0.25', fillcolor='#BDC3C7')
        conflict_attrs = dict(style='dashed,filled', penwidth='2.0', fillcolor='#BDC3C7')

        dot.attr('node', shape='oval', style='')
        nodes_iter = self._topological_sort()

        # block_tips = set(x.data for x in self.get_block_tips())
        tx_tips = set(x.data for x in self.get_tx_tips())

        with g_genesis as g_g, g_txs as g_t, g_blocks as g_b:
            for i, tx in enumerate(nodes_iter):
                assert tx.hash is not None
                name = tx.hash.hex()
                attrs_node = {'label': tx.hash.hex()[-4:]}
                attrs_edge = {}

                if tx.is_block:
                    attrs_node.update(block_attrs)
                    attrs_edge.update(dict(penwidth='4'))

                if tx.hash in tx_tips:
                    attrs_node.update(tx_tips_attrs)

                if weight:
                    attrs_node.update(dict(label='{}\nw: {:.2f}'.format(attrs_node['label'], tx.weight)))

                if acc_weight:
                    metadata = tx.get_metadata()
                    attrs_node.update(
                        dict(label='{}\naw: {:.2f}'.format(attrs_node['label'], metadata.accumulated_weight)))

                if tx.is_genesis:
                    attrs_node.update(dict(fillcolor='#87D37C', style='filled'))
                    g_g.node(name, **attrs_node)
                elif tx.is_block:
                    g_b.node(name, **attrs_node)
                else:
                    meta = tx.get_metadata()
                    if len(meta.voided_by) > 0:
                        attrs_node.update(voided_attrs)
                        if tx.hash in meta.voided_by:
                            attrs_node.update(conflict_attrs)
                    g_t.node(name, **attrs_node)

                for txin in tx.inputs:
                    dot.edge(name, txin.tx_id.hex(), **attrs_edge)

        dot.attr(rankdir='RL')
        return dot


class TransactionStorageAsyncFromSync(TransactionStorage):
    """Implement async interface from sync interface, for legacy implementations."""

    def save_transaction_deferred(self, tx, *, only_metadata=False):
        return succeed(skip_warning(self.save_transaction)(tx, only_metadata=only_metadata))

    def transaction_exists_deferred(self, hash_bytes):
        return succeed(skip_warning(self.transaction_exists)(hash_bytes))

    def get_transaction_deferred(self, hash_bytes):
        return succeed(skip_warning(self.get_transaction)(hash_bytes))

    def get_all_transactions_deferred(self):
        return succeed(skip_warning(self.get_all_transactions)())

    def get_count_tx_blocks_deferred(self):
        return succeed(skip_warning(self.get_count_tx_blocks)())


class BaseTransactionStorage(TransactionStorage):
    def __init__(self, with_index: bool = True, pubsub: Optional[Any] = None) -> None:
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

    def _reset_cache(self) -> None:
        """Reset all caches. This function should not be called unless you know what you are doing."""
        if not self.with_index:
            raise NotImplementedError
        self._cache_block_count = 0
        self._cache_tx_count = 0

        self.block_index = IndexesManager()
        self.tx_index = IndexesManager()
        self.all_index = TipsIndex()

        self._latest_timestamp = 0
        from hathor.transaction.genesis import genesis_transactions
        self._first_timestamp = min(x.timestamp for x in genesis_transactions(self))

    def remove_cache(self):
        """Remove all caches in case we don't need it."""
        self.with_index = False
        self.block_index = None
        self.tx_index = None
        self.all_index = None

    def get_best_block_tips(self, timestamp: Optional[float] = None) -> List[bytes]:
        return super().get_best_block_tips(timestamp)

    def get_block_tips(self, timestamp: Optional[float] = None) -> Set[Interval]:
        if not self.with_index:
            raise NotImplementedError
        if timestamp is None:
            timestamp = self.latest_timestamp
        return self.block_index.tips_index[timestamp]

    def get_tx_tips(self, timestamp: Optional[float] = None) -> Set[Interval]:
        if not self.with_index:
            raise NotImplementedError
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
        if timestamp is None:
            timestamp = self.latest_timestamp
        tips = self.all_index[timestamp]
        return tips

    def get_newest_blocks(self, count: int) -> Tuple[List[Block], bool]:
        if not self.with_index:
            raise NotImplementedError
        block_hashes, has_more = self.block_index.get_newest(count)
        blocks = [self.get_transaction(block_hash) for block_hash in block_hashes]
        return blocks, has_more

    def get_newest_txs(self, count):
        if not self.with_index:
            raise NotImplementedError
        tx_hashes, has_more = self.tx_index.get_newest(count)
        txs = [self.get_transaction(tx_hash) for tx_hash in tx_hashes]
        return txs, has_more

    def get_older_blocks_after(self, timestamp, hash_bytes, count):
        if not self.with_index:
            raise NotImplementedError
        block_hashes, has_more = self.block_index.get_older(timestamp, hash_bytes, count)
        blocks = [self.get_transaction(block_hash) for block_hash in block_hashes]
        return blocks, has_more

    def get_newer_blocks_after(self, timestamp, hash_bytes, count):
        if not self.with_index:
            raise NotImplementedError
        block_hashes, has_more = self.block_index.get_newer(timestamp, hash_bytes, count)
        blocks = [self.get_transaction(block_hash) for block_hash in block_hashes]
        return blocks, has_more

    def get_older_txs_after(self, timestamp, hash_bytes, count):
        if not self.with_index:
            raise NotImplementedError
        tx_hashes, has_more = self.tx_index.get_older(timestamp, hash_bytes, count)
        txs = [self.get_transaction(tx_hash) for tx_hash in tx_hashes]
        return txs, has_more

    def get_newer_txs_after(self, timestamp, hash_bytes, count):
        if not self.with_index:
            raise NotImplementedError
        tx_hashes, has_more = self.tx_index.get_newer(timestamp, hash_bytes, count)
        txs = [self.get_transaction(tx_hash) for tx_hash in tx_hashes]
        return txs, has_more

    def _manually_initialize(self):
        self._reset_cache()

        # We need to construct a topological sort, then iterate from
        # genesis to tips.
        for tx in self._topological_sort():
            self._add_to_cache(tx)

    def _topological_sort(self) -> Iterator:
        # TODO We must optimize this algorithm to remove the `visited` set.
        #      It will consume too much memory when the number of transactions is big.
        #      A solution would be to store the ordering in disk, probably indexing by tx's height.
        #      Sorting the vertices by the lengths of their longest incoming paths produces a topological
        #      ordering (Dekel, Nassimi & Sahni 1981). See: https://epubs.siam.org/doi/10.1137/0210049
        #      See also: https://gitlab.com/HathorNetwork/hathor-python/merge_requests/31
        visited: Dict[bytes, int] = dict()  # Dict[bytes, int]
        cnt = 0
        for tx in self.get_all_transactions():
            cnt += 1
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

            for txin in tx.inputs:
                if txin.tx_id not in visited:
                    txinput = self.get_transaction(txin.tx_id)
                    stack.append(txinput)

            for parent_hash in tx.parents:
                if parent_hash not in visited:
                    parent = self.get_transaction(parent_hash)
                    stack.append(parent)

    # XXX: NOT IN USE:
    def iter_bfs(self, root):  # pragma: no cover
        """Run a BFS starting from the given transaction to genesis (right_to_left)

        :param root: Starting point of the BFS, either a block or a transaction.
        :return: An iterable with the transactions (with the root)
        """
        to_visit = deque([root.hash])  # List[bytes]
        seen = set(to_visit)  # Set[bytes]

        while to_visit:
            tx_hash = to_visit.popleft()
            tx = self.get_transaction(tx_hash)
            yield tx
            seen.add(tx_hash)
            for parent_hash in tx.parents:
                if parent_hash not in seen:
                    to_visit.append(parent_hash)
                    seen.add(parent_hash)

    def iter_bfs_children(self, root: Transaction) -> Iterator[BaseTransaction]:
        to_visit = deque(root.get_metadata().children)  # List[bytes(hash)]
        seen = set(to_visit)  # Set[bytes]

        while to_visit:
            tx_hash = to_visit.popleft()
            tx = self.get_transaction(tx_hash)
            yield tx
            seen.add(tx_hash)
            for children_hash in tx.get_metadata().children:
                if children_hash not in seen:
                    to_visit.append(children_hash)
                    seen.add(children_hash)

    def iter_bfs_spent_by(self, root: Transaction) -> Iterator[BaseTransaction]:
        to_visit = deque(chain(*root.get_metadata().spent_outputs.values()))  # Deque[bytes(hash)]
        seen = set(to_visit)  # Set[bytes]

        while to_visit:
            tx_hash = to_visit.popleft()
            tx = self.get_transaction(tx_hash)
            yield tx
            seen.add(tx_hash)
            for spent_hash in chain(*tx.get_metadata().spent_outputs.values()):
                if spent_hash not in seen:
                    to_visit.append(spent_hash)
                    seen.add(spent_hash)

    def _add_to_cache(self, tx: BaseTransaction) -> None:
        if not self.with_index:
            raise NotImplementedError
        self._latest_timestamp = max(self.latest_timestamp, tx.timestamp)
        self.all_index.add_tx(tx)
        if tx.is_block:
            self._cache_block_count += 1
            self.block_index.add_tx(tx)
        else:
            self._cache_tx_count += 1
            self.tx_index.add_tx(tx)

    def _del_from_cache(self, tx: Transaction) -> None:
        if not self.with_index:
            raise NotImplementedError
        if tx.is_block:
            self._cache_block_count -= 1
            self.block_index.del_tx(tx)
        else:
            self._cache_tx_count -= 1
            self.tx_index.del_tx(tx)

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
        from hathor.transaction.genesis import genesis_transactions
        self._genesis_cache = {}
        assert self._genesis_cache is not None
        for genesis in genesis_transactions(self):
            assert genesis.hash is not None
            self._genesis_cache[genesis.hash] = genesis

    def get_best_height(self):  # pragma: no cover
        latest_block = self.get_latest_block()
        return latest_block.height

    def get_transactions_before(self, hash_bytes, num_blocks=100):  # pragma: no cover
        ref_tx = self.get_transaction(hash_bytes)
        visited = dict()  # Dict[bytes, int]
        result = [x for x in self._topological_sort_dfs(ref_tx, visited) if not x.is_block]
        result = result[-num_blocks:]
        return result

    def iter_bfs_ascendent_blocks(self, root: Block, max_depth: int) -> Iterator[Block]:
        pending_visits = deque([(1, parent_hash) for parent_hash in root.parents])
        used = set(root.parents)
        while pending_visits:
            depth, tx_hash = pending_visits.popleft()
            tx = self.get_transaction(tx_hash)
            if not tx.is_block:
                continue
            assert isinstance(tx, Block)
            yield tx
            if depth >= max_depth:
                continue
            for parent_hash in tx.parents:
                if parent_hash not in used:
                    used.add(parent_hash)
                    pending_visits.append((depth + 1, parent_hash))

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

    # XXX: NOT IN USE:
    def get_block_hashes_after(self, hash_bytes, num_blocks=100):  # pragma: no cover
        """Retrieve the next num_blocks block hashes after the given hash. Return value is a list of hashes."""
        hashes = []
        tx = self.get_transaction(hash_bytes)
        if not tx.is_block:
            raise TransactionIsNotABlock
        for i in range(tx.height + 1, tx.height + 1 + num_blocks):
            for h in self.get_block_hashes_at_height(i):
                hashes.append(h)
        return hashes

    # XXX: NOT IN USE:
    def get_latest(self, transactions, count=2, page=1):  # pragma: no cover
        transactions = sorted(transactions, key=lambda t: t.timestamp, reverse=True)

        # Calculating indexes based on count and page
        start_index = (page - 1) * count
        end_index = start_index + count
        return transactions[start_index:end_index]

    # XXX: NOT IN USE:
    def get_all_after_hash(self, transactions, ref_hash, count):  # pragma: no cover
        """ Receives the list of elements (txs or blocks) to be paginated.

        We first order the elements by timestamp and then
        If ref_hash is None, we return the first count elements
        If ref_hash is not None, we calculate the elements after ref_hash and if we still have more

        :param transactions: List of elements we need to paginate
        :param ref_hash: Hash in bytes passed as reference, so we can return the blocks after this one
        :param count: Quantity of elements to return
        :return: List of blocks or txs and a boolean indicating if there are more blocks before
        """
        # XXX This method is not optimized, we need to improve this search
        txs = sorted(transactions, key=lambda t: t.timestamp, reverse=True)

        total = len(txs)

        if not ref_hash:
            return txs[:count], total > count
        else:
            for idx, tx in enumerate(txs):
                if tx.hash == ref_hash:
                    start_idx = idx + 1
                    end_idx = start_idx + count
                    return txs[start_idx:end_idx], total > end_idx

    # XXX: NOT IN USE:
    def get_all_before_hash(self, transactions, ref_hash, count):  # pragma: no cover
        """ Receives the list of elements (txs or blocks) to be paginated.

        We first order the elements by timestamp and then
        We calculate the elements before ref_hash and if we still have more before it

        :param transactions: List of elements we need to paginate
        :param ref_hash: Hash in bytes passed as reference, so we can return the blocks before this one
        :param count: Quantity of elements to return
        :return: List of blocks or txs and a boolean indicating if there are more blocks before
        """
        # XXX This method is not optimized, we need to improve this search
        txs = sorted(transactions, key=lambda t: t.timestamp, reverse=True)

        for idx, tx in enumerate(txs):
            if tx.hash == ref_hash:
                start_idx = max(0, idx - count)
                return txs[start_idx:idx], start_idx > 0
