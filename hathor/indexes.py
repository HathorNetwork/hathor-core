from math import inf
from typing import Dict, List, NamedTuple, Set, Tuple

from intervaltree import Interval, IntervalTree
from sortedcontainers import SortedKeyList

from hathor.transaction import BaseTransaction


class TransactionIndexElement(NamedTuple):
    timestamp: int
    hash: bytes


class IndexesManager:
    """ IndexesManager manages all the indexes that we will have in the system

        The ideia is for the manager to handle all method calls to indexes,
        so it will know which index is better to use in each moment
    """

    def __init__(self) -> None:
        self.tips_index = TipsIndex()
        self.txs_index = TransactionsIndex()

    def add_tx(self, tx: BaseTransaction) -> None:
        """ Add a transaction to the indexes

        :param tx: Transaction to be added
        """
        self.tips_index.add_tx(tx)
        self.txs_index.add_tx(tx)

    def del_tx(self, tx: BaseTransaction) -> None:
        """ Delete a transaction from the indexes

        :param tx: Transaction to be deleted
        """
        self.tips_index.del_tx(tx)
        self.txs_index.del_tx(tx)

    def get_newest(self, count: int) -> Tuple[List[bytes], bool]:
        """ Get transactions or blocks in txs_index from the newest to the oldest

        :param count: Number of transactions or blocks to be returned
        :return: List of tx hashes and a boolean indicating if has more txs
        """
        return self.txs_index.get_newest(count)

    def get_older(self, timestamp: int, hash_bytes: bytes, count: int) -> Tuple[List[bytes], bool]:
        """ Get transactions or blocks in txs_index from the timestamp/hash_bytes reference to the oldest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of transactions or blocks to be returned
        :return: List of tx hashes and a boolean indicating if has more txs
        """
        return self.txs_index.get_older(timestamp, hash_bytes, count)

    def get_newer(self, timestamp: int, hash_bytes: bytes, count: int) -> Tuple[List[bytes], bool]:
        """ Get transactions or blocks in txs_index from the timestamp/hash_bytes reference to the newest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of transactions or blocks to be returned
        :return: List of tx hashes and a boolean indicating if has more txs
        """
        return self.txs_index.get_newer(timestamp, hash_bytes, count)


class TipsIndex:
    """ Use an interval tree to quick get the tips at a given timestamp.

    The interval of a transaction is in the form [begin, end), where `begin` is
    the transaction's timestamp, and `end` is when it was first verified by another
    transaction.

    If a transaction is still a tip, `end` is equal to infinity.

    If a transaction has been verified many times, `end` is equal to `min(tx.timestamp)`.

    TODO Use an interval tree stored in disk, possibly using a B-tree.
    """

    # An interval tree used to know the tips at any timestamp.
    # The intervals are in the form (begin, end), where begin is the timestamp
    # of the transaction, and end is the smallest timestamp of the tx's children.
    tree: IntervalTree

    # It is a way to access the interval by the hash of the transaction.
    # It is useful because the interval tree allows access only by the interval.
    tx_last_interval: Dict[bytes, Interval]

    def __init__(self) -> None:
        self.tree = IntervalTree()
        self.tx_last_interval = {}  # Dict[bytes(hash), Interval]

    def add_tx(self, tx: BaseTransaction) -> None:
        """ Add a new transaction to the index

        :param tx: Transaction to be added
        """
        assert tx.hash is not None
        assert tx.storage is not None
        if tx.hash in self.tx_last_interval:
            return

        # Fix the end of the interval of its parents.
        for parent_hash in tx.parents:
            pi = self.tx_last_interval.get(parent_hash, None)
            if not pi:
                continue
            if tx.timestamp < pi.end:
                self.tree.remove(pi)
                new_interval = Interval(pi.begin, tx.timestamp, pi.data)
                self.tree.add(new_interval)
                self.tx_last_interval[parent_hash] = new_interval

        # Check whether any children has already been added.
        # It so, the end of the interval is equal to the smallest timestamp of the children.
        min_timestamp = inf
        meta = tx.get_metadata()
        for child_hash in meta.children:
            if child_hash in self.tx_last_interval:
                child = tx.storage.get_transaction(child_hash)
                min_timestamp = min(min_timestamp, child.timestamp)

        # Add the interval to the tree.
        interval = Interval(tx.timestamp, min_timestamp, tx.hash)
        self.tree.add(interval)
        self.tx_last_interval[tx.hash] = interval

    def del_tx(self, tx: BaseTransaction) -> None:
        """ Remove a transaction from the index.
        """
        assert tx.hash is not None
        assert tx.storage is not None

        interval = self.tx_last_interval.pop(tx.hash, None)
        if interval is None:
            return
        assert interval.end == inf
        self.tree.remove(interval)

        # Update its parents as tips if needed.
        # FIXME Although it works, it does not seem to be a good solution.
        for parent_hash in tx.parents:
            parent = tx.storage.get_transaction(parent_hash)
            if parent.is_block != tx.is_block:
                continue
            self.update_tx(parent)

    def update_tx(self, tx: BaseTransaction) -> None:
        """ Update a tx according to its children.
        """
        assert tx.storage is not None
        assert tx.hash is not None

        meta = tx.get_metadata()
        if meta.voided_by:
            assert tx.hash not in self.tx_last_interval
            return

        pi = self.tx_last_interval[tx.hash]

        min_timestamp = inf
        for child_hash in meta.children:
            if child_hash in self.tx_last_interval:
                child = tx.storage.get_transaction(child_hash)
                min_timestamp = min(min_timestamp, child.timestamp)

        if min_timestamp != pi.end:
            self.tree.remove(pi)
            new_interval = Interval(pi.begin, min_timestamp, pi.data)
            self.tree.add(new_interval)
            self.tx_last_interval[tx.hash] = new_interval

    def __getitem__(self, index: float) -> Set[Interval]:
        return self.tree[index]


class TransactionsIndex:
    """ Index of transactions sorted by their timestamps.
    """

    transactions: 'SortedKeyList[TransactionIndexElement]'

    def __init__(self) -> None:
        self.transactions = SortedKeyList(key=lambda x: (x.timestamp, x.hash))

    def add_tx(self, tx: BaseTransaction) -> None:
        """ Add a transaction to the index

        :param tx: Transaction to be added
        """
        assert tx.hash is not None
        # It is safe to use the in operator because it is O(log(n)).
        # http://www.grantjenks.com/docs/sortedcontainers/sortedlist.html#sortedcontainers.SortedList.__contains__
        if tx in self.transactions:
            return
        self.transactions.add(TransactionIndexElement(tx.timestamp, tx.hash))

    def del_tx(self, tx: BaseTransaction) -> None:
        """ Delete a transaction from the index

        :param tx: Transaction to be deleted
        """
        idx = self.transactions.bisect_key_left((tx.timestamp, tx.hash))
        if idx < len(self.transactions) and self.transactions[idx].hash == tx.hash:
            self.transactions.pop(idx)

    def get_newest(self, count: int) -> Tuple[List[bytes], bool]:
        """ Get transactions or blocks from the newest to the oldest

        :param count: Number of transactions or blocks to be returned
        :return: List of tx hashes and a boolean indicating if has more txs
        """
        newest = self.transactions[-count:]
        newest.reverse()
        if count >= len(self.transactions):
            has_more = False
        else:
            has_more = True
        return [tx_index.hash for tx_index in newest], has_more

    def get_older(self, timestamp: int, hash_bytes: bytes, count: int) -> Tuple[List[bytes], bool]:
        """ Get transactions or blocks from the timestamp/hash_bytes reference to the oldest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of transactions or blocks to be returned
        :return: List of tx hashes and a boolean indicating if has more txs
        """
        # Get idx of element
        idx = self.transactions.bisect_key_left((timestamp, hash_bytes))
        first_idx = max(0, idx - count)
        txs = self.transactions[first_idx:idx]
        # Reverse because we want the newest first
        txs.reverse()
        return [tx_index.hash for tx_index in txs], first_idx > 0

    def get_newer(self, timestamp: int, hash_bytes: bytes, count: int) -> Tuple[List[bytes], bool]:
        """ Get transactions or blocks from the timestamp/hash_bytes reference to the newest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of transactions or blocks to be returned
        :return: List of tx hashes and a boolean indicating if has more txs
        """
        # Get idx of element
        idx = self.transactions.bisect_key_left((timestamp, hash_bytes))
        last_idx = min(len(self.transactions), idx + 1 + count)
        txs = self.transactions[idx + 1:last_idx]
        # Reverse because we want the newest first
        txs.reverse()
        return [tx_index.hash for tx_index in txs], last_idx < len(self.transactions)
