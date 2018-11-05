from intervaltree import IntervalTree, Interval
from sortedcontainers import SortedKeyList
from math import inf


class IndexesManager:
    """ IndexesManager manages all the indexes that we will have in the system

        The ideia is for the manager to handle all method calls to indexes,
        so it will know which index is better to use in each moment
    """
    def __init__(self):
        self.tips_index = TipsIndex()
        self.txs_index = TransactionsIndex()

    def add_tx(self, tx):
        """ Add a transaction to the indexes

        :param tx: Transaction to be added
        :type tx: :py:class:`hathor.transaction.BaseTransaction`
        """
        self.tips_index.add_tx(tx)
        self.txs_index.add_tx(tx)

    def del_tx(self, tx):
        """ Delete a transaction from the indexes

        :param tx: Transaction to be deleted
        :type tx: :py:class:`hathor.transaction.BaseTransaction`
        """
        self.tips_index.del_tx(tx)
        self.txs_index.del_tx(tx)

    def get_newest(self, count):
        """ Get transactions or blocks in txs_index from the newest to the oldest

            :param count: Number of transactions or blocks to be returned
            :type count: int

            :return: List of transactions or blocks and a boolean indicating if has more txs
            :rtype: Tuple[List[Transaction], bool]
        """
        return self.txs_index.get_newest(count)

    def get_older(self, timestamp, hash_bytes, count):
        """ Get transactions or blocks in txs_index from the timestamp/hash_bytes reference to the oldest

            :param timestamp: Timestamp reference to start the search
            :type timestamp: int

            :param hash_bytes: Hash reference to start the search
            :type hash_bytes: bytes

            :param count: Number of transactions or blocks to be returned
            :type count: int

            :return: List of transactions or blocks and a boolean indicating if has more txs
            :rtype: Tuple[List[Transaction], bool]
        """
        return self.txs_index.get_older(timestamp, hash_bytes, count)

    def get_newer(self, timestamp, hash_bytes, count):
        """ Get transactions or blocks in txs_index from the timestamp/hash_bytes reference to the newest

            :param timestamp: Timestamp reference to start the search
            :type timestamp: int

            :param hash_bytes: Hash reference to start the search
            :type hash_bytes: bytes

            :param count: Number of transactions or blocks to be returned
            :type count: int

            :return: List of transactions or blocks and a boolean indicating if has more txs
            :rtype: Tuple[List[Transaction], bool]
        """
        return self.txs_index.get_newer(timestamp, hash_bytes, count)


class TipsIndex(object):
    """ Use an interval tree to quick get the tips at a given timestamp.

    The interval of a transaction is in the form [begin, end), where `begin` is
    the transaction's timestamp, and `end` is when it was first verified by another
    transaction.

    If a transaction is still a tip, `end` is equal to infinity.

    If a transaction has been verified many times, `end` is equal to `min(tx.timestamp)`.

    TODO Use an interval tree stored in disk, possibly using a B-tree.
    """
    def __init__(self):
        self.tree = IntervalTree()
        self.tx_last_interval = {}  # Dict[bytes(hash), Interval]

    def add_tx(self, tx):
        """ Add a new transaction to the index

        :param tx: Transaction to be added
        :type tx: :py:class:`hathor.transaction.BaseTransaction`
        """
        for parent_hash in tx.parents:
            pi = self.tx_last_interval.get(parent_hash, None)
            if not pi:
                continue
            if tx.timestamp < pi.end:
                self.tree.discard(pi)
                new_interval = Interval(pi.begin, tx.timestamp, pi.data)
                self.tree.add(new_interval)
                self.tx_last_interval[parent_hash] = new_interval

        interval = Interval(tx.timestamp, inf, tx.hash)
        self.tree.add(interval)
        self.tx_last_interval[tx.hash] = interval

    def del_tx(self, tx):
        interval = self.tx_last_interval.pop(tx.hash, None)
        if interval is None:
            return
        self.tree.remove(interval)

    def __getitem__(self, index):
        return self.tree[index]


class TransactionsIndex:
    def __init__(self):
        self.transactions = SortedKeyList(key=lambda x: (x.timestamp, x.hash))

    def add_tx(self, tx):
        """ Add a transaction to the index

        :param tx: Transaction to be added
        :type tx: :py:class:`hathor.transaction.BaseTransaction`
        """
        self.transactions.add(tx)

    def del_tx(self, tx):
        """ Delete a transaction from the index

        :param tx: Transaction to be deleted
        :type tx: :py:class:`hathor.transaction.BaseTransaction`
        """
        idx = self.transactions.bisect_key_left((tx.timestamp, tx.hash))
        if idx < len(self.transactions) and self.transactions[idx].hash == tx.hash:
            self.transactions.pop(idx)

    def get_newest(self, count):
        """ Get transactions or blocks from the newest to the oldest

            :param count: Number of transactions or blocks to be returned
            :type count: int

            :return: List of transactions or blocks and a boolean indicating if has more txs
            :rtype: Tuple[List[Transaction], bool]
        """
        newest = self.transactions[-count:]
        newest.reverse()
        if count >= len(self.transactions):
            has_more = False
        else:
            has_more = True
        return newest, has_more

    def get_older(self, timestamp, hash_bytes, count):
        """ Get transactions or blocks from the timestamp/hash_bytes reference to the oldest

            :param timestamp: Timestamp reference to start the search
            :type timestamp: int

            :param hash_bytes: Hash reference to start the search
            :type hash_bytes: bytes

            :param count: Number of transactions or blocks to be returned
            :type count: int

            :return: List of transactions or blocks and a boolean indicating if has more txs
            :rtype: Tuple[List[Transaction], bool]
        """
        # Get idx of element
        idx = self.transactions.bisect_key_left((timestamp, hash_bytes))
        first_idx = max(0, idx-count)
        txs = self.transactions[first_idx:idx]
        # Reverse because we want the newest first
        txs.reverse()
        return txs, first_idx > 0

    def get_newer(self, timestamp, hash_bytes, count):
        """ Get transactions or blocks from the timestamp/hash_bytes reference to the newest

            :param timestamp: Timestamp reference to start the search
            :type timestamp: int

            :param hash_bytes: Hash reference to start the search
            :type hash_bytes: bytes

            :param count: Number of transactions or blocks to be returned
            :type count: int

            :return: List of transactions or blocks and a boolean indicating if has more txs
            :rtype: Tuple[List[Transaction], bool]
        """
        # Get idx of element
        idx = self.transactions.bisect_key_left((timestamp, hash_bytes))
        last_idx = min(len(self.transactions), idx + 1 + count)
        txs = self.transactions[idx+1:last_idx]
        # Reverse because we want the newest first
        txs.reverse()
        return txs, last_idx < len(self.transactions)
