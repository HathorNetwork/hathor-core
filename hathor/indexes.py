from intervaltree import IntervalTree, Interval
from math import inf


class TimestampIndex(object):
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
        self.tx_last_interval = {}

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

    def __getitem__(self, index):
        return self.tree[index]
