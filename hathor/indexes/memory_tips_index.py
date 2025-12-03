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

from math import inf
from typing import Optional

from intervaltree import Interval, IntervalTree
from structlog import get_logger

from hathor.conf.settings import HathorSettings
from hathor.indexes.tips_index import ScopeType, TipsIndex
from hathor.transaction import BaseTransaction

logger = get_logger()


class MemoryTipsIndex(TipsIndex):
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
    tx_last_interval: dict[bytes, Interval]

    def __init__(self, *, scope_type: ScopeType, settings: HathorSettings) -> None:
        super().__init__(scope_type=scope_type, settings=settings)
        self.log = logger.new()
        self.tree = IntervalTree()
        self.tx_last_interval = {}

    def get_db_name(self) -> Optional[str]:
        return None

    def force_clear(self) -> None:
        self.tree.clear()
        self.tx_last_interval.clear()

    def init_loop_step(self, tx: BaseTransaction) -> None:
        tx_meta = tx.get_metadata()
        if not tx_meta.validation.is_final():
            return
        self.add_tx(tx)

    def _add_interval(self, interval: Interval) -> None:
        self.tree.add(interval)
        self.tx_last_interval[interval.data] = interval

    def _del_interval(self, interval: Interval) -> None:
        self.tree.remove(interval)

    def add_tx(self, tx: BaseTransaction) -> bool:
        """ Add a new transaction to the index

        :param tx: Transaction to be added
        """
        assert tx.storage is not None
        if tx.hash in self.tx_last_interval:
            return False

        # Fix the end of the interval of its parents.
        for parent_hash in tx.parents:
            pi = self.tx_last_interval.get(parent_hash, None)
            if not pi:
                continue
            if tx.timestamp < pi.end:
                self._del_interval(pi)
                new_interval = Interval(pi.begin, tx.timestamp, pi.data)
                self._add_interval(new_interval)

        # Check whether any children has already been added.
        # It so, the end of the interval is equal to the smallest timestamp of the children.
        min_timestamp = inf
        for child_hash in tx.get_children():
            if child_hash in self.tx_last_interval:
                child = tx.storage.get_transaction(child_hash)
                min_timestamp = min(min_timestamp, child.timestamp)

        # Add the interval to the tree.
        interval = Interval(tx.timestamp, min_timestamp, tx.hash)
        self._add_interval(interval)
        return True

    def del_tx(self, tx: BaseTransaction, *, relax_assert: bool = False) -> None:
        """ Remove a transaction from the index.
        """
        assert tx.storage is not None

        interval = self.tx_last_interval.pop(tx.hash, None)
        if interval is None:
            return

        if not relax_assert:
            assert interval.end == inf

        self._del_interval(interval)

        # Update its parents as tips if needed.
        # FIXME Although it works, it does not seem to be a good solution.
        for parent_hash in tx.parents:
            parent = tx.storage.get_transaction(parent_hash)
            if parent.is_block != tx.is_block:
                continue
            self.update_tx(parent, relax_assert=relax_assert)

    def update_tx(self, tx: BaseTransaction, *, relax_assert: bool = False) -> None:
        """ Update a tx according to its children.
        """
        assert tx.storage is not None

        meta = tx.get_metadata()
        if meta.voided_by:
            if not relax_assert:
                assert tx.hash not in self.tx_last_interval
            return

        pi = self.tx_last_interval[tx.hash]

        min_timestamp = inf
        for child_hash in tx.get_children():
            if child_hash in self.tx_last_interval:
                child = tx.storage.get_transaction(child_hash)
                min_timestamp = min(min_timestamp, child.timestamp)

        if min_timestamp != pi.end:
            self._del_interval(pi)
            new_interval = Interval(pi.begin, min_timestamp, pi.data)
            self._add_interval(new_interval)

    def __getitem__(self, index: float) -> set[Interval]:
        return self.tree[index]
