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

from typing import List, Optional, Tuple

from sortedcontainers import SortedKeyList
from structlog import get_logger

from hathor.indexes.utils import (
    TransactionIndexElement,
    get_newer_sorted_key_list,
    get_newest_sorted_key_list,
    get_older_sorted_key_list,
)
from hathor.transaction import BaseTransaction

logger = get_logger()


class TimestampIndex:
    """ Index of transactions sorted by their timestamps.
    """

    transactions: 'SortedKeyList[TransactionIndexElement]'

    def __init__(self) -> None:
        self.transactions = SortedKeyList(key=lambda x: (x.timestamp, x.hash))

    def __getitem__(self, index: slice) -> List[TransactionIndexElement]:
        """ Get items from SortedKeyList given a slice

        :param index: list index slice, for eg [1:6]
        """
        return self.transactions[index]

    def update(self, values: List[TransactionIndexElement]) -> None:
        """ Update sorted list by adding all values from iterable

        :param values: new values to add to SortedKeyList
        """
        self.transactions.update(values)

    def add_tx(self, tx: BaseTransaction) -> bool:
        """ Add a transaction to the index

        :param tx: Transaction to be added
        """
        assert tx.hash is not None
        # It is safe to use the in operator because it is O(log(n)).
        # http://www.grantjenks.com/docs/sortedcontainers/sortedlist.html#sortedcontainers.SortedList.__contains__
        element = TransactionIndexElement(tx.timestamp, tx.hash)
        if element in self.transactions:
            return False
        self.transactions.add(element)
        return True

    def del_tx(self, tx: BaseTransaction) -> None:
        """ Delete a transaction from the index

        :param tx: Transaction to be deleted
        """
        idx = self.transactions.bisect_key_left((tx.timestamp, tx.hash))
        if idx < len(self.transactions) and self.transactions[idx].hash == tx.hash:
            self.transactions.pop(idx)

    def find_tx_index(self, tx: BaseTransaction) -> Optional[int]:
        """Return the index of a transaction in the index

        :param tx: Transaction to be found
        """
        idx = self.transactions.bisect_key_left((tx.timestamp, tx.hash))
        if idx < len(self.transactions) and self.transactions[idx].hash == tx.hash:
            return idx
        return None

    def get_newest(self, count: int) -> Tuple[List[bytes], bool]:
        """ Get transactions or blocks from the newest to the oldest

        :param count: Number of transactions or blocks to be returned
        :return: List of tx hashes and a boolean indicating if has more txs
        """
        return get_newest_sorted_key_list(self.transactions, count)

    def get_older(self, timestamp: int, hash_bytes: bytes, count: int) -> Tuple[List[bytes], bool]:
        """ Get transactions or blocks from the timestamp/hash_bytes reference to the oldest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of transactions or blocks to be returned
        :return: List of tx hashes and a boolean indicating if has more txs
        """
        return get_older_sorted_key_list(self.transactions, timestamp, hash_bytes, count)

    def get_newer(self, timestamp: int, hash_bytes: bytes, count: int) -> Tuple[List[bytes], bool]:
        """ Get transactions or blocks from the timestamp/hash_bytes reference to the newest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of transactions or blocks to be returned
        :return: List of tx hashes and a boolean indicating if has more txs
        """
        return get_newer_sorted_key_list(self.transactions, timestamp, hash_bytes, count)

    def find_first_at_timestamp(self, timestamp: int) -> int:
        """ Get index of first element at the given timestamp, or where it would be inserted if
        the timestamp is not in the list.

        Eg: SortedKeyList = [(3,hash1), (3, hash2), (7, hash3), (8, hash4)]
        find_first_at_timestamp(7) = 2, which is the index of (7, hash3)
        find_first_at_timestamp(4) = 2, which is the index of (7, hash3)

        :param timestamp: timestamp we're interested in
        :return: the index of the element, or None if timestamp is greater than all in the list
        """
        idx = self.transactions.bisect_key_left((timestamp, b''))
        return idx
