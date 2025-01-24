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

from __future__ import annotations

from typing import Iterator, Optional

from sortedcontainers import SortedKeyList
from structlog import get_logger

from hathor.indexes.timestamp_index import RangeIdx, ScopeType, TimestampIndex
from hathor.indexes.utils import (
    TransactionIndexElement,
    get_newer_sorted_key_list,
    get_newest_sorted_key_list,
    get_older_sorted_key_list,
)
from hathor.transaction import BaseTransaction

logger = get_logger()


class MemoryTimestampIndex(TimestampIndex):
    """ Index of transactions sorted by their timestamps.
    """

    _index: SortedKeyList[TransactionIndexElement]

    def __init__(self, *, scope_type: ScopeType):
        super().__init__(scope_type=scope_type)
        self.log = logger.new()
        self.force_clear()

    def get_db_name(self) -> Optional[str]:
        return None

    def force_clear(self) -> None:
        self._index = SortedKeyList(key=lambda x: (x.timestamp, x.hash))

    def add_tx(self, tx: BaseTransaction) -> bool:
        # It is safe to use the in operator because it is O(log(n)).
        # http://www.grantjenks.com/docs/sortedcontainers/sortedlist.html#sortedcontainers.SortedList.__contains__
        element = TransactionIndexElement(tx.timestamp, tx.hash)
        if element in self._index:
            return False
        self._index.add(element)
        return True

    def del_tx(self, tx: BaseTransaction) -> None:
        idx = self._index.bisect_key_left((tx.timestamp, tx.hash))
        if idx < len(self._index) and self._index[idx].hash == tx.hash:
            self._index.pop(idx)

    def get_newest(self, count: int) -> tuple[list[bytes], bool]:
        return get_newest_sorted_key_list(self._index, count)

    def get_older(self, timestamp: int, hash_bytes: bytes, count: int) -> tuple[list[bytes], bool]:
        return get_older_sorted_key_list(self._index, timestamp, hash_bytes, count)

    def get_newer(self, timestamp: int, hash_bytes: bytes, count: int) -> tuple[list[bytes], bool]:
        return get_newer_sorted_key_list(self._index, timestamp, hash_bytes, count)

    def get_hashes_and_next_idx(self, from_idx: RangeIdx, count: int) -> tuple[list[bytes], Optional[RangeIdx]]:
        timestamp, offset = from_idx
        idx = self._index.bisect_key_left((timestamp, b''))
        txs = SortedKeyList(key=lambda x: (x.timestamp, x.hash))
        txs.update(self._index[idx:idx+offset+count])
        ret_txs = txs[offset:offset+count]
        hashes = [tx.hash for tx in ret_txs]
        if len(ret_txs) < count:
            return hashes, None
        else:
            next_offset = offset + count
            next_timestamp = ret_txs[-1].timestamp
            if next_timestamp != timestamp:
                next_idx = txs.bisect_key_left((next_timestamp, b''))
                next_offset -= next_idx
        return hashes, RangeIdx(next_timestamp, next_offset)

    def iter(self) -> Iterator[bytes]:
        for element in self._index:
            yield element.hash

    def __contains__(self, elem: tuple[int, bytes]) -> bool:
        return TransactionIndexElement(*elem) in self._index
