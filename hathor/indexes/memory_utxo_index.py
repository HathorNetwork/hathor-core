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

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterator, NamedTuple, Optional, Union

from sortedcontainers import SortedSet
from structlog import get_logger

from hathor.indexes.utxo_index import UtxoIndex, UtxoIndexItem

logger = get_logger()


class _IndexKey(NamedTuple):
    token_uid: bytes
    address: str


class _NoLockItem(NamedTuple):
    amount: int
    tx_id: bytes
    # XXX: using idx instead of index because `def index` exists in parent class
    idx: int


class _TimeLockItem(NamedTuple):
    timelock: int
    amount: int
    tx_id: bytes
    # XXX: using idx instead of index because `def index` exists in parent class
    idx: int


class _HeightLockItem(NamedTuple):
    heightlock: int
    amount: int
    tx_id: bytes
    # XXX: using idx instead of index because `def index` exists in parent class
    idx: int


@dataclass(frozen=True)
class _IndexItem:
    nolock: 'SortedSet[_NoLockItem]' = field(default_factory=SortedSet)
    timelock: 'SortedSet[_TimeLockItem]' = field(default_factory=SortedSet)
    heightlock: 'SortedSet[_HeightLockItem]' = field(default_factory=SortedSet)


class MemoryUtxoIndex(UtxoIndex):
    _index: defaultdict[_IndexKey, _IndexItem]

    def __init__(self):
        super().__init__()
        self._index = defaultdict(_IndexItem)

    def get_db_name(self) -> Optional[str]:
        return None

    def force_clear(self) -> None:
        self._index.clear()

    def _add_utxo(self, item: UtxoIndexItem) -> None:
        self.log.debug('add utxo', item=item)
        subindex = self._index[_IndexKey(item.token_uid, item.address)]
        if item.timelock is not None:
            subindex.timelock.add(_TimeLockItem(item.timelock, item.amount, item.tx_id, item.index))
        elif item.heightlock is not None:
            subindex.heightlock.add(_HeightLockItem(item.heightlock, item.amount, item.tx_id, item.index))
        else:
            subindex.nolock.add(_NoLockItem(item.amount, item.tx_id, item.index))

    def _remove_utxo(self, item: UtxoIndexItem) -> None:
        self.log.debug('del utxo', item=item)
        subindex = self._index[_IndexKey(item.token_uid, item.address)]
        if item.timelock is not None:
            subindex.timelock.discard(_TimeLockItem(item.timelock, item.amount, item.tx_id, item.index))
        elif item.heightlock is not None:
            subindex.heightlock.discard(_HeightLockItem(item.heightlock, item.amount, item.tx_id, item.index))
        else:
            subindex.nolock.discard(_NoLockItem(item.amount, item.tx_id, item.index))

    def _iter_utxos_nolock(self, *, token_uid: bytes, address: str, target_amount: int) -> Iterator[UtxoIndexItem]:
        subindex = self._index[_IndexKey(token_uid, address)].nolock
        # this will point to the next value that is equal or higher than target_amount
        idx_next_amount = subindex.bisect((target_amount,)) + 1
        for i in subindex.islice(stop=idx_next_amount, reverse=True):
            yield UtxoIndexItem(token_uid, i.tx_id, i.idx, address, i.amount, None, None)

    def _iter_utxos_timelock(self, *, token_uid: bytes, address: str, target_amount: int,
                             target_timestamp: Optional[int] = None) -> Iterator[UtxoIndexItem]:
        import math
        seek_timestamp: Union[int, float]
        if target_timestamp is None:
            seek_timestamp = math.inf
        else:
            seek_timestamp = target_timestamp
        subindex = self._index[_IndexKey(token_uid, address)].timelock
        # this will point to the next value that is equal or higher than target_amount
        idx_next_amount = subindex.bisect((seek_timestamp, target_amount)) + 1
        for i in subindex.islice(stop=idx_next_amount, reverse=True):
            # it might happen that the first one is out of the timestamp range
            if i.timelock > seek_timestamp:
                continue
            yield UtxoIndexItem(token_uid, i.tx_id, i.idx, address, i.amount, i.timelock, None)

    def _iter_utxos_heightlock(self, *, token_uid: bytes, address: str, target_amount: int,
                               target_height: Optional[int] = None) -> Iterator[UtxoIndexItem]:
        import math
        seek_height: Union[int, float]
        if target_height is None:
            seek_height = math.inf
        else:
            seek_height = target_height
        subindex = self._index[_IndexKey(token_uid, address)].heightlock
        # this will point to the next value that is equal or higher than target_amount
        idx_next_amount = subindex.bisect((seek_height, target_amount)) + 1
        for i in subindex.islice(stop=idx_next_amount, reverse=True):
            # it might happen that the first one is out of the heightlock range
            if i.heightlock > seek_height:
                continue
            yield UtxoIndexItem(token_uid, i.tx_id, i.idx, address, i.amount, None, i.heightlock)
