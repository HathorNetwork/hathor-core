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

import math
import time
from typing import TYPE_CHECKING, Dict, Iterator, Optional, Union

import structlog
from intervaltree import Interval, IntervalTree
from structlog import get_logger

from hathor.indexes.memory_tips_index import MemoryTipsIndex
from hathor.indexes.rocksdb_utils import RocksDBIndexUtils
from hathor.indexes.tips_index import ScopeType
from hathor.util import LogDuration

if TYPE_CHECKING:  # pragma: no cover
    import rocksdb

    from hathor.indexes.manager import IndexesManager

logger = get_logger()


_INF_PLACEHOLDER = 2**32 - 1
_DT_LOG_PROGRESS = 30  # time in seconds


def _to_db_value(i: Union[int, float]) -> int:
    if math.isinf(i):
        return _INF_PLACEHOLDER
    return int(i)


def _from_db_value(i: int) -> Union[int, float]:
    if i == _INF_PLACEHOLDER:
        return math.inf
    return i


def progress(iter_iv: Iterator[Interval], *, log: 'structlog.stdlib.BoundLogger', total: Optional[int],
             ) -> Iterator[Interval]:
    """ Implementation of progress helper for using with loading the interval tree.

    This is basically a stripped down version of `hathor.util.progress`
    """
    t_start = time.time()
    count = 0
    count_log_prev = 0
    if total is not None:
        log.info('loading... 0%', progress=0)
    else:
        log.info('loading...')
    t_log_prev = t_start
    while True:
        try:
            iv = next(iter_iv)
        except StopIteration:
            break

        t_log = time.time()
        dt_log = LogDuration(t_log - t_log_prev)
        if dt_log > _DT_LOG_PROGRESS:
            t_log_prev = t_log
            dcount = count - count_log_prev
            rate = '?' if dt_log == 0 else dcount / dt_log
            kwargs = dict(rate=rate, iv_new=dcount, dt=dt_log, total=count)
            if total is not None:
                progress = count / total
                # TODO: we could add an ETA since we know the total
                log.info(f'loading... {math.floor(progress * 100):2.0f}%', progress=progress, **kwargs)
            else:
                log.info('loading...', **kwargs)
            count_log_prev = count
        count += 1

        yield iv

    t_final = time.time()
    dt_total = LogDuration(t_final - t_start)
    rate = '?' if dt_total == 0 else count / dt_total
    if total is not None:
        progress = count / total
        log.info(f'loaded...  {math.floor(progress * 100):2.0f}%', progress=progress, count=count, rate=rate,
                 total_dt=dt_total)
    else:
        log.info('loaded', count=count, rate=rate, total_dt=dt_total)


class PartialRocksDBTipsIndex(MemoryTipsIndex, RocksDBIndexUtils):
    """ Partial memory-rocksdb implementation

    """

    # An interval tree used to know the tips at any timestamp.
    # The intervals are in the form (begin, end), where begin is the timestamp
    # of the transaction, and end is the smallest timestamp of the tx's children.
    tree: IntervalTree

    # It is a way to access the interval by the hash of the transaction.
    # It is useful because the interval tree allows access only by the interval.
    tx_last_interval: Dict[bytes, Interval]

    def __init__(self, db: 'rocksdb.DB', *, scope_type: ScopeType):
        MemoryTipsIndex.__init__(self, scope_type=scope_type)
        self._name = scope_type.get_name()
        self.log = logger.new()  # XXX: override MemoryTipsIndex logger so it shows the correct module
        RocksDBIndexUtils.__init__(self, db, f'tips-{self._name}'.encode())

    def get_db_name(self) -> Optional[str]:
        return f'tips_{self._name}'

    def force_clear(self) -> None:
        super().force_clear()
        self.clear()

    def _to_key(self, interval: Interval) -> bytes:
        import struct
        assert len(interval.data) == 32
        begin = _to_db_value(interval.begin)
        end = _to_db_value(interval.end)
        return struct.pack('>II', begin, end) + interval.data

    def _from_key(self, key: bytes) -> Interval:
        import struct
        assert len(key) == 4 + 4 + 32
        begin, end = struct.unpack('>II', key[:8])
        tx_id = key[8:]
        assert len(tx_id) == 32
        return Interval(_from_db_value(begin), _from_db_value(end), tx_id)

    def init_start(self, indexes_manager: 'IndexesManager') -> None:
        log = self.log.new(index=f'tips-{self._name}')
        total: Optional[int]
        if self is indexes_manager.all_tips:
            total = indexes_manager.info.get_tx_count() + indexes_manager.info.get_block_count()
        elif self is indexes_manager.block_tips:
            total = indexes_manager.info.get_block_count()
        elif self is indexes_manager.tx_tips:
            total = indexes_manager.info.get_tx_count()
        else:
            log.info('index not identified, skipping total count')
            total = None
        for iv in progress(self._iter_intervals_db(), log=log, total=total):
            self.tree.add(iv)
            self.tx_last_interval[iv.data] = iv

    def _iter_intervals_db(self) -> Iterator[Interval]:
        it = self._db.iterkeys(self._cf)
        it.seek_to_first()
        for _, key in it:
            yield self._from_key(key)

    def _add_interval_db(self, interval: Interval) -> None:
        self._db.put((self._cf, self._to_key(interval)), b'')

    def _del_interval_db(self, interval: Interval) -> None:
        self._db.delete((self._cf, self._to_key(interval)))

    def _add_interval(self, interval: Interval) -> None:
        super()._add_interval(interval)
        self._add_interval_db(interval)

    def _del_interval(self, interval: Interval) -> None:
        super()._del_interval(interval)
        self._del_interval_db(interval)
