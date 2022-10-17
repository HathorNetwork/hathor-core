# Copyright 2022 Hathor Labs
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

from typing import Optional

from hathor.indexes.info_index import InfoIndex
from hathor.transaction import BaseTransaction


class MemoryInfoIndex(InfoIndex):
    def __init__(self):
        self._block_count = 0
        self._tx_count = 0
        self._first_timestamp = 0
        self._latest_timestamp = 0

    def init_start(self) -> None:
        self.force_clear()

    def get_db_name(self) -> Optional[str]:
        return None

    def force_clear(self) -> None:
        from hathor.transaction.genesis import BLOCK_GENESIS, TX_GENESIS2
        self._block_count = 1
        self._tx_count = 2
        self._first_timestamp = BLOCK_GENESIS.timestamp
        self._latest_timestamp = TX_GENESIS2.timestamp

    def update_timestamps(self, tx: BaseTransaction) -> None:
        if tx.is_genesis:
            return
        self._latest_timestamp = max(self._latest_timestamp, tx.timestamp)
        self._first_timestamp = min(self._first_timestamp, tx.timestamp)

    def update_counts(self, tx: BaseTransaction, *, remove: bool = False) -> None:
        if tx.is_genesis:
            return
        if remove:
            if tx.is_block:
                if self._block_count == 0:
                    raise ValueError('cannot subtract more')
                self._block_count -= 1
            else:
                if self._tx_count == 0:
                    raise ValueError('cannot subtract more')
                self._tx_count -= 1
        else:
            if tx.is_block:
                self._block_count += 1
            else:
                self._tx_count += 1

    def get_block_count(self) -> int:
        return self._block_count

    def get_tx_count(self) -> int:
        return self._tx_count

    def get_vertices_count(self) -> int:
        return self.get_tx_count() + self.get_block_count()

    def get_latest_timestamp(self) -> int:
        return self._latest_timestamp

    def get_first_timestamp(self) -> int:
        return self._first_timestamp
