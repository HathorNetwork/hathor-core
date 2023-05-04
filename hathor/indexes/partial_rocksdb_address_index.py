# Copyright 2023 Hathor Labs
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

from typing import TYPE_CHECKING, List, Optional

from hathor.indexes.address_index import AddressIndex
from hathor.indexes.memory_address_index import MemoryAddressIndex
from hathor.indexes.rocksdb_address_index import RocksDBAddressIndex
from hathor.transaction import BaseTransaction

if TYPE_CHECKING:  # pragma: no cover
    from hathor.indexes.manager import IndexesManager


class PartialRocksDBAddressIndex(AddressIndex):
    """ This class is a hybrid Memory+RocksDB implementation that relies on both Memory and RocksDB implementations.


    Basically it needs both Memory and RocksDB instances and will work as follows:

    - read operations will be forwarded to the Memory implementation (better read performance)
    - write operations will be forwarded to both implementations (worse write performance)
    - initialization is performed by converting from the RocksDB implementation (better than initializing from
      transactions, but still worse than not having to do any initialization, like in the case of only using RocksDB)
    """

    def __init__(self, memory_address_index: MemoryAddressIndex, rocksdb_address_index: RocksDBAddressIndex) -> None:
        self._memory = MemoryAddressIndex
        self._rocksdb = RocksDBAddressIndex

    def get_db_name(self) -> Optional[str]:
        return self._rocksdb.get_db_name()

    def init_start(self, indexes_manager: 'IndexesManager') -> None:
        # XXX: this method uses the internal of both indexes to initialize the memory index from the rocksdb index
        assert len(self._memory.index) == 0, "memory index not empty, are you running init_start() twice?"
        for key, timestamp, tx_hash in self._rocksdb._iter_items():
            self._memory.index[key].add(tx_hash)

    def add_tx(self, tx: BaseTransaction) -> None:
        self._rocksdb.add_tx(tx)
        self._memory.add_tx(tx)

    def remove_tx(self, tx: BaseTransaction) -> None:
        self._rocksdb.remove_tx(tx)
        self._memory.remove_tx(tx)

    def get_from_address(self, address: str) -> List[bytes]:
        return self._memory.get_from_address(address)

    def get_sorted_from_address(self, address: str) -> List[bytes]:
        return self._memory.get_sorted_from_address(address)

    def is_address_empty(self, address: str) -> bool:
        return self._memory.is_address_empty(address)
