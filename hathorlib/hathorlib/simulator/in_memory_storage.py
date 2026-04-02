# Copyright 2026 Hathor Labs
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

from hathorlib.nanocontracts.storage.factory import NCStorageFactory
from hathorlib.nanocontracts.storage.memory_backends import InMemoryNodeTrieStore


class InMemoryNCStorageFactory(NCStorageFactory):
    """Storage factory using in-memory backing store.

    NCStorageFactory already implements get_block_storage() and get_empty_block_storage()
    using self._store. This subclass just provides the InMemoryNodeTrieStore.
    """
    _store: InMemoryNodeTrieStore

    def __init__(self) -> None:
        self._store = InMemoryNodeTrieStore()
