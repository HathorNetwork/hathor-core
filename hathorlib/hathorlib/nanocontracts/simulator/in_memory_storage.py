# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
