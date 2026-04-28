# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING, Optional

from hathorlib.nanocontracts.storage.backends import NodeTrieStore
from hathorlib.nanocontracts.storage.block_storage import NCBlockStorage

if TYPE_CHECKING:
    from hathorlib.nanocontracts.storage.patricia_trie import NodeId, PatriciaTrie


class NCStorageFactory(ABC):
    _store: 'NodeTrieStore'

    @staticmethod
    def bytes_to_node_id(node_id: Optional[bytes]) -> Optional['NodeId']:
        from hathorlib.nanocontracts.storage.patricia_trie import NodeId
        if node_id is None:
            return node_id
        return NodeId(node_id)

    def _get_trie(self, root_id: Optional[bytes]) -> 'PatriciaTrie':
        """Return a PatriciaTrie object with a given root."""
        from hathorlib.nanocontracts.storage.patricia_trie import PatriciaTrie
        trie = PatriciaTrie(self._store, root_id=self.bytes_to_node_id(root_id))
        return trie

    def get_block_storage(self, block_root_id: bytes) -> NCBlockStorage:
        """Return a non-empty block storage."""
        trie = self._get_trie(block_root_id)
        return NCBlockStorage(trie)

    def get_empty_block_storage(self) -> NCBlockStorage:
        """Create an empty block storage."""
        trie = self._get_trie(None)
        return NCBlockStorage(trie)
