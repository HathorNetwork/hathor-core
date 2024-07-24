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

import pickle
from typing import Any, Optional

from hathor.nanocontracts.storage.backends import MemoryNodeTrieStore
from hathor.nanocontracts.storage.base_storage import AttrKey, BalanceKey, NCBaseStorage, NCStorageFactory, _Tag
from hathor.nanocontracts.storage.patricia_trie import PatriciaTrie
from hathor.nanocontracts.storage.types import _NOT_PROVIDED, DeletedKey, DeletedKeyType
from hathor.types import VertexId


class NCMemoryStorage(NCBaseStorage):
    """Memory implementation of the storage."""

    def __init__(self, *, trie: PatriciaTrie, nc_id: VertexId) -> None:
        # State (balances and attributes)
        self._trie: PatriciaTrie = trie

        # Nano contract id
        self.nc_id = nc_id

    def _serialize(self, value: Any) -> bytes:
        """Serialize a value to be stored on RocksDB."""
        return pickle.dumps(value)

    def _deserialize(self, _bytes: bytes) -> Any:
        """Deserialize a value to be stored on RocksDB."""
        value = pickle.loads(_bytes)
        if isinstance(value, DeletedKeyType):
            return DeletedKey
        return value

    def _trie_get(self, key: bytes, *, default: Any = _NOT_PROVIDED) -> Any:
        try:
            value_bytes = self._trie.get(key)
        except KeyError:
            if default is _NOT_PROVIDED:
                raise
            return default
        else:
            return self._deserialize(value_bytes)

    def _trie_update(self, key: bytes, value: Any) -> None:
        value_bytes = self._serialize(value)
        self._trie.update(key, value_bytes)

    def _to_attr_key(self, key: str) -> AttrKey:
        """Return the actual key used in the storage."""
        return AttrKey(self.nc_id, key)

    def get(self, key: str, *, default: Any = _NOT_PROVIDED) -> Any:
        internal_key = self._to_attr_key(key)
        internal_key_bytes = bytes(internal_key)
        try:
            value = self._trie_get(internal_key_bytes, default=default)
        except KeyError as e:
            raise KeyError(f'key={key!r} key_bytes={internal_key_bytes!r}') from e
        if value is DeletedKey:
            raise KeyError(key)
        return value

    def put(self, key: str, value: Any) -> None:
        internal_key = self._to_attr_key(key)
        self._trie_update(bytes(internal_key), value)

    def delete(self, key: str) -> None:
        internal_key = self._to_attr_key(key)
        self._trie_update(bytes(internal_key), DeletedKey)

    def get_balance(self, token_uid: bytes) -> int:
        key = BalanceKey(self.nc_id, token_uid)
        return self._trie_get(bytes(key), default=0)

    def get_all_balances(self) -> dict[BalanceKey, int]:
        balances: dict[BalanceKey, int] = {}
        balance_tag = self._trie._encode_key(_Tag.BALANCE.value)

        node = self._trie._find_nearest_node(balance_tag)
        if node.key.startswith(balance_tag):
            balance_root = node
        else:
            for prefix, child_id in node.children.items():
                child = self._trie.get_node(child_id)
                if child.key.startswith(balance_tag):
                    balance_root = child
                    break
            else:
                # No balance found.
                return balances

        for node, _, is_leaf in self._trie.iter_dfs(node=balance_root):
            if node.value is None:
                # Skip all nodes with no value.
                continue
            # Found a leaf!
            assert is_leaf
            assert node.value is not None
            value = self._deserialize(node.value)
            token_uid = self._trie._decode_key(node.key)[1:]
            key = BalanceKey(self.nc_id, token_uid)
            balances[key] = value
        return balances

    def add_balance(self, token_uid: bytes, amount: int) -> None:
        key = BalanceKey(self.nc_id, token_uid)
        key_bytes = bytes(key)
        old = self._trie_get(key_bytes, default=0)
        new = old + amount
        assert new >= 0, 'balance cannot be negative'
        self._trie_update(key_bytes, new)

    def commit(self) -> None:
        self._trie.commit()

    def get_root_id(self) -> bytes:
        assert self._trie.root.id is not None
        return self._trie.root.id


class NCMemoryStorageFactory(NCStorageFactory):
    """Factory to create a memory storage for a contract.

    As it is a memory storage, the factory keeps all contract stored data on
    its attribute `self.data`.
    """

    def __init__(self) -> None:
        # This attribute stores data from all contracts.
        self._store = MemoryNodeTrieStore()
        self._mempool_root_id = None

    def __call__(self, nano_contract_id: bytes, nc_root_id: Optional[bytes]) -> NCMemoryStorage:
        trie = self.get_trie(nc_root_id)
        return NCMemoryStorage(trie=trie, nc_id=nano_contract_id)
