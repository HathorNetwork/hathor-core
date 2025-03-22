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

import hashlib
import pickle
from enum import Enum
from typing import Any, NamedTuple

from hathor.nanocontracts.storage.patricia_trie import PatriciaTrie
from hathor.nanocontracts.storage.types import _NOT_PROVIDED, DeletedKey, DeletedKeyType
from hathor.nanocontracts.types import BlueprintId, VertexId


class _Tag(Enum):
    ATTR = b'\0'
    BALANCE = b'\1'
    METADATA = b'\2'


class AttrKey(NamedTuple):
    nc_id: bytes
    key: str

    def __bytes__(self):
        base = self.key.encode('ascii')
        return _Tag.ATTR.value + hashlib.sha1(base).digest()


class BalanceKey(NamedTuple):
    nc_id: bytes
    token_uid: bytes

    def __bytes__(self):
        return _Tag.BALANCE.value + self.token_uid


class MetadataKey(NamedTuple):
    nc_id: bytes
    key: bytes

    def __bytes__(self):
        return _Tag.METADATA.value + hashlib.sha1(self.key).digest()


BLUEPRINT_ID_KEY = b'blueprint_id'


class NCStorage:
    """This is the storage used by NanoContracts.

    This implementation works for both memory and rocksdb backends."""

    def __init__(self, *, trie: PatriciaTrie, nc_id: VertexId) -> None:
        # State (balances and attributes)
        self._trie: PatriciaTrie = trie

        # Nano contract id
        self.nc_id = nc_id

        # Flag to check whether any change or commit can be executed.
        self.is_locked = False

    def lock(self) -> None:
        """Lock the storage for changes or commits."""
        self.is_locked = True

    def unlock(self) -> None:
        """Unlock the storage."""
        self.is_locked = False

    def check_if_locked(self) -> None:
        """Raise a runtime error if the wallet is locked."""
        if self.is_locked:
            raise RuntimeError('you cannot modify or commit if the storage is locked')

    def _serialize(self, value: Any) -> bytes:
        """Serialize a value to be stored on the trie."""
        return pickle.dumps(value)

    def _deserialize(self, _bytes: bytes) -> Any:
        """Deserialize a value stored on the trie."""
        value = pickle.loads(_bytes)
        if isinstance(value, DeletedKeyType):
            return DeletedKey
        return value

    def _trie_get(self, key: bytes, *, default: Any = _NOT_PROVIDED) -> Any:
        """Internal method that gets the value of a key from the trie."""
        try:
            value_bytes = self._trie.get(key)
        except KeyError:
            if default is _NOT_PROVIDED:
                raise
            return default
        else:
            return self._deserialize(value_bytes)

    def _trie_update(self, key: bytes, value: Any) -> None:
        """Internal method that updates the value of a key in the trie."""
        value_bytes = self._serialize(value)
        self._trie.update(key, value_bytes)

    def _to_attr_key(self, key: str) -> AttrKey:
        """Return the actual key used in the storage."""
        return AttrKey(self.nc_id, key)

    def get(self, key: str, *, default: Any = _NOT_PROVIDED) -> Any:
        """Return the value of the provided `key`.

        It raises KeyError if key is not found and a default value is not provided.
        """
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
        """Store the `value` for the provided `key`.
        """
        self.check_if_locked()
        internal_key = self._to_attr_key(key)
        self._trie_update(bytes(internal_key), value)

    def delete(self, key: str) -> None:
        """Delete `key` from storage.
        """
        self.check_if_locked()
        internal_key = self._to_attr_key(key)
        self._trie_update(bytes(internal_key), DeletedKey)

    def contains(self, key: str) -> bool:
        """Check whether `key` exists in the storage."""
        try:
            _ = self.get(key)
        except KeyError:
            return False
        return True

    def _get_metadata(self, key: bytes) -> bytes:
        """Return the value of a metadata key."""
        internal_key = MetadataKey(self.nc_id, key)
        return self._trie_get(bytes(internal_key))

    def _put_metadata(self, key: bytes, value: bytes) -> None:
        """Store a new value for a metadata key."""
        internal_key = MetadataKey(self.nc_id, key)
        self._trie_update(bytes(internal_key), value)

    def get_blueprint_id(self) -> BlueprintId:
        """Return the blueprint id of the contract."""
        return BlueprintId(VertexId(self._get_metadata(BLUEPRINT_ID_KEY)))

    def set_blueprint_id(self, value: BlueprintId) -> None:
        """Set a new blueprint id for the contract."""
        return self._put_metadata(BLUEPRINT_ID_KEY, value)

    def get_balance(self, token_uid: bytes) -> int:
        """Return the contract balance for a token."""
        key = BalanceKey(self.nc_id, token_uid)
        return self._trie_get(bytes(key), default=0)

    def get_all_balances(self) -> dict[BalanceKey, int]:
        """Return the contract balances of all tokens."""
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
            # Found a token.
            assert node.value is not None
            value = self._deserialize(node.value)
            token_uid = self._trie._decode_key(node.key)[1:]
            key = BalanceKey(self.nc_id, token_uid)
            balances[key] = value
        return balances

    def add_balance(self, token_uid: bytes, amount: int) -> None:
        """Change the contract balance for a token. The amount will be added to the previous balance.

        Note that the amount might be negative."""
        self.check_if_locked()
        key = BalanceKey(self.nc_id, token_uid)
        key_bytes = bytes(key)
        old = self._trie_get(key_bytes, default=0)
        new = old + amount
        assert new >= 0, 'balance cannot be negative'
        self._trie_update(key_bytes, new)

    def commit(self) -> None:
        """Flush all local changes to the storage."""
        self.check_if_locked()
        self._trie.commit()

    def get_root_id(self) -> bytes:
        """Return the current merkle root id of the trie."""
        return self._trie.root.id
