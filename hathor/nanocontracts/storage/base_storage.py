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
from abc import ABC, abstractmethod
from enum import Enum
from typing import TYPE_CHECKING, Any, NamedTuple, Optional

from hathor.types import VertexId

if TYPE_CHECKING:
    from hathor.nanocontracts.storage.backends import NodeTrieStore
    from hathor.nanocontracts.storage.patricia_trie import NodeId, PatriciaTrie


class _Tag(Enum):
    ATTR = b'\0'
    BALANCE = b'\1'


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


class NCBaseStorage(ABC):
    """This is the storage used by NanoContracts.
    """

    @abstractmethod
    def get(self, key: str) -> Any:
        """Return the value of the provided `key`.

        It raises KeyError if key is not found.
        """
        raise NotImplementedError

    @abstractmethod
    def put(self, key: str, value: Any) -> None:
        """Store the `value` for the provided `key`.
        """
        raise NotImplementedError

    @abstractmethod
    def delete(self, key: str) -> None:
        """Delete `key` from storage.
        """
        raise NotImplementedError

    @abstractmethod
    def get_balance(self, token_uid: bytes) -> int:
        """Return the contract balance for a token."""
        raise NotImplementedError

    @abstractmethod
    def get_all_balances(self) -> dict[BalanceKey, int]:
        """Return the contract balances of all tokens."""
        raise NotImplementedError

    @abstractmethod
    def add_balance(self, token_uid: bytes, amount: int) -> None:
        """Change the contract balance for a token. The amount will be added to the previous balance.

        Note that the amount might be negative."""
        raise NotImplementedError

    @abstractmethod
    def commit(self) -> None:
        """Flush all local changes to the storage."""
        raise NotImplementedError

    def get_root_id(self) -> bytes:
        """Return the current merkle root id of the trie."""
        raise NotImplementedError


class NCStorageFactory(ABC):
    _store: 'NodeTrieStore'

    @staticmethod
    def bytes_to_node_id(node_id: Optional[bytes]) -> Optional['NodeId']:
        from hathor.nanocontracts.storage.patricia_trie import NodeId
        if node_id is None:
            return node_id
        return NodeId(node_id)

    def get_trie(self, root_id: Optional[bytes]) -> 'PatriciaTrie':
        """Return a PatriciaTrie object with a given root."""
        from hathor.nanocontracts.storage.patricia_trie import PatriciaTrie
        trie = PatriciaTrie(self._store, root_id=self.bytes_to_node_id(root_id))
        return trie

    @abstractmethod
    def __call__(self, nano_contract_id: VertexId, nc_root_id: Optional[bytes]) -> NCBaseStorage:
        """Return a storage object for a given nano contract."""
        raise NotImplementedError
