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

from typing import Any, Iterator, Optional, TypeVar

from hathor.indexes import IndexesManager
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction.storage.migrations import MigrationState
from hathor.transaction.storage.transaction_storage import BaseTransactionStorage
from hathor.transaction.transaction import BaseTransaction
from hathor.transaction.transaction_metadata import TransactionMetadata

_Clonable = TypeVar('_Clonable', BaseTransaction, TransactionMetadata)


class TransactionMemoryStorage(BaseTransactionStorage):
    def __init__(self, indexes: Optional[IndexesManager] = None, *, _clone_if_needed: bool = False) -> None:
        """
        :param _clone_if_needed: *private parameter*, defaults to True, controls whether to clone
                                 transaction/blocks/metadata when returning those objects.
        :type _clone_if_needed: bool
        """
        self.transactions: dict[bytes, BaseTransaction] = {}
        self.metadata: dict[bytes, TransactionMetadata] = {}
        # Store custom key/value attributes
        self.attributes: dict[str, Any] = {}
        self._clone_if_needed = _clone_if_needed
        super().__init__(indexes=indexes)

    def _check_and_set_network(self) -> None:
        # XXX: does not apply to memory storage, can safely be ignored
        pass

    def _check_and_apply_migrations(self):
        # XXX: does not apply to memory storage, can safely be ignored
        pass

    def _clone(self, x: _Clonable) -> _Clonable:
        if self._clone_if_needed:
            return x.clone()
        else:
            return x

    def get_migration_state(self, migration_name: str) -> MigrationState:
        # XXX: it will always return COMPLETED, migrations don't apply to memory storage
        return MigrationState.COMPLETED

    def set_migration_state(self, migration_name: str, state: MigrationState) -> None:
        # XXX: do nothing, migrations have no effect on memory storage
        pass

    def remove_transaction(self, tx: BaseTransaction) -> None:
        super().remove_transaction(tx)
        self.transactions.pop(tx.hash, None)
        self.metadata.pop(tx.hash, None)

    def save_transaction(self, tx: 'BaseTransaction', *, only_metadata: bool = False) -> None:
        super().save_transaction(tx, only_metadata=only_metadata)
        self._save_transaction(tx, only_metadata=only_metadata)

    def _save_transaction(self, tx: BaseTransaction, *, only_metadata: bool = False) -> None:
        if not only_metadata:
            self.transactions[tx.hash] = self._clone(tx)
        meta = getattr(tx, '_metadata', None)
        if meta:
            self.metadata[tx.hash] = self._clone(meta)

    def transaction_exists(self, hash_bytes: bytes) -> bool:
        return hash_bytes in self.transactions

    def _get_transaction(self, hash_bytes: bytes) -> BaseTransaction:
        if hash_bytes in self.transactions:
            tx = self._clone(self.transactions[hash_bytes])
            if hash_bytes in self.metadata:
                tx._metadata = self._clone(self.metadata[hash_bytes])
            assert tx._metadata is not None
            return tx
        else:
            raise TransactionDoesNotExist(hash_bytes.hex())

    def _get_all_transactions(self) -> Iterator[BaseTransaction]:
        for tx in self.transactions.values():
            tx = self._clone(tx)
            if tx.hash in self.metadata:
                tx._metadata = self._clone(self.metadata[tx.hash])
            yield tx

    def _get_local_vertices_count(self) -> int:
        return len(self.transactions)

    def is_empty(self) -> bool:
        return self._get_local_vertices_count() <= 3

    def add_value(self, key: str, value: str) -> None:
        self.attributes[key] = value

    def remove_value(self, key: str) -> None:
        self.attributes.pop(key, None)

    def get_value(self, key: str) -> Optional[str]:
        return self.attributes.get(key)
