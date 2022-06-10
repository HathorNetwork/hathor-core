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

from typing import Any, NamedTuple

from hathor.nanocontracts.storage.base_storage import NCBaseStorage, NCStorageFactory


class DataKey(NamedTuple):
    nc_id: bytes
    key: str


class BalanceKey(NamedTuple):
    nanocontract_id: bytes
    token_uid: bytes


class NCMemoryStorage(NCBaseStorage):
    """Memory implementation of the storage."""

    def __init__(self, *, nc_id: bytes = b'') -> None:
        # Data
        self.data: dict[DataKey, Any] = {}

        # Balances
        self.balances: dict[BalanceKey, int] = {}

        # Prefix
        self.nc_id = nc_id

    def _to_key(self, key: str) -> DataKey:
        """Return the actual key used in the storage."""
        return DataKey(self.nc_id, key)

    def get(self, key: str) -> Any:
        internal_key = self._to_key(key)
        return self.data[internal_key]

    def put(self, key: str, value: Any) -> None:
        internal_key = self._to_key(key)
        self.data[internal_key] = value

    def delete(self, key: str) -> None:
        internal_key = self._to_key(key)
        del self.data[internal_key]

    def get_balance(self, token_uid: bytes) -> int:
        key = BalanceKey(self.nc_id, token_uid)
        return self.balances.get(key, 0)

    def add_balance(self, token_uid: bytes, amount: int) -> None:
        key = BalanceKey(self.nc_id, token_uid)
        old = self.balances.get(key, 0)
        new = old + amount
        assert new >= 0, 'balance cannot be negative'
        self.balances[key] = new


class NCMemoryStorageFactory(NCStorageFactory):
    """Factory to create a memory storage for a contract.

    As it is a memory storage, the factory keeps all contract stored data on
    its attribute `self.data`.
    """

    def __init__(self) -> None:
        # This attribute stores data from all contracts.
        self.data: dict[DataKey, Any] = {}

        # This attribute stores balances from all contracts.
        self.balances: dict[BalanceKey, int] = {}

    def __call__(self, nano_contract_id: bytes) -> NCBaseStorage:
        storage = NCMemoryStorage(nc_id=nano_contract_id)
        storage.data = self.data
        storage.balances = self.balances
        return storage
