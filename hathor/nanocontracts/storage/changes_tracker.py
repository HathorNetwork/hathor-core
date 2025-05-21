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

from typing import Any

from hathor.nanocontracts.exception import NCInsufficientFunds
from hathor.nanocontracts.storage.storage import AttrKey, BalanceKey, NCStorage
from hathor.nanocontracts.storage.types import _NOT_PROVIDED, DeletedKey


class NCChangesTracker(NCStorage):
    """Keep track of changes during the execution of a contract's method.

    These changes are not committed to the storage."""

    def __init__(self, nc_id: bytes, storage: NCStorage):
        self.storage = storage
        self.nc_id = nc_id

        self.data: dict[AttrKey, Any] = {}
        self.balance_diff: dict[BalanceKey, int] = {}

        self.has_been_commited = False
        self.has_been_blocked = False

    def _to_key(self, key: str) -> AttrKey:
        """Return the actual key used in the storage."""
        assert self.nc_id is not None
        return AttrKey(self.nc_id, key)

    def check_if_locked(self) -> None:
        """Check if this instance has been locked. A lock occurs after a commit is executed."""
        if self.has_been_commited:
            raise RuntimeError('you cannot change any value after the commit has been executed')
        elif self.has_been_blocked:
            raise RuntimeError('you cannot change any value after the changes have been blocked')

    def block(self) -> None:
        """Block the changes and prevent them from being committed."""
        self.check_if_locked()
        self.has_been_blocked = True

    def get(self, key: str, *, default: Any = _NOT_PROVIDED) -> Any:
        internal_key = self._to_key(key)
        if internal_key in self.data:
            value = self.data[internal_key]
        else:
            value = self.storage.get(key, default=default)
        if value is DeletedKey:
            raise KeyError(key)
        return value

    def put(self, key: str, value: Any) -> None:
        self.check_if_locked()
        internal_key = self._to_key(key)
        self.data[internal_key] = value

    def delete(self, key: str) -> None:
        self.check_if_locked()
        internal_key = self._to_key(key)
        self.data[internal_key] = DeletedKey

    def commit(self) -> None:
        """Save the changes in the storage."""
        self.check_if_locked()
        for (_, key), value in self.data.items():
            if value is not DeletedKey:
                self.storage.put(key, value)
            else:
                self.storage.delete(key)
        for (_, token_uid), amount in self.balance_diff.items():
            self.storage.add_balance(token_uid, amount)
        self.has_been_commited = True

    def reset(self) -> None:
        """Discard all local changes without persisting."""
        self.data = {}
        self.balance_diff = {}

    def get_balance(self, token_uid: bytes) -> int:
        internal_key = BalanceKey(self.nc_id, token_uid)
        cur = self.storage.get_balance(token_uid)
        diff = self.balance_diff.get(internal_key, 0)
        return cur + diff

    def validate_balances(self) -> None:
        """Check that all final balances are positive. If not, it raises NCInsufficientFunds."""
        for _, token_uid in self.balance_diff.keys():
            balance = self.get_balance(token_uid)
            if balance < 0:
                raise NCInsufficientFunds(
                    f'negative balance for contract {self.nc_id.hex()} (balance={balance} token_uid={token_uid.hex()})'
                )

    def get_all_balances(self) -> dict[BalanceKey, int]:
        all_balances = self.storage.get_all_balances()
        for key, balance in all_balances.items():
            all_balances[key] = balance + self.balance_diff.get(key, 0)

        # There might be tokens in change tracker that are still not on storage
        # so we must check and add them as well
        for key, diff_balance in self.balance_diff.items():
            if key not in all_balances:
                all_balances[key] = diff_balance
        return all_balances

    def add_balance(self, token_uid: bytes, amount: int) -> None:
        self.check_if_locked()
        internal_key = BalanceKey(self.nc_id, token_uid)
        old = self.balance_diff.get(internal_key, 0)
        new = old + amount
        self.balance_diff[internal_key] = new

    def is_empty(self) -> bool:
        return not bool(self.data)

    def get_root_id(self) -> bytes:
        raise NotImplementedError
