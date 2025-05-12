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

import itertools
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any

from typing_extensions import override

from hathor.conf.settings import HATHOR_TOKEN_UID
from hathor.nanocontracts.exception import NCInsufficientFunds, NCTokenAlreadyExists
from hathor.nanocontracts.storage.contract_storage import AttrKey, Balance, BalanceKey, NCContractStorage
from hathor.nanocontracts.storage.types import _NOT_PROVIDED, DeletedKey
from hathor.nanocontracts.types import ContractId, TokenUid
from hathor.transaction.token_creation_tx import TokenDescription


class _NCAuthorityState(Enum):
    """The tri-state of an authority during execution."""
    NONE = 'none'
    GRANTED = 'granted'
    REVOKED = 'revoked'


@dataclass(slots=True, kw_only=True)
class _NCAuthorityDiff:
    """Track the tri-state diff of each authority."""
    mint: _NCAuthorityState = _NCAuthorityState.NONE
    melt: _NCAuthorityState = _NCAuthorityState.NONE

    def grant_mint(self) -> bool:
        """Return whether the final mint state of this diff in granted."""
        return self.mint is _NCAuthorityState.GRANTED

    def grant_melt(self) -> bool:
        """Return whether the final melt state of this diff in granted."""
        return self.melt is _NCAuthorityState.GRANTED

    def revoke_mint(self) -> bool:
        """Return whether the final mint state of this diff in revoked."""
        return self.mint is _NCAuthorityState.REVOKED

    def revoke_melt(self) -> bool:
        """Return whether the final melt state of this diff in revoked."""
        return self.melt is _NCAuthorityState.REVOKED


class NCChangesTracker(NCContractStorage):
    """Keep track of changes during the execution of a contract's method.

    These changes are not committed to the storage."""

    def __init__(self, nc_id: ContractId, storage: NCContractStorage):
        self.storage = storage
        self.nc_id = nc_id

        self.data: dict[AttrKey, Any] = {}
        self._balance_diff: dict[BalanceKey, int] = {}
        self._authorities_diff: dict[BalanceKey, _NCAuthorityDiff] = {}
        self._created_tokens: dict[TokenUid, TokenDescription] = {}

        self.has_been_commited = False
        self.has_been_blocked = False

    def create_token(self, token_id: TokenUid, token_name: str, token_symbol: str) -> None:
        """Create a new token in this changes tracker."""
        if self.has_token(token_id):
            raise NCTokenAlreadyExists
        self._created_tokens[token_id] = TokenDescription(
            token_id=token_id,
            token_name=token_name,
            token_symbol=token_symbol,
        )

    def has_token(self, token_id: TokenUid) -> bool:
        """Return True if a given token_id already exists."""
        if token_id in self._created_tokens:
            return True
        return self.storage.has_token(token_id)

    def get_balance_diff(self) -> MappingProxyType[BalanceKey, int]:
        """Return the balance diff of this change tracker."""
        return MappingProxyType(self._balance_diff)

    def _to_key(self, key: str) -> AttrKey:
        """Return the actual key used in the storage."""
        assert self.nc_id is not None
        return AttrKey(self.nc_id, key)

    @override
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

    @override
    def get(self, key: str, *, default: Any = _NOT_PROVIDED) -> Any:
        internal_key = self._to_key(key)
        if internal_key in self.data:
            value = self.data[internal_key]
        else:
            value = self.storage.get(key, default=default)
        if value is DeletedKey:
            raise KeyError(key)
        return value

    @override
    def put(self, key: str, value: Any) -> None:
        self.check_if_locked()
        internal_key = self._to_key(key)
        self.data[internal_key] = value

    @override
    def delete(self, key: str) -> None:
        self.check_if_locked()
        internal_key = self._to_key(key)
        self.data[internal_key] = DeletedKey

    @override
    def commit(self) -> None:
        """Save the changes in the storage."""
        self.check_if_locked()
        for (_, key), value in self.data.items():
            if value is not DeletedKey:
                self.storage.put(key, value)
            else:
                self.storage.delete(key)

        for (_, token_uid), amount in self._balance_diff.items():
            self.storage.add_balance(token_uid, amount)

        for (_, token_uid), diff in self._authorities_diff.items():
            self.storage.grant_authorities(
                token_uid,
                grant_mint=diff.grant_mint(),
                grant_melt=diff.grant_melt(),
            )
            self.storage.revoke_authorities(
                token_uid,
                revoke_mint=diff.revoke_mint(),
                revoke_melt=diff.revoke_melt(),
            )

        for td in self._created_tokens.values():
            self.storage.create_token(TokenUid(td.token_id), td.token_name, td.token_symbol)

        self.has_been_commited = True

    def reset(self) -> None:
        """Discard all local changes without persisting."""
        self.data = {}
        self._balance_diff = {}

    @override
    def get_balance(self, token_uid: bytes) -> Balance:
        internal_key = BalanceKey(self.nc_id, token_uid)
        balance = self.storage._get_mutable_balance(token_uid)
        balance_diff = self._balance_diff.get(internal_key, 0)
        authorities_diff = self._authorities_diff.get(internal_key, _NCAuthorityDiff())

        balance.value += balance_diff
        balance.grant_authorities(
            grant_mint=authorities_diff.grant_mint(),
            grant_melt=authorities_diff.grant_melt(),
        )
        balance.revoke_authorities(
            revoke_mint=authorities_diff.revoke_mint(),
            revoke_melt=authorities_diff.revoke_melt(),
        )

        return balance.to_immutable()

    def validate_balances(self) -> None:
        """Check that all final balances are positive. If not, it raises NCInsufficientFunds."""
        for _, token_uid in self._balance_diff.keys():
            balance = self.get_balance(token_uid)
            if balance.value < 0:
                raise NCInsufficientFunds(
                    f'negative balance for contract {self.nc_id.hex()} (balance={balance} token_uid={token_uid.hex()})'
                )

    @override
    def get_all_balances(self) -> dict[BalanceKey, Balance]:
        all_balance_keys: itertools.chain[BalanceKey] = itertools.chain(
            self.storage.get_all_balances().keys(),
            # There might be tokens in the change tracker that are still
            # not on storage, so we must check and add them as well
            self._balance_diff.keys(),
            self._authorities_diff.keys(),
        )

        return {key: self.get_balance(key.token_uid) for key in set(all_balance_keys)}

    @override
    def add_balance(self, token_uid: bytes, amount: int) -> None:
        self.check_if_locked()
        internal_key = BalanceKey(self.nc_id, token_uid)
        old = self._balance_diff.get(internal_key, 0)
        new = old + amount
        self._balance_diff[internal_key] = new

    @override
    def grant_authorities(self, token_uid: bytes, *, grant_mint: bool, grant_melt: bool) -> None:
        assert token_uid != HATHOR_TOKEN_UID
        self.check_if_locked()
        internal_key = BalanceKey(self.nc_id, token_uid)
        diff = self._authorities_diff.get(internal_key, _NCAuthorityDiff())
        diff.mint = _NCAuthorityState.GRANTED if grant_mint else diff.mint
        diff.melt = _NCAuthorityState.GRANTED if grant_melt else diff.melt
        self._authorities_diff[internal_key] = diff

    @override
    def revoke_authorities(self, token_uid: bytes, *, revoke_mint: bool, revoke_melt: bool) -> None:
        assert token_uid != HATHOR_TOKEN_UID
        self.check_if_locked()
        internal_key = BalanceKey(self.nc_id, token_uid)
        diff = self._authorities_diff.get(internal_key, _NCAuthorityDiff())
        diff.mint = _NCAuthorityState.REVOKED if revoke_mint else diff.mint
        diff.melt = _NCAuthorityState.REVOKED if revoke_melt else diff.melt
        self._authorities_diff[internal_key] = diff

    def is_empty(self) -> bool:
        # this method is only called in view contexts, so it's impossible for the balance to have changed.
        assert not bool(self._balance_diff)
        return not bool(self.data)

    @override
    def get_root_id(self) -> bytes:
        raise NotImplementedError
