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
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, TypeVar

from typing_extensions import override

from hathor.conf.settings import HATHOR_TOKEN_UID
from hathor.nanocontracts.exception import NCInsufficientFunds, NCTokenAlreadyExists
from hathor.nanocontracts.nc_types import NCType
from hathor.nanocontracts.storage.contract_storage import (
    AttrKey,
    Balance,
    BalanceKey,
    MutableBalance,
    NCContractStorage,
)
from hathor.nanocontracts.storage.types import _NOT_PROVIDED, DeletedKey, DeletedKeyType
from hathor.nanocontracts.types import Address, Amount, BlueprintId, ContractId, TokenUid
from hathor.transaction.token_info import TokenDescription, TokenVersion

T = TypeVar('T')
D = TypeVar('D')


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
        return self.mint == _NCAuthorityState.GRANTED

    def grant_melt(self) -> bool:
        """Return whether the final melt state of this diff in granted."""
        return self.melt == _NCAuthorityState.GRANTED

    def revoke_mint(self) -> bool:
        """Return whether the final mint state of this diff in revoked."""
        return self.mint == _NCAuthorityState.REVOKED

    def revoke_melt(self) -> bool:
        """Return whether the final melt state of this diff in revoked."""
        return self.melt == _NCAuthorityState.REVOKED


class NCChangesTracker(NCContractStorage):
    """Keep track of changes during the execution of a contract's method.

    These changes are not committed to the storage."""

    def __init__(self, nc_id: ContractId, storage: NCContractStorage):
        self.storage = storage
        self.nc_id = nc_id

        self.data: dict[AttrKey, tuple[Any, NCType | None]] = {}
        self._balance_diff: dict[BalanceKey, int] = {}
        self._authorities_diff: dict[BalanceKey, _NCAuthorityDiff] = {}
        self._created_tokens: dict[TokenUid, TokenDescription] = {}
        self._transfers: defaultdict[tuple[Address, TokenUid], int] = defaultdict(int)
        self._blueprint_id: BlueprintId | None = None

        self.has_been_commited = False
        self.has_been_blocked = False

    def create_token(
        self,
        *,
        token_id: TokenUid,
        token_name: str,
        token_symbol: str,
        token_version: TokenVersion
    ) -> None:
        """Create a new token in this changes tracker."""
        if self.has_token(token_id):
            raise NCTokenAlreadyExists
        self._created_tokens[token_id] = TokenDescription(
            token_id=token_id,
            token_name=token_name,
            token_symbol=token_symbol,
            token_version=token_version,
        )

    def has_token(self, token_id: TokenUid) -> bool:
        """Return True if a given token_id already exists."""
        if token_id in self._created_tokens:
            return True
        return self.storage.has_token(token_id)

    def get_token(self, token_id: TokenUid) -> TokenDescription:
        """Get token description for a given token ID."""
        token_description = self._created_tokens.get(token_id)
        if token_description is not None:
            return token_description
        return self.storage.get_token(token_id)

    def add_address_balance(
        self,
        address: Address,
        amount: Amount,
        token_id: TokenUid,
    ) -> None:
        assert amount >= 0
        self._transfers[(address, token_id)] += amount

    def get_balance_diff(self) -> MappingProxyType[BalanceKey, int]:
        """Return the balance diff of this change tracker."""
        return MappingProxyType(self._balance_diff)

    @override
    def check_if_locked(self) -> None:
        if self.has_been_commited:
            raise RuntimeError('you cannot change any value after the commit has been executed')
        elif self.has_been_blocked:
            raise RuntimeError('you cannot change any value after the changes have been blocked')

    def block(self) -> None:
        """Block the changes and prevent them from being committed."""
        self.check_if_locked()
        self.has_been_blocked = True

    @override
    def get_obj(self, key: bytes, nc_type: NCType[T], *, default: D = _NOT_PROVIDED) -> T | D:
        obj_key = self._to_attr_key(key)
        obj: T | D | DeletedKeyType
        if obj_key in self.data:
            obj, _ = self.data[obj_key]
        else:
            # XXX: extra variable used so mypy can infer the correct type
            obj_td = self.storage.get_obj(key, nc_type, default=default)
            obj = obj_td
        if obj is DeletedKey:
            if default is not _NOT_PROVIDED:
                return default
            raise KeyError(key)
        assert not isinstance(obj, DeletedKeyType)
        assert obj is not _NOT_PROVIDED
        return obj

    @override
    def put_obj(self, key: bytes, nc_type: NCType[T], data: T) -> None:
        self.check_if_locked()
        nc_type.check_value(data)
        obj_key = self._to_attr_key(key)
        self.data[obj_key] = (data, nc_type)

    @override
    def del_obj(self, key: bytes) -> None:
        self.check_if_locked()
        obj_key = self._to_attr_key(key)
        self.data[obj_key] = (DeletedKey, None)

    @override
    def has_obj(self, key: bytes) -> bool:
        obj_key = self._to_attr_key(key)
        if obj_key in self.data:
            obj, _ = self.data[obj_key]
            return obj is not DeletedKey
        else:
            return self.storage.has_obj(key)

    @override
    def commit(self) -> None:
        """Save the changes in the storage."""
        self.check_if_locked()
        for attr_key, (obj, nc_type) in self.data.items():
            if obj is not DeletedKey:
                assert nc_type is not None
                assert not isinstance(obj, DeletedKeyType)
                self.storage.put_obj(attr_key.key, nc_type, obj)
            else:
                self.storage.del_obj(attr_key.key)

        for balance_key, amount in self._balance_diff.items():
            self.storage.add_balance(balance_key.token_uid, amount)

        for balance_key, diff in self._authorities_diff.items():
            self.storage.grant_authorities(
                balance_key.token_uid,
                grant_mint=diff.grant_mint(),
                grant_melt=diff.grant_melt(),
            )
            self.storage.revoke_authorities(
                balance_key.token_uid,
                revoke_mint=diff.revoke_mint(),
                revoke_melt=diff.revoke_melt(),
            )

        for td in self._created_tokens.values():
            self.storage.create_token(
                token_id=TokenUid(td.token_id),
                token_name=td.token_name,
                token_symbol=td.token_symbol,
                token_version=TokenVersion(td.token_version)
            )

        for (address, token_id), amount in self._transfers.items():
            self.storage.add_address_balance(address, Amount(amount), token_id)

        if self._blueprint_id is not None:
            self.storage.set_blueprint_id(self._blueprint_id)

        self.has_been_commited = True

    @override
    def _get_mutable_balance(self, token_uid: bytes) -> MutableBalance:
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

        return balance

    def validate_balances_are_positive(self) -> None:
        """Check that all final balances are positive. If not, it raises NCInsufficientFunds."""
        for balance_key in self._balance_diff.keys():
            balance = self.get_balance(balance_key.token_uid)
            if balance.value < 0:
                raise NCInsufficientFunds(
                    f'negative balance for contract {self.nc_id.hex()} '
                    f'(balance={balance} token_uid={balance_key.token_uid.hex()})'
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
        assert not bool(self._authorities_diff)
        assert not bool(self._created_tokens)
        assert not bool(self._blueprint_id)
        return not bool(self.data)

    @override
    def get_root_id(self) -> bytes:
        raise NotImplementedError

    def get_blueprint_id(self) -> BlueprintId:
        if self._blueprint_id is not None:
            return self._blueprint_id
        return self.storage.get_blueprint_id()

    def set_blueprint_id(self, value: BlueprintId) -> None:
        """Set a new blueprint id for the contract."""
        self.check_if_locked()
        self._blueprint_id = value
