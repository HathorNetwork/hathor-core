#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import pytest

from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.exception import NCInvalidAction
from hathor.nanocontracts.storage.contract_storage import Balance
from hathor.nanocontracts.types import ContractId, NCAcquireAuthorityAction, NCAction, NCGrantAuthorityAction, TokenUid
from hathor.transaction.token_info import TokenVersion
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class CalleeBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public(allow_grant_authority=True, allow_acquire_authority=True)
    def nop(self, ctx: Context) -> None:
        pass

    @public
    def revoke_from_self(self, ctx: Context, token_uid: TokenUid, mint: bool, melt: bool) -> None:
        self.syscall.revoke_authorities(token_uid, revoke_mint=mint, revoke_melt=melt)

    @public
    def grant_all_to_other(self, ctx: Context, contract_id: ContractId, token_uid: TokenUid) -> None:
        action = NCGrantAuthorityAction(token_uid=token_uid, mint=True, melt=True)
        self.syscall.get_contract(contract_id, blueprint_id=None).public(action).nop()

    @public
    def revoke_all_from_other(self, ctx: Context, contract_id: ContractId, token_uid: TokenUid) -> None:
        self.syscall.get_contract(contract_id, blueprint_id=None).public().revoke_from_self(token_uid, True, True)


class CallerBlueprint(Blueprint):
    other_id: ContractId

    @public(allow_grant_authority=True)
    def initialize(self, ctx: Context, other_id: ContractId) -> None:
        self.other_id = other_id

    @public(allow_grant_authority=True, allow_reentrancy=True)
    def nop(self, ctx: Context) -> None:
        pass

    @public
    def grant_to_other(self, ctx: Context, token_uid: TokenUid, mint: bool, melt: bool) -> None:
        action = NCGrantAuthorityAction(token_uid=token_uid, mint=mint, melt=melt)
        self.syscall.get_contract(self.other_id, blueprint_id=None).public(action).nop()

    @public(allow_grant_authority=True, allow_reentrancy=True)
    def revoke_from_self(self, ctx: Context, token_uid: TokenUid, mint: bool, melt: bool) -> None:
        self.syscall.revoke_authorities(token_uid, revoke_mint=mint, revoke_melt=melt)

    @public
    def revoke_from_other(self, ctx: Context, token_uid: TokenUid, mint: bool, melt: bool) -> None:
        self.syscall.get_contract(self.other_id, blueprint_id=None).public().revoke_from_self(token_uid, mint, melt)

    @public
    def acquire_another(self, ctx: Context, token_uid: TokenUid, mint: bool, melt: bool) -> None:
        action = NCAcquireAuthorityAction(token_uid=token_uid, mint=mint, melt=melt)
        self.syscall.get_contract(self.other_id, blueprint_id=None).public(action).nop()

    @public
    def call_grant_all_to_other_then_revoke(self, ctx: Context, token_uid: TokenUid) -> None:
        self.syscall.revoke_authorities(token_uid, revoke_mint=True, revoke_melt=True)
        assert not self.syscall.can_mint(token_uid)
        assert not self.syscall.can_melt(token_uid)
        self.syscall.get_contract(self.other_id, blueprint_id=None).public().grant_all_to_other(
            contract_id=self.syscall.get_contract_id(),
            token_uid=token_uid,
        )
        assert self.syscall.can_mint(token_uid)
        assert self.syscall.can_melt(token_uid)
        self.syscall.revoke_authorities(token_uid, revoke_mint=True, revoke_melt=True)
        assert not self.syscall.can_mint(token_uid)
        assert not self.syscall.can_melt(token_uid)

    @public(allow_grant_authority=True)
    def call_revoke_all_from_other(self, ctx: Context, token_uid: TokenUid) -> None:
        assert self.syscall.can_mint(token_uid)
        assert self.syscall.can_melt(token_uid)
        self.syscall.get_contract(self.other_id, blueprint_id=None).public().revoke_all_from_other(
            contract_id=self.syscall.get_contract_id(),
            token_uid=token_uid,
        )
        assert not self.syscall.can_mint_before_current_call(token_uid)
        assert not self.syscall.can_melt_before_current_call(token_uid)


class TestAuthoritiesCallAnother(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.callee_blueprint_id = self.gen_random_blueprint_id()
        self.caller_blueprint_id = self.gen_random_blueprint_id()

        self.nc_catalog.blueprints[self.callee_blueprint_id] = CalleeBlueprint
        self.nc_catalog.blueprints[self.caller_blueprint_id] = CallerBlueprint

        self.callee_id = self.gen_random_contract_id()
        self.caller_id = self.gen_random_contract_id()

        self.token_a = self.gen_random_token_uid()
        self.address = self.gen_random_address()
        self.tx = self.get_genesis_tx()

    def _initialize(self, caller_actions: list[NCAction] | None = None) -> None:
        caller_ctx = self.create_context(
            actions=caller_actions or [],
            vertex=self.tx,
            caller_id=self.address,
            timestamp=self.now
        )
        callee_ctx = self.create_context(
            actions=[],
            vertex=self.tx,
            caller_id=self.address,
            timestamp=self.now
        )
        self.runner.create_contract(self.caller_id, self.caller_blueprint_id, caller_ctx, other_id=self.callee_id)
        self.runner.create_contract(self.callee_id, self.callee_blueprint_id, callee_ctx)
        self.caller_storage = self.runner.get_storage(self.caller_id)
        self.callee_storage = self.runner.get_storage(self.callee_id)

        self.caller_storage.create_token(
            token_id=self.token_a,
            token_name='TKA',
            token_symbol='TKA',
            token_version=TokenVersion.DEPOSIT
        )

    def _grant_to_other(self, *, mint: bool, melt: bool) -> None:
        context = self.create_context(
            actions=[],
            vertex=self.tx,
            caller_id=self.address,
            timestamp=self.now
        )
        self.runner.call_public_method(
            self.caller_id, 'grant_to_other', context, token_uid=self.token_a, mint=mint, melt=melt
        )

    def _revoke_from_self(self, contract_id: ContractId, *, actions: list[NCAction], mint: bool, melt: bool) -> None:
        context = self.create_context(
            actions=actions,
            vertex=self.tx,
            caller_id=self.address,
            timestamp=self.now
        )
        self.runner.call_public_method(
            contract_id, 'revoke_from_self', context, token_uid=self.token_a, mint=mint, melt=melt
        )

    def _revoke_from_other(self, *, mint: bool, melt: bool) -> None:
        context = self.create_context(
            actions=[],
            vertex=self.tx,
            caller_id=self.address,
            timestamp=self.now
        )
        self.runner.call_public_method(
            self.caller_id, 'revoke_from_other', context, token_uid=self.token_a, mint=mint, melt=melt
        )

    def test_grant_mint_success(self) -> None:
        self._initialize(caller_actions=[NCGrantAuthorityAction(token_uid=self.token_a, mint=True, melt=False)])
        assert self.callee_storage.get_balance(self.token_a) == Balance(value=0, can_mint=False, can_melt=False)
        self._grant_to_other(mint=True, melt=False)
        assert self.callee_storage.get_balance(self.token_a) == Balance(value=0, can_mint=True, can_melt=False)

    def test_revoke_mint_success(self) -> None:
        self.test_grant_mint_success()
        assert self.callee_storage.get_balance(self.token_a) == Balance(value=0, can_mint=True, can_melt=False)
        self._revoke_from_other(mint=True, melt=False)
        assert self.callee_storage.get_balance(self.token_a) == Balance(value=0, can_mint=False, can_melt=False)

    def test_grant_mint_fail(self) -> None:
        self._initialize()
        assert self.callee_storage.get_balance(self.token_a) == Balance(value=0, can_mint=False, can_melt=False)
        msg = f'GRANT_AUTHORITY token {self.token_a.hex()} requires mint, but contract does not have that authority'
        with pytest.raises(NCInvalidAction, match=msg):
            self._grant_to_other(mint=True, melt=False)
        assert self.callee_storage.get_balance(self.token_a) == Balance(value=0, can_mint=False, can_melt=False)

    def test_grant_melt_success(self) -> None:
        self._initialize(caller_actions=[NCGrantAuthorityAction(token_uid=self.token_a, mint=False, melt=True)])
        assert self.callee_storage.get_balance(self.token_a) == Balance(value=0, can_mint=False, can_melt=False)
        self._grant_to_other(mint=False, melt=True)
        assert self.callee_storage.get_balance(self.token_a) == Balance(value=0, can_mint=False, can_melt=True)

    def test_revoke_melt_success(self) -> None:
        self.test_grant_melt_success()
        assert self.callee_storage.get_balance(self.token_a) == Balance(value=0, can_mint=False, can_melt=True)
        self._revoke_from_other(mint=False, melt=True)
        assert self.callee_storage.get_balance(self.token_a) == Balance(value=0, can_mint=False, can_melt=False)

    def test_grant_melt_fail(self) -> None:
        self._initialize()
        assert self.callee_storage.get_balance(self.token_a) == Balance(value=0, can_mint=False, can_melt=False)
        msg = f'GRANT_AUTHORITY token {self.token_a.hex()} requires melt, but contract does not have that authority'
        with pytest.raises(NCInvalidAction, match=msg):
            self._grant_to_other(mint=False, melt=True)
        assert self.callee_storage.get_balance(self.token_a) == Balance(value=0, can_mint=False, can_melt=False)

    def test_acquire_mint(self) -> None:
        self._initialize()
        context = self.create_context(
            actions=[NCGrantAuthorityAction(token_uid=self.token_a, mint=True, melt=False)],
            vertex=self.tx,
            caller_id=self.address,
            timestamp=self.now
        )
        self.runner.call_public_method(self.callee_id, 'nop', context)
        assert self.callee_storage.get_balance(self.token_a) == Balance(value=0, can_mint=True, can_melt=False)
        assert self.caller_storage.get_balance(self.token_a) == Balance(value=0, can_mint=False, can_melt=False)

        context = self.create_context(
            actions=[],
            vertex=self.tx,
            caller_id=self.address,
            timestamp=self.now
        )
        self.runner.call_public_method(
            self.caller_id, 'acquire_another', context, token_uid=self.token_a, mint=True, melt=False
        )

        assert self.callee_storage.get_balance(self.token_a) == Balance(value=0, can_mint=True, can_melt=False)
        assert self.caller_storage.get_balance(self.token_a) == Balance(value=0, can_mint=True, can_melt=False)

    def test_acquire_melt(self) -> None:
        self._initialize()
        context = self.create_context(
            actions=[NCGrantAuthorityAction(token_uid=self.token_a, mint=False, melt=True)],
            vertex=self.tx,
            caller_id=self.address,
            timestamp=self.now
        )
        self.runner.call_public_method(self.callee_id, 'nop', context)
        assert self.callee_storage.get_balance(self.token_a) == Balance(value=0, can_mint=False, can_melt=True)
        assert self.caller_storage.get_balance(self.token_a) == Balance(value=0, can_mint=False, can_melt=False)

        context = self.create_context(
            actions=[],
            vertex=self.tx,
            caller_id=self.address,
            timestamp=self.now
        )
        self.runner.call_public_method(
            self.caller_id, 'acquire_another', context, token_uid=self.token_a, mint=False, melt=True
        )

        assert self.callee_storage.get_balance(self.token_a) == Balance(value=0, can_mint=False, can_melt=True)
        assert self.caller_storage.get_balance(self.token_a) == Balance(value=0, can_mint=False, can_melt=True)

    def test_grant_and_revoke_single_contract(self) -> None:
        self._initialize()
        assert self.caller_storage.get_balance(self.token_a) == Balance(value=0, can_mint=False, can_melt=False)
        self._revoke_from_self(
            self.caller_id,
            actions=[NCGrantAuthorityAction(token_uid=self.token_a, mint=True, melt=True)],
            mint=True,
            melt=True,
        )
        # actions run before the method, so the final result is revoked.
        assert self.caller_storage.get_balance(self.token_a) == Balance(value=0, can_mint=False, can_melt=False)

    def test_revoke_then_grant_same_call_another_contract(self) -> None:
        self._initialize(caller_actions=[NCGrantAuthorityAction(token_uid=self.token_a, mint=True, melt=True)])
        self._grant_to_other(mint=True, melt=True)
        assert self.caller_storage.get_balance(self.token_a) == Balance(value=0, can_mint=True, can_melt=True)
        assert self.callee_storage.get_balance(self.token_a) == Balance(value=0, can_mint=True, can_melt=True)
        context = self.create_context(
            actions=[],
            vertex=self.tx,
            caller_id=self.address,
            timestamp=self.now
        )
        self.runner.call_public_method(self.caller_id, 'call_grant_all_to_other_then_revoke', context, self.token_a)
        # the main call calls the revoke syscall last, so the final result is revoked.
        assert self.caller_storage.get_balance(self.token_a) == Balance(value=0, can_mint=False, can_melt=False)

    def test_grant_then_revoke_same_call_another_contract(self) -> None:
        self._initialize()
        context = self.create_context(
            actions=[NCGrantAuthorityAction(token_uid=self.token_a, mint=True, melt=True)],
            vertex=self.tx,
            caller_id=self.address,
            timestamp=self.now
        )
        self.runner.call_public_method(self.caller_id, 'call_revoke_all_from_other', context, self.token_a)
        # actions run before the method, so the final result is revoked.
        assert self.caller_storage.get_balance(self.token_a) == Balance(value=0, can_mint=False, can_melt=False)
