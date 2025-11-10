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

from hathor.nanocontracts import HATHOR_TOKEN_UID, Blueprint, Context, public
from hathor.nanocontracts.types import (
    ContractId,
    NCAction,
    NCDepositAction,
    NCGrantAuthorityAction,
    NCWithdrawalAction,
    TokenUid,
)
from hathor.transaction.token_info import TokenVersion
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class MyBlueprint(Blueprint):
    token_uid: TokenUid

    @public(allow_deposit=True)
    def initialize(self, ctx: Context, token_uid: TokenUid) -> None:
        self.token_uid = token_uid

    def assert_balance(self, token_uid: TokenUid, *, before: int, current: int) -> None:
        assert self.syscall.get_balance_before_current_call(token_uid) == before
        assert self.syscall.get_current_balance(token_uid) == current

    def assert_token_balance(self, *, before: int, current: int) -> None:
        self.assert_balance(self.token_uid, before=before, current=current)

    def assert_htr_balance(self, *, before: int, current: int) -> None:
        self.assert_balance(TokenUid(HATHOR_TOKEN_UID), before=before, current=current)

    @public(allow_deposit=True)
    def deposit(self, ctx: Context) -> None:
        self.assert_htr_balance(before=10, current=10)
        self.assert_token_balance(before=0, current=10)

    @public(allow_withdrawal=True)
    def withdrawal(self, ctx: Context) -> None:
        self.assert_htr_balance(before=10, current=10)
        self.assert_token_balance(before=10, current=7)

    @public(allow_grant_authority=True)
    def mint(self, ctx: Context) -> None:
        self.assert_htr_balance(before=10, current=10)
        self.assert_token_balance(before=0, current=0)
        self.syscall.mint_tokens(self.token_uid, amount=300)
        self.assert_htr_balance(before=10, current=7)
        self.assert_token_balance(before=0, current=300)

        assert not self.syscall.can_mint_before_current_call(self.token_uid)
        assert self.syscall.can_mint(self.token_uid)
        self.syscall.revoke_authorities(self.token_uid, revoke_mint=True, revoke_melt=False)
        assert not self.syscall.can_mint_before_current_call(self.token_uid)
        assert not self.syscall.can_mint(self.token_uid)

    @public(allow_grant_authority=True)
    def melt(self, ctx: Context) -> None:
        self.assert_htr_balance(before=7, current=7)
        self.assert_token_balance(before=300, current=300)
        self.syscall.melt_tokens(self.token_uid, amount=200)
        self.assert_htr_balance(before=7, current=9)
        self.assert_token_balance(before=300, current=100)

        assert not self.syscall.can_melt_before_current_call(self.token_uid)
        assert self.syscall.can_melt(self.token_uid)
        self.syscall.revoke_authorities(self.token_uid, revoke_mint=False, revoke_melt=True)
        assert not self.syscall.can_melt_before_current_call(self.token_uid)
        assert not self.syscall.can_melt(self.token_uid)

    @public(allow_deposit=True)
    def deposit_into_another(self, ctx: Context, contract_id: ContractId) -> None:
        self.assert_token_balance(before=0, current=10)
        action = NCDepositAction(token_uid=self.token_uid, amount=7)
        self.syscall \
            .get_contract(contract_id, blueprint_id=None) \
            .public(action) \
            .accept_deposit_from_another(self.syscall.get_contract_id())
        self.assert_token_balance(before=0, current=6)

    @public(allow_deposit=True)
    def accept_deposit_from_another(self, ctx: Context, contract_id: ContractId) -> None:
        self.assert_token_balance(before=0, current=7)
        action = NCDepositAction(token_uid=self.token_uid, amount=3)
        self.syscall.get_contract(contract_id, blueprint_id=None).public(action).accept_deposit_from_another_callback()
        self.assert_token_balance(before=0, current=4)

    @public(allow_deposit=True, allow_reentrancy=True)
    def accept_deposit_from_another_callback(self, ctx: Context) -> None:
        self.assert_token_balance(before=3, current=6)

    @public(allow_withdrawal=True)
    def withdraw_from_another(self, ctx: Context, contract_id: ContractId) -> None:
        self.assert_token_balance(before=6, current=5)
        action = NCWithdrawalAction(token_uid=self.token_uid, amount=2)
        self.syscall.get_contract(contract_id, blueprint_id=None).public(action).accept_withdrawal_from_another(
            self.syscall.get_contract_id()
        )
        self.assert_token_balance(before=6, current=6)

    @public(allow_withdrawal=True)
    def accept_withdrawal_from_another(self, ctx: Context, contract_id: ContractId) -> None:
        self.assert_token_balance(before=4, current=2)
        action = NCWithdrawalAction(token_uid=self.token_uid, amount=1)
        self.syscall.get_contract(contract_id, blueprint_id=None) \
            .public(action) \
            .accept_withdrawal_from_another_callback()
        self.assert_token_balance(before=4, current=3)

    @public(allow_withdrawal=True, allow_reentrancy=True)
    def accept_withdrawal_from_another_callback(self, ctx: Context) -> None:
        self.assert_token_balance(before=7, current=6)


class TestExecutionOrder(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.blueprint_id = self._register_blueprint_class(MyBlueprint)
        self.contract_id1 = self.gen_random_contract_id()
        self.contract_id2 = self.gen_random_contract_id()
        self.token_a = self.gen_random_token_uid()
        self.tx = self.get_genesis_tx()
        self.address = self.gen_random_address()

        action = NCDepositAction(token_uid=TokenUid(HATHOR_TOKEN_UID), amount=10)
        self.runner.create_contract(self.contract_id1, self.blueprint_id, self._get_context(action), self.token_a)
        self.runner.create_contract(self.contract_id2, self.blueprint_id, self._get_context(action), self.token_a)

        self.create_token(
            token_uid=self.token_a,
            token_name='TKA',
            token_symbol='TKA',
            token_version=TokenVersion.DEPOSIT,
        )

    def _get_context(self, *actions: NCAction) -> Context:
        return self.create_context(
            actions=list(actions),
            vertex=self.tx,
            caller_id=self.address,
            timestamp=self.now,
        )

    def test_deposit_and_withdrawal(self) -> None:
        action: NCAction = NCDepositAction(token_uid=self.token_a, amount=10)
        self.runner.call_public_method(self.contract_id1, 'deposit', self._get_context(action))

        action = NCWithdrawalAction(token_uid=self.token_a, amount=3)
        self.runner.call_public_method(self.contract_id1, 'withdrawal', self._get_context(action))

    def test_mint_and_melt(self) -> None:
        action: NCAction = NCGrantAuthorityAction(token_uid=self.token_a, mint=True, melt=False)
        self.runner.call_public_method(self.contract_id1, 'mint', self._get_context(action))

        action = NCGrantAuthorityAction(token_uid=self.token_a, mint=False, melt=True)
        self.runner.call_public_method(self.contract_id1, 'melt', self._get_context(action))

    def test_deposit_and_withdrawal_across_contracts(self) -> None:
        action: NCAction = NCDepositAction(token_uid=self.token_a, amount=10)
        self.runner.call_public_method(
            self.contract_id1, 'deposit_into_another', self._get_context(action), self.contract_id2
        )

        action = NCWithdrawalAction(token_uid=self.token_a, amount=1)
        self.runner.call_public_method(
            self.contract_id1, 'withdraw_from_another', self._get_context(action), self.contract_id2
        )
