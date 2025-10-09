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

from hathor import Blueprint, Context, ContractId, NCFail, TokenUid, public
from tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class MyBlueprint(Blueprint):
    token_uid: TokenUid

    @public
    def initialize(self, ctx: Context, token_uid: TokenUid) -> None:
        self.token_uid = token_uid

    @public
    def test_balance_syscalls_on_self(self, ctx: Context) -> None:
        self.syscall.get_current_balance()
        self.syscall.get_balance_before_current_call()

        self.syscall.can_mint(self.token_uid)
        self.syscall.can_mint_before_current_call(self.token_uid)

        self.syscall.can_melt(self.token_uid)
        self.syscall.can_melt_before_current_call(self.token_uid)

    @public
    def test_current_balance_syscalls_on_another(self, ctx: Context, other_id: ContractId) -> None:
        self.syscall.get_current_balance(contract_id=other_id)
        self.syscall.can_mint(self.token_uid, contract_id=other_id)
        self.syscall.can_melt(self.token_uid, contract_id=other_id)

    @public
    def test_get_balance_before_current_call_on_another(self, ctx: Context, other_id: ContractId) -> None:
        self.syscall.get_balance_before_current_call(contract_id=other_id)

    @public
    def test_can_mint_before_current_call_on_another(self, ctx: Context, other_id: ContractId) -> None:
        self.syscall.can_mint_before_current_call(self.token_uid, contract_id=other_id)

    @public
    def test_can_melt_before_current_call_on_another(self, ctx: Context, other_id: ContractId) -> None:
        self.syscall.can_melt_before_current_call(self.token_uid, contract_id=other_id)


class BalanceSyscallsTestCase(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.blueprint_id = self._register_blueprint_class(MyBlueprint)
        self.contract_id1 = self.gen_random_contract_id()
        self.contract_id2 = self.gen_random_contract_id()

        token_uid = self.gen_random_token_uid()
        self.runner.create_contract(self.contract_id1, self.blueprint_id, self.create_context(), token_uid)
        self.runner.create_contract(self.contract_id2, self.blueprint_id, self.create_context(), token_uid)

    def test_balance_syscalls_on_self(self) -> None:
        self.runner.call_public_method(self.contract_id1, 'test_balance_syscalls_on_self', self.create_context())

    def test_current_balance_syscalls_on_another(self) -> None:
        self.runner.call_public_method(
            self.contract_id1,
            'test_current_balance_syscalls_on_another',
            self.create_context(),
            self.contract_id2,
        )

    def test_get_balance_before_current_call_on_another(self) -> None:
        msg = 'getting the balance of another contract before the current call is not supported.'
        with pytest.raises(NCFail, match=msg):
            self.runner.call_public_method(
                self.contract_id1,
                'test_get_balance_before_current_call_on_another',
                self.create_context(),
                self.contract_id2,
            )

    def test_can_mint_before_current_call_on_another(self) -> None:
        msg = 'getting the balance of another contract before the current call is not supported.'
        with pytest.raises(NCFail, match=msg):
            self.runner.call_public_method(
                self.contract_id1,
                'test_can_mint_before_current_call_on_another',
                self.create_context(),
                self.contract_id2,
            )

    def test_can_melt_before_current_call_on_another(self) -> None:
        msg = 'getting the balance of another contract before the current call is not supported.'
        with pytest.raises(NCFail, match=msg):
            self.runner.call_public_method(
                self.contract_id1,
                'test_can_melt_before_current_call_on_another',
                self.create_context(),
                self.contract_id2,
            )
