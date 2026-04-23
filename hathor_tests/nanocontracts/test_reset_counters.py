#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import pytest

from hathor import HATHOR_TOKEN_UID, Blueprint, Context, public
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from hathorlib.nanocontracts.exception import NCFail
from hathorlib.nanocontracts.types import ContractId, NCDepositAction


class MyBlueprint(Blueprint):
    @public(allow_deposit=True)
    def initialize(self, ctx: Context) -> None:
        for action in ctx.all_actions:
            ctx.authorize(action)

    @public
    def create_token(self, ctx: Context, fail: bool) -> None:
        self.syscall.create_deposit_token(token_name='TokenA', token_symbol='TKA', amount=100)
        if fail:
            raise NCFail('fail!')

    @public
    def call_another_create_token(self, ctx: Context, contract_id: ContractId, fail: bool) -> None:
        contract = self.syscall.get_contract(contract_id, blueprint_id=self.syscall.get_blueprint_id())
        contract.public().create_token(fail=fail)

    @public
    def nop(self, ctx: Context) -> None:
        pass


class TestResetCounters(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.blueprint_id = self._register_blueprint_class(MyBlueprint)
        self.contract_id1 = self.gen_random_contract_id()
        self.contract_id2 = self.gen_random_contract_id()

        ctx = self.create_context(actions=[NCDepositAction(token_uid=HATHOR_TOKEN_UID, amount=100)])
        self.runner.create_contract(self.contract_id1, self.blueprint_id, ctx)
        self.runner.create_contract(self.contract_id2, self.blueprint_id, ctx)

    def test_reset_counters_after_success(self) -> None:
        ctx = self.create_context()
        self.runner.call_public_method(
            self.contract_id1, 'call_another_create_token', ctx, self.contract_id2, fail=False
        )
        self.runner.call_public_method(self.contract_id1, 'nop', ctx)

    def test_reset_counters_after_failure(self) -> None:
        ctx = self.create_context()
        with pytest.raises(NCFail, match='fail!'):
            self.runner.call_public_method(
                self.contract_id1, 'call_another_create_token', ctx, self.contract_id2, fail=True
            )
        self.runner.call_public_method(self.contract_id1, 'nop', ctx)
