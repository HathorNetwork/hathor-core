# Copyright 2025 Hathor Labs
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

from hathor import (
    HATHOR_TOKEN_UID,
    Amount,
    Blueprint,
    Context,
    ContractId,
    NCDepositAction,
    NCWithdrawalAction,
    public,
)
from hathor.nanocontracts.utils import derive_child_token_id
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class TokenCreatorBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public(allow_deposit=True, allow_withdrawal=True)
    def create_and_withdraw_token(self, ctx: Context, amount: Amount) -> None:
        self.syscall.create_deposit_token(
            token_name='deposit-based token',
            token_symbol='DBT',
            amount=amount,
        )


class WithdrawFromCreatorBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public(allow_deposit=True, allow_withdrawal=True)
    def create_token_in_another_contract(self, ctx: Context, creator_id: ContractId) -> None:
        creator = self.syscall.get_contract(creator_id, blueprint_id=None)
        creator.public(*ctx.actions_list).create_and_withdraw_token(1000)


class TokenCreation3TestCase(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.creator_blueprint_id = self._register_blueprint_class(TokenCreatorBlueprint)
        self.withdraw_blueprint_id = self._register_blueprint_class(WithdrawFromCreatorBlueprint)

        self.creator_nc_id = self.gen_random_contract_id()
        self.withdraw_nc_id = self.gen_random_contract_id()

    def test_withdraw_token_created_on_same_call(self) -> None:
        """Test withdrawing a token created in the same transaction to a regular tx output."""
        ctx = self.create_context()
        self.runner.create_contract(self.creator_nc_id, self.creator_blueprint_id, ctx)

        token_uid = derive_child_token_id(self.creator_nc_id, 'DBT')

        ctx = self.create_context(actions=[
            NCDepositAction(amount=10, token_uid=HATHOR_TOKEN_UID),
            NCWithdrawalAction(amount=100, token_uid=token_uid)
        ])
        self.runner.call_public_method(self.creator_nc_id, 'create_and_withdraw_token', ctx, 1000)

    def test_withdraw_token_created_on_same_call_from_another_contract(self) -> None:
        """Test withdrawing a token created in the same call from one contract to another contract."""
        ctx = self.create_context()
        self.runner.create_contract(self.creator_nc_id, self.creator_blueprint_id, ctx)

        ctx = self.create_context()
        self.runner.create_contract(self.withdraw_nc_id, self.withdraw_blueprint_id, ctx)

        token_uid = derive_child_token_id(self.creator_nc_id, 'DBT')

        ctx = self.create_context(actions=[
            NCDepositAction(amount=10, token_uid=HATHOR_TOKEN_UID),
            NCWithdrawalAction(amount=100, token_uid=token_uid),
        ])
        self.runner.call_public_method(
            self.withdraw_nc_id,
            'create_token_in_another_contract',
            ctx,
            self.creator_nc_id
        )
