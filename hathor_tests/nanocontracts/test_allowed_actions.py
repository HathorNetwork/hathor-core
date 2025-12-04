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

import re

import pytest

from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.exception import BlueprintSyntaxError, NCForbiddenAction
from hathor.nanocontracts.types import (
    NCAcquireAuthorityAction,
    NCAction,
    NCActionType,
    NCArgs,
    NCDepositAction,
    NCGrantAuthorityAction,
    NCWithdrawalAction,
    fallback,
)
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class MyBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def nop(self, ctx: Context) -> None:
        pass

    @public(allow_deposit=True)
    def deposit(self, ctx: Context) -> None:
        pass

    @public(allow_withdrawal=True)
    def withdrawal(self, ctx: Context) -> None:
        pass

    @public(allow_grant_authority=True)
    def grant_authority(self, ctx: Context) -> None:
        pass

    @public(allow_acquire_authority=True)
    def acquire_authority(self, ctx: Context) -> None:
        pass

    @fallback
    def fallback(self, ctx: Context, method_name: str, nc_args: NCArgs) -> None:
        pass


class TestAllowedActions(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.blueprint_id = self._register_blueprint_class(MyBlueprint)
        self.contract_id = self.gen_random_contract_id()

        self.token_a = self.gen_random_token_uid()
        self.address = self.gen_random_address()
        self.tx = self.get_genesis_tx()

        self.all_actions: set[NCAction] = {
            NCDepositAction(token_uid=self.token_a, amount=123),
            NCWithdrawalAction(token_uid=self.token_a, amount=123),
            NCGrantAuthorityAction(token_uid=self.token_a, mint=True, melt=True),
            NCAcquireAuthorityAction(token_uid=self.token_a, mint=True, melt=True),
        }

        all_actions_types = [action.type for action in self.all_actions]
        for action_type in NCActionType:
            # To make sure we remember to test new action types when we implement them
            assert action_type in all_actions_types, f'missing {action_type.name}'

    def _get_context(self, *actions: NCAction) -> Context:
        return self.create_context(
            actions=list(actions),
            vertex=self.tx,
            caller_id=self.address,
            timestamp=self.now,
        )

    def test_no_actions_allowed(self) -> None:
        self.runner.create_contract(self.contract_id, self.blueprint_id, self._get_context())
        for action in self.all_actions:
            ctx = self._get_context(action)

            # Test on public method
            with pytest.raises(NCForbiddenAction, match=f'action {action.name} is forbidden on method `nop`'):
                self.runner.call_public_method(self.contract_id, 'nop', ctx)

            # Test on fallback method
            with pytest.raises(NCForbiddenAction, match=f'action {action.name} is forbidden on method `fallback`'):
                self.runner.call_public_method(self.contract_id, 'unknown', ctx)

    def test_conflicting_params(self) -> None:
        msg = 'use only one of `allow_actions` or per-action flags: `initialize()`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class InvalidBlueprint(Blueprint):
                @public(allow_deposit=True, allow_actions=[NCActionType.DEPOSIT])
                def initialize(self, ctx: Context) -> None:
                    pass

    def test_allow_specific_action_on_public(self) -> None:
        for allowed_action in self.all_actions:
            runner = self.build_runner()
            runner.create_contract(self.contract_id, self.blueprint_id, self._get_context())
            method_name = allowed_action.name.lower()
            forbidden_actions = self.all_actions.difference({allowed_action})

            for forbidden_action in forbidden_actions:
                msg = f'action {forbidden_action.name} is forbidden on method `{method_name}`'
                ctx = self._get_context(forbidden_action)
                with pytest.raises(NCForbiddenAction, match=msg):
                    runner.call_public_method(self.contract_id, method_name, ctx)

    def test_allow_specific_action_on_fallback(self) -> None:
        for allowed_action in self.all_actions:
            class MyOtherBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @fallback(allow_actions=[allowed_action.type])
                def fallback(self, ctx: Context, method_name: str, nc_args: NCArgs) -> None:
                    pass

            runner = self.build_runner()
            blueprint_id = self._register_blueprint_class(MyOtherBlueprint)
            runner.create_contract(self.contract_id, blueprint_id, self._get_context())
            method_name = allowed_action.name.lower()
            forbidden_actions = self.all_actions.difference({allowed_action})

            for forbidden_action in forbidden_actions:
                msg = f'action {forbidden_action.name} is forbidden on method `fallback`'
                ctx = self._get_context(forbidden_action)
                with pytest.raises(NCForbiddenAction, match=msg):
                    runner.call_public_method(self.contract_id, method_name, ctx)
