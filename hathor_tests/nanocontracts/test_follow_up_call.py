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

from hathor.nanocontracts import Blueprint, Context, NCFail, public, view
from hathor.nanocontracts.types import ContractId
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class MyBlueprint1(Blueprint):
    other_id: ContractId

    @public
    def initialize(self, ctx: Context, other_id: ContractId) -> None:
        self.other_id = other_id

    @public
    def public_nop(self, ctx: Context) -> None:
        pass

    @view
    def view_call_other_view(self, method_name: str) -> None:
        self.syscall.get_contract(self.other_id, blueprint_id=None) \
            .get_view_method(method_name) \
            .call()

    @public
    def public_call_other_view(self, ctx: Context, method_name: str) -> None:
        self.syscall.get_contract(self.other_id, blueprint_id=None) \
            .get_view_method(method_name) \
            .call()

    @public
    def public_call_other_public(self, ctx: Context, method_name: str) -> None:
        self.syscall.get_contract(self.other_id, blueprint_id=None) \
            .get_public_method(method_name) \
            .call()


class MyBlueprint2(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @view
    def view_nop(self) -> None:
        pass

    @view
    def view_fail(self) -> None:
        raise NCFail('fail called')

    @public
    def public_nop(self, ctx: Context) -> None:
        pass

    @public
    def public_fail(self, ctx: Context) -> None:
        raise NCFail('fail called')


class TestFollowUpCall(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.blueprint_id1 = self._register_blueprint_class(MyBlueprint1)
        self.blueprint_id2 = self._register_blueprint_class(MyBlueprint2)

        self.contract_id = self.gen_random_contract_id()
        self.other_id = self.gen_random_contract_id()

        self.runner.create_contract(self.other_id, self.blueprint_id2, self.create_context())
        self.runner.create_contract(self.contract_id, self.blueprint_id1, self.create_context(), self.other_id)

    def test_view_call_other_view_success(self) -> None:
        self.runner.call_view_method(self.contract_id, 'view_call_other_view', 'view_nop')
        self.runner.call_public_method(self.contract_id, 'public_nop', self.create_context())

    def test_public_call_other_view_success(self) -> None:
        self.runner.call_public_method(self.contract_id, 'public_call_other_view', self.create_context(), 'view_nop')
        self.runner.call_public_method(self.contract_id, 'public_nop', self.create_context())

    def test_public_call_other_public_success(self) -> None:
        self.runner.call_public_method(
            self.contract_id, 'public_call_other_public', self.create_context(), 'public_nop'
        )
        self.runner.call_public_method(self.contract_id, 'public_nop', self.create_context())

    def test_view_call_other_view_fail(self) -> None:
        with pytest.raises(NCFail, match='fail called'):
            self.runner.call_view_method(self.contract_id, 'view_call_other_view', 'view_fail')
        self.runner.call_public_method(self.contract_id, 'public_nop', self.create_context())

    def test_public_call_other_view_fail(self) -> None:
        with pytest.raises(NCFail, match='fail called'):
            self.runner.call_public_method(
                self.contract_id, 'public_call_other_view', self.create_context(), 'view_fail'
            )
        self.runner.call_public_method(self.contract_id, 'public_nop', self.create_context())

    def test_public_call_other_public_fail(self) -> None:
        with pytest.raises(NCFail, match='fail called'):
            self.runner.call_public_method(
                self.contract_id, 'public_call_other_public', self.create_context(), 'public_fail'
            )
        self.runner.call_public_method(self.contract_id, 'public_nop', self.create_context())
