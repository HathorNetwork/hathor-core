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

from hathor import HATHOR_TOKEN_UID, Blueprint, BlueprintId, Context, NCDepositAction, NCFail, public, view
from hathor.nanocontracts.exception import NCViewMethodError
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class MyBlueprint1(Blueprint):
    @public(allow_deposit=True)
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def test_initialize_method(self, ctx: Context, blueprint_id: BlueprintId, name: str) -> str:
        action = NCDepositAction(token_uid=HATHOR_TOKEN_UID, amount=123)
        _, ret = self.syscall.setup_new_contract(blueprint_id, action, salt=b'1').initialize(name)
        assert isinstance(ret, str)
        return ret

    @public
    def test_multiple_initialize_calls_on_setup(self, ctx: Context, blueprint_id: BlueprintId) -> None:
        setup = self.syscall.setup_new_contract(blueprint_id, salt=b'1')
        setup.initialize('')
        setup.initialize('')

    @public
    def test_multiple_initialize_calls_on_method(self, ctx: Context, blueprint_id: BlueprintId) -> None:
        method = self.syscall.setup_new_contract(blueprint_id, salt=b'1').initialize
        method('')
        method('')

    @view
    def test_initialize_from_view(self, blueprint_id: BlueprintId) -> None:
        action = NCDepositAction(token_uid=HATHOR_TOKEN_UID, amount=123)
        self.syscall.setup_new_contract(blueprint_id, action, salt=b'1').initialize('')


class MyBlueprint2(Blueprint):
    @public(allow_deposit=True)
    def initialize(self, ctx: Context, name: str) -> str:
        return f'hello {name}'


class TestInitializeMethodAccessor(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.blueprint_id1 = self._register_blueprint_class(MyBlueprint1)
        self.blueprint_id2 = self._register_blueprint_class(MyBlueprint2)
        self.contract_id = self.gen_random_contract_id()

        action = NCDepositAction(token_uid=HATHOR_TOKEN_UID, amount=123)
        self.runner.create_contract(self.contract_id, self.blueprint_id1, self.create_context([action]))

    def test_initialize_method(self) -> None:
        ret = self.runner.call_public_method(
            self.contract_id,
            'test_initialize_method',
            self.create_context(),
            self.blueprint_id2,
            'alice'
        )
        assert ret == 'hello alice'

    def test_multiple_initialize_calls_on_setup(self) -> None:
        msg = 'accessor for initialize method was already used, you must use `setup_new_contract` to call it again'
        with pytest.raises(NCFail, match=re.escape(msg)):
            self.runner.call_public_method(
                self.contract_id,
                'test_multiple_initialize_calls_on_setup',
                self.create_context(),
                self.blueprint_id2,
            )

    def test_multiple_initialize_calls_on_method(self) -> None:
        msg = 'accessor for initialize method was already used, you must use `setup_new_contract` to call it again'
        with pytest.raises(NCFail, match=re.escape(msg)):
            self.runner.call_public_method(
                self.contract_id,
                'test_multiple_initialize_calls_on_method',
                self.create_context(),
                self.blueprint_id2,
            )

    def test_initialize_from_view(self) -> None:
        with pytest.raises(NCViewMethodError, match='@view method cannot call `syscall.setup_new_contract`'):
            self.runner.call_view_method(
                self.contract_id,
                'test_initialize_from_view',
                self.blueprint_id2,
            )
