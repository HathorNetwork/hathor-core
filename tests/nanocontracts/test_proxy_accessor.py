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

from hathor import (
    HATHOR_TOKEN_UID,
    Blueprint,
    BlueprintId,
    Context,
    NCArgs,
    NCDepositAction,
    NCFail,
    NCParsedArgs,
    fallback,
    public,
)
from tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class MyBlueprint1(Blueprint):
    other_blueprint_id: BlueprintId

    @public(allow_deposit=True)
    def initialize(self, ctx: Context, blueprint_id: BlueprintId) -> None:
        self.other_blueprint_id = blueprint_id

    @public
    def test_get_blueprint_id(self, ctx: Context) -> BlueprintId:
        proxy = self.syscall.get_proxy(self.other_blueprint_id)
        return proxy.get_blueprint_id()

    @public
    def test_public_method(self, ctx: Context, name: str) -> str:
        proxy = self.syscall.get_proxy(self.other_blueprint_id)
        action = NCDepositAction(amount=123, token_uid=HATHOR_TOKEN_UID)

        ret1 = proxy.public(action).hello(name)
        ret2 = proxy.public(action).hello.call(name)
        ret3 = proxy.get_public_method('hello', action).call(name)
        ret4 = proxy.get_public_method('hello', action)(name)

        nc_args = NCParsedArgs(args=(name,), kwargs={})
        ret5 = proxy.public(action).hello.call_with_nc_args(nc_args)
        ret6 = proxy.get_public_method('hello', action).call_with_nc_args(nc_args)

        assert len({ret1, ret2, ret3, ret4, ret5, ret6}) == 1
        return ret1

    @public
    def test_multiple_public_calls_on_prepared_call(self, ctx: Context) -> tuple[str, str]:
        proxy = self.syscall.get_proxy(self.other_blueprint_id)
        action = NCDepositAction(amount=123, token_uid=HATHOR_TOKEN_UID)
        prepared_call = proxy.public(action)

        ret1 = prepared_call.hello('')
        ret2 = prepared_call.hello('')
        return ret1, ret2

    @public
    def test_multiple_public_calls_on_method(self, ctx: Context) -> tuple[str, str]:
        proxy = self.syscall.get_proxy(self.other_blueprint_id)
        action = NCDepositAction(amount=123, token_uid=HATHOR_TOKEN_UID)
        prepared_call = proxy.public(action)
        method = prepared_call.hello

        ret1 = method('')
        ret2 = method('')
        return ret1, ret2

    @public
    def test_fallback_allowed(self, ctx: Context) -> str:
        proxy = self.syscall.get_proxy(self.other_blueprint_id)
        return proxy.public().unknown()

    @public
    def test_fallback_forbidden(self, ctx: Context) -> str:
        proxy = self.syscall.get_proxy(self.other_blueprint_id)
        return proxy.public(forbid_fallback=True).unknown()


class MyBlueprint2(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public(allow_deposit=True)
    def hello(self, ctx: Context, name: str) -> str:
        return f'hello {name}'

    @fallback
    def fallback(self, ctx: Context, method_name: str, nc_args: NCArgs) -> str:
        return f'fallback called for method `{method_name}`'


class TestProxyAccessor(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.blueprint_id1 = self._register_blueprint_class(MyBlueprint1)
        self.blueprint_id2 = self._register_blueprint_class(MyBlueprint2)
        self.contract_id = self.gen_random_contract_id()

        ctx = self.create_context([NCDepositAction(amount=123, token_uid=HATHOR_TOKEN_UID)])
        self.runner.create_contract(self.contract_id, self.blueprint_id1, ctx, self.blueprint_id2)

    def test_get_blueprint_id(self) -> None:
        ret = self.runner.call_public_method(
            self.contract_id,
            'test_get_blueprint_id',
            self.create_context(),
        )
        assert ret == self.blueprint_id2

    def test_public_method(self) -> None:
        ret = self.runner.call_public_method(
            self.contract_id,
            'test_public_method',
            self.create_context(),
            'alice',
        )
        assert ret == 'hello alice'

    def test_multiple_public_calls_on_prepared_call(self) -> None:
        msg = (
            f'prepared proxy public method for blueprint `{self.blueprint_id2.hex()}` was already used, '
            f'you must use `public` on the proxy to call it again'
        )
        with pytest.raises(NCFail, match=re.escape(msg)):
            self.runner.call_public_method(
                self.contract_id,
                'test_multiple_public_calls_on_prepared_call',
                self.create_context(),
            )

    def test_multiple_public_calls_on_method(self) -> None:
        msg = (
            'accessor for proxy public method `hello` was already used, '
            'you must use `public`/`public_method` on the proxy to call it again'
        )
        with pytest.raises(NCFail, match=re.escape(msg)):
            self.runner.call_public_method(
                self.contract_id,
                'test_multiple_public_calls_on_method',
                self.create_context(),
            )

    def test_fallback_allowed(self) -> None:
        ret = self.runner.call_public_method(
            self.contract_id,
            'test_fallback_allowed',
            self.create_context(),
        )
        assert ret == 'fallback called for method `unknown`'

    def test_fallback_forbidden(self) -> None:
        msg = 'method `unknown` not found and fallback is forbidden'
        with pytest.raises(NCFail, match=re.escape(msg)):
            self.runner.call_public_method(
                self.contract_id,
                'test_fallback_forbidden',
                self.create_context(),
            )
