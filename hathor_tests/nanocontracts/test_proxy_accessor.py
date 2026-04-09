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
    view,
)
from hathor.nanocontracts.exception import NCInvalidMethodCall, NCInvalidSyscall, NCViewMethodError
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class MyBlueprint1(Blueprint):
    other_blueprint_id: BlueprintId

    @public(allow_deposit=True)
    def initialize(self, ctx: Context, blueprint_id: BlueprintId) -> None:
        self.other_blueprint_id = blueprint_id

    @public
    def test_get_blueprint_id(self, ctx: Context) -> BlueprintId:
        proxy = self.syscall.get_proxy(self.other_blueprint_id)
        return proxy.get_blueprint_id()

    @view
    def test_view_method(self, name: str) -> str:
        proxy = self.syscall.get_proxy(self.other_blueprint_id)

        ret1 = proxy.view().hello_view(name)
        ret2 = proxy.view().hello_view.call(name)
        ret3 = proxy.get_view_method('hello_view').call(name)
        ret4 = proxy.get_view_method('hello_view')(name)

        assert len({ret1, ret2, ret3, ret4}) == 1
        return ret1

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

    @view
    def test_multiple_view_calls_on_prepared_call(self) -> tuple[str, str]:
        proxy = self.syscall.get_proxy(self.other_blueprint_id)
        prepared_call = proxy.view()

        ret1 = prepared_call.hello_view('alice')
        ret2 = prepared_call.hello_view('bob')
        return ret1, ret2

    @view
    def test_multiple_view_calls_on_method(self) -> tuple[str, str]:
        proxy = self.syscall.get_proxy(self.other_blueprint_id)
        prepared_call = proxy.view()
        method = prepared_call.hello_view

        ret1 = method('alice')
        ret2 = method('bob')
        return ret1, ret2

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

    @public
    def test_get_blueprint_id_through_proxy(self, ctx: Context) -> BlueprintId:
        proxy = self.syscall.get_proxy(self.other_blueprint_id)
        return proxy.public().get_blueprint_id()

    @public
    def test_get_current_code_blueprint_id(self, ctx: Context) -> BlueprintId:
        current_code_blueprint_id = self.syscall.get_current_code_blueprint_id()
        assert self.syscall.get_blueprint_id() == current_code_blueprint_id, (
            "should be the same BlueprintId when we're not in a proxy call"
        )
        proxy = self.syscall.get_proxy(self.other_blueprint_id)
        return proxy.public().get_current_code_blueprint_id()

    @public(allow_deposit=True)
    def nop_public(self, ctx: Context) -> None:
        pass

    @public
    def call_itself_through_double_proxy_other(self, ctx: Context) -> None:
        proxy = self.syscall.get_proxy(self.other_blueprint_id)
        proxy.public().call_itself_through_proxy(self.other_blueprint_id)

    @public
    def call_itself_through_double_proxy_same(self, ctx: Context) -> None:
        proxy = self.syscall.get_proxy(self.other_blueprint_id)
        proxy.public().call_itself_through_proxy(self.syscall.get_blueprint_id())

    @view
    def call_itself_through_double_proxy_other_view(self) -> None:
        proxy = self.syscall.get_proxy(self.other_blueprint_id)
        proxy.view().call_itself_through_proxy_view(self.other_blueprint_id)

    @view
    def call_itself_through_double_proxy_same_view(self) -> None:
        proxy = self.syscall.get_proxy(self.other_blueprint_id)
        proxy.view().call_itself_through_proxy_view(self.syscall.get_blueprint_id())

    @public
    def test_visibility_combinations_public_public_public(self, ctx: Context, blueprint_id: BlueprintId) -> None:
        proxy = self.syscall.get_proxy(blueprint_id)
        action = NCDepositAction(amount=123, token_uid=HATHOR_TOKEN_UID)
        proxy.public(action).nop_public()

    @public
    def test_visibility_combinations_public_public_view(self, ctx: Context, blueprint_id: BlueprintId) -> None:
        proxy = self.syscall.get_proxy(blueprint_id)
        action = NCDepositAction(amount=123, token_uid=HATHOR_TOKEN_UID)
        proxy.public(action).nop_view()

    @public
    def test_visibility_combinations_public_view_public(self, ctx: Context, blueprint_id: BlueprintId) -> None:
        proxy = self.syscall.get_proxy(blueprint_id)
        proxy.view().nop_public()

    @public
    def test_visibility_combinations_public_view_view(self, ctx: Context, blueprint_id: BlueprintId) -> None:
        proxy = self.syscall.get_proxy(blueprint_id)
        proxy.view().nop_view()

    @view
    def test_visibility_combinations_view_public_public(self, blueprint_id: BlueprintId) -> None:
        proxy = self.syscall.get_proxy(blueprint_id)
        action = NCDepositAction(amount=123, token_uid=HATHOR_TOKEN_UID)
        proxy.public(action).nop_public()

    @view
    def test_visibility_combinations_view_public_view(self, blueprint_id: BlueprintId) -> None:
        proxy = self.syscall.get_proxy(blueprint_id)
        action = NCDepositAction(amount=123, token_uid=HATHOR_TOKEN_UID)
        proxy.public(action).nop_view()

    @view
    def test_visibility_combinations_view_view_public(self, blueprint_id: BlueprintId) -> None:
        proxy = self.syscall.get_proxy(blueprint_id)
        proxy.view().nop_public()

    @view
    def test_visibility_combinations_view_view_view(self, blueprint_id: BlueprintId) -> None:
        proxy = self.syscall.get_proxy(blueprint_id)
        proxy.view().nop_view()


class MyBlueprint2(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @view
    def hello_view(self, name: str) -> str:
        return f'hello {name}'

    @public(allow_deposit=True)
    def hello(self, ctx: Context, name: str) -> str:
        return f'hello {name}'

    @fallback
    def fallback(self, ctx: Context, method_name: str, nc_args: NCArgs) -> str:
        return f'fallback called for method `{method_name}`'

    @public
    def get_blueprint_id(self, ctx: Context) -> BlueprintId:
        return self.syscall.get_blueprint_id()

    @public
    def get_current_code_blueprint_id(self, ctx: Context) -> BlueprintId:
        return self.syscall.get_current_code_blueprint_id()

    @public(allow_deposit=True)
    def nop_public(self, ctx: Context) -> None:
        pass

    @view
    def nop_view(self) -> None:
        pass

    @public
    def call_itself_through_proxy(self, ctx: Context, blueprint_id: BlueprintId) -> None:
        proxy = self.syscall.get_proxy(blueprint_id)
        proxy.public().nop_public()

    @view
    def call_itself_through_proxy_view(self, blueprint_id: BlueprintId) -> None:
        proxy = self.syscall.get_proxy(blueprint_id)
        proxy.view().nop_view()


class TestProxyAccessor(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.blueprint_id1 = self._register_blueprint_class(MyBlueprint1)
        self.blueprint_id2 = self._register_blueprint_class(MyBlueprint2)
        self.contract_id1 = self.gen_random_contract_id()
        self.contract_id2 = self.gen_random_contract_id()

        ctx = self.create_context([NCDepositAction(amount=123, token_uid=HATHOR_TOKEN_UID)])
        self.runner.create_contract(self.contract_id1, self.blueprint_id1, ctx, self.blueprint_id2)
        self.runner.create_contract(self.contract_id2, self.blueprint_id2, self.create_context())

    def test_get_blueprint_id(self) -> None:
        ret = self.runner.call_public_method(
            self.contract_id1,
            'test_get_blueprint_id',
            self.create_context(),
        )
        assert ret == self.blueprint_id2

    def test_view_method(self) -> None:
        ret = self.runner.call_view_method(self.contract_id1, 'test_view_method', 'alice')
        assert ret == 'hello alice'

    def test_public_method(self) -> None:
        ret = self.runner.call_public_method(
            self.contract_id1,
            'test_public_method',
            self.create_context(),
            'alice',
        )
        assert ret == 'hello alice'

    def test_multiple_view_calls_on_prepared_call(self) -> None:
        ret = self.runner.call_view_method(self.contract_id1, 'test_multiple_view_calls_on_prepared_call')
        assert ret == ('hello alice', 'hello bob')

    def test_multiple_view_calls_on_method(self) -> None:
        ret = self.runner.call_view_method(self.contract_id1, 'test_multiple_view_calls_on_method')
        assert ret == ('hello alice', 'hello bob')

    def test_multiple_public_calls_on_prepared_call(self) -> None:
        msg = (
            f'prepared proxy public method for blueprint `{self.blueprint_id2.hex()}` was already used, '
            f'you must use `public` on the proxy to call it again'
        )
        with pytest.raises(NCFail, match=re.escape(msg)):
            self.runner.call_public_method(
                self.contract_id1,
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
                self.contract_id1,
                'test_multiple_public_calls_on_method',
                self.create_context(),
            )

    def test_fallback_allowed(self) -> None:
        ret = self.runner.call_public_method(
            self.contract_id1,
            'test_fallback_allowed',
            self.create_context(),
        )
        assert ret == 'fallback called for method `unknown`'

    def test_fallback_forbidden(self) -> None:
        msg = 'method `unknown` not found and fallback is forbidden'
        with pytest.raises(NCFail, match=re.escape(msg)):
            self.runner.call_public_method(
                self.contract_id1,
                'test_fallback_forbidden',
                self.create_context(),
            )

    def test_get_blueprint_id_through_proxy(self) -> None:
        ret = self.runner.call_public_method(
            self.contract_id1,
            'test_get_blueprint_id_through_proxy',
            self.create_context(),
        )
        assert ret == self.blueprint_id1

    def test_get_current_code_blueprint_id(self) -> None:
        ret = self.runner.call_public_method(
            self.contract_id1,
            'test_get_current_code_blueprint_id',
            self.create_context(),
        )
        assert ret == self.blueprint_id2

    def test_call_itself_through_proxy(self) -> None:
        with pytest.raises(NCInvalidSyscall, match='cannot call the same blueprint of the running contract'):
            self.runner.call_public_method(
                self.contract_id2,
                'call_itself_through_proxy',
                self.create_context(),
                self.blueprint_id2,
            )

    def test_call_itself_through_double_proxy_other(self) -> None:
        with pytest.raises(NCInvalidSyscall, match='cannot call the same blueprint of the running blueprint'):
            self.runner.call_public_method(
                self.contract_id1,
                'call_itself_through_double_proxy_other',
                self.create_context(),
            )

    def test_call_itself_through_double_proxy_same(self) -> None:
        with pytest.raises(NCInvalidSyscall, match='cannot call the same blueprint of the running contract'):
            self.runner.call_public_method(
                self.contract_id1,
                'call_itself_through_double_proxy_same',
                self.create_context(),
            )

    def test_call_itself_through_proxy_view(self) -> None:
        with pytest.raises(NCInvalidSyscall, match='cannot call the same blueprint of the running contract'):
            self.runner.call_view_method(
                self.contract_id2,
                'call_itself_through_proxy_view',
                self.blueprint_id2,
            )

    def test_call_itself_through_double_proxy_other_view(self) -> None:
        with pytest.raises(NCInvalidSyscall, match='cannot call the same blueprint of the running blueprint'):
            self.runner.call_view_method(
                self.contract_id1,
                'call_itself_through_double_proxy_other_view',
            )

    def test_call_itself_through_double_proxy_same_view(self) -> None:
        with pytest.raises(NCInvalidSyscall, match='cannot call the same blueprint of the running contract'):
            self.runner.call_view_method(
                self.contract_id1,
                'call_itself_through_double_proxy_same_view',
            )

    def test_visibility_combinations(self) -> None:
        """
        This test checks that method visibility is respected when using proxy accessors.
        Consider this exhaustive table of combinations of the caller method, the accessor it uses,
        the method it calls, and the expected outcode:

        caller | accessor | callee | expected
        -------------------------------------
        public | public   | public | SUCCESS
        public | public   | view   | FAIL
        public | view     | public | FAIL
        public | view     | view   | SUCCESS
        view   | public   | public | FAIL
        view   | public   | view   | FAIL
        view   | view     | public | FAIL
        view   | view     | view   | SUCCESS
        """

        self.runner.call_public_method(
            self.contract_id1,
            'test_visibility_combinations_public_public_public',
            self.create_context(),
            blueprint_id=self.blueprint_id2,
        )

        with pytest.raises(NCInvalidMethodCall, match='method `nop_view` is not a public method'):
            self.runner.call_public_method(
                self.contract_id1,
                'test_visibility_combinations_public_public_view',
                self.create_context(),
                blueprint_id=self.blueprint_id2,
            )

        with pytest.raises(NCInvalidMethodCall, match='`nop_public` is not a view method'):
            self.runner.call_public_method(
                self.contract_id1,
                'test_visibility_combinations_public_view_public',
                self.create_context(),
                blueprint_id=self.blueprint_id2,
            )

        self.runner.call_public_method(
            self.contract_id1,
            'test_visibility_combinations_public_view_view',
            self.create_context(),
            blueprint_id=self.blueprint_id2,
        )

        with pytest.raises(NCViewMethodError, match='@view method cannot call `syscall.proxy_call_public_method`'):
            self.runner.call_view_method(
                self.contract_id1,
                'test_visibility_combinations_view_public_public',
                blueprint_id=self.blueprint_id2,
            )

        with pytest.raises(NCViewMethodError, match='@view method cannot call `syscall.proxy_call_public_method`'):
            self.runner.call_view_method(
                self.contract_id1,
                'test_visibility_combinations_view_public_view',
                blueprint_id=self.blueprint_id2,
            )

        with pytest.raises(NCInvalidMethodCall, match='`nop_public` is not a view method'):
            self.runner.call_view_method(
                self.contract_id1,
                'test_visibility_combinations_view_view_public',
                blueprint_id=self.blueprint_id2,
            )

        self.runner.call_view_method(
            self.contract_id1,
            'test_visibility_combinations_view_view_view',
            blueprint_id=self.blueprint_id2,
        )
