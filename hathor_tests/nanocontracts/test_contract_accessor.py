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

import inspect
import re

import pytest

from hathor.nanocontracts import HATHOR_TOKEN_UID, NCFail
from hathor.nanocontracts.exception import NCInvalidMethodCall, NCViewMethodError
from hathor.nanocontracts.types import NCDepositAction
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from hathor_tests.nanocontracts.test_blueprints import contract_accessor_blueprint


class TestContractAccessor(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.blueprint_id = self.register_blueprint_file(inspect.getfile(contract_accessor_blueprint))
        self.contract_id1 = self.gen_random_contract_id()
        self.contract_id2 = self.gen_random_contract_id()

        action = NCDepositAction(amount=1000, token_uid=HATHOR_TOKEN_UID)
        self.runner.create_contract(self.contract_id1, self.blueprint_id, self.create_context(actions=[action]))
        self.runner.create_contract(self.contract_id2, self.blueprint_id, self.create_context())

    def test_simple_view_method(self) -> None:
        ret = self.runner.call_view_method(
            self.contract_id1, 'test_simple_view_method', other_id=self.contract_id2, name='alice'
        )
        assert ret == 'hello "alice" from simple view method'

    def test_simple_public_method(self) -> None:
        ret = self.runner.call_public_method(
            self.contract_id1,
            'test_simple_public_method',
            self.create_context(),
            other_id=self.contract_id2,
            name='bob',
        )
        assert ret == (
            "hello \"bob\" from simple public method with actions: (NCDepositAction(token_uid=b'\\x00', amount=123),)"
        )

    def test_simple_public_method_no_actions(self) -> None:
        ret = self.runner.call_public_method(
            self.contract_id1,
            'test_simple_public_method_no_actions',
            self.create_context(),
            other_id=self.contract_id2,
            name='bob',
        )
        assert ret == (
            "hello \"bob\" from simple public method with actions: ()"
        )

    def test_multiple_view_calls_on_prepared_call(self) -> None:
        ret = self.runner.call_view_method(
            self.contract_id1, 'test_multiple_view_calls_on_prepared_call', other_id=self.contract_id2, name='alice'
        )
        assert ret == (
            'hello "alice1" from simple view method',
            'hello "alice2" from simple view method',
        )

    def test_multiple_view_calls_on_method(self) -> None:
        ret = self.runner.call_view_method(
            self.contract_id1, 'test_multiple_view_calls_on_method', other_id=self.contract_id2, name='alice'
        )
        assert ret == (
            'hello "alice1" from simple view method',
            'hello "alice2" from simple view method',
        )

    def test_multiple_public_calls_on_prepared_call(self) -> None:
        msg = (
            f'prepared public method for contract `{self.contract_id2.hex()}` was already used, '
            f'you must use `public` on the contract to call it again'
        )
        with pytest.raises(NCFail, match=re.escape(msg)):
            self.runner.call_public_method(
                self.contract_id1,
                'test_multiple_public_calls_on_prepared_call',
                self.create_context(),
                other_id=self.contract_id2,
                name='bob',
            )

    def test_multiple_public_calls_on_method(self) -> None:
        msg = (
            'accessor for public method `simple_public_method` was already used, '
            'you must use `public`/`public_method` on the contract to call it again'
        )
        with pytest.raises(NCFail, match=re.escape(msg)):
            self.runner.call_public_method(
                self.contract_id1,
                'test_multiple_public_calls_on_method',
                self.create_context(),
                other_id=self.contract_id2,
                name='bob',
            )

    def test_fallback_allowed(self) -> None:
        ret = self.runner.call_public_method(
            self.contract_id1,
            'test_fallback_allowed',
            self.create_context(),
            other_id=self.contract_id2,
        )
        assert ret == 'fallback called for method `unknown`'

    def test_fallback_forbidden(self) -> None:
        msg = 'method `unknown` not found and fallback is forbidden'
        with pytest.raises(NCFail, match=re.escape(msg)):
            self.runner.call_public_method(
                self.contract_id1,
                'test_fallback_forbidden',
                self.create_context(),
                other_id=self.contract_id2,
            )

    def test_view_allow_single_blueprint_valid(self) -> None:
        ret = self.runner.call_view_method(
            self.contract_id1, 'test_view_allow_single_blueprint_valid', other_id=self.contract_id2, name='alice'
        )
        assert ret == 'hello "alice" from simple view method'

    def test_view_allow_single_blueprint_invalid(self) -> None:
        blueprint_id = b'\x11' * 32
        msg = (
            f"expected blueprint to be one of `('{blueprint_id.hex()}',)`, "
            f'got `{self.blueprint_id.hex()}` for contract `{self.contract_id2.hex()}`'
        )
        with pytest.raises(NCFail, match=re.escape(msg)):
            self.runner.call_view_method(
                self.contract_id1, 'test_view_allow_single_blueprint_invalid', other_id=self.contract_id2, name='alice'
            )

    def test_view_allow_multiple_blueprints_valid(self) -> None:
        ret = self.runner.call_view_method(
            self.contract_id1, 'test_view_allow_multiple_blueprints_valid', other_id=self.contract_id2, name='alice'
        )
        assert ret == 'hello "alice" from simple view method'

    def test_view_allow_multiple_blueprints_invalid(self) -> None:
        blueprint_id1 = b'\x11' * 32
        blueprint_id2 = b'\x22' * 32
        msg = (
            f"expected blueprint to be one of `('{blueprint_id1.hex()}', '{blueprint_id2.hex()}')`, "
            f"got `{self.blueprint_id.hex()}` for contract `{self.contract_id2.hex()}`"
        )
        with pytest.raises(NCFail, match=re.escape(msg)):
            self.runner.call_view_method(
                self.contract_id1,
                'test_view_allow_multiple_blueprints_invalid',
                other_id=self.contract_id2,
                name='alice',
            )

    def test_public_allow_single_blueprint_valid(self) -> None:
        ret = self.runner.call_public_method(
            self.contract_id1,
            'test_public_allow_single_blueprint_valid',
            self.create_context(),
            other_id=self.contract_id2,
            name='alice',
        )
        assert ret == 'hello "alice" from simple public method with actions: ()'

    def test_public_allow_single_blueprint_invalid(self) -> None:
        blueprint_id = b'\x11' * 32
        msg = (
            f"expected blueprint to be one of `('{blueprint_id.hex()}',)`, "
            f'got `{self.blueprint_id.hex()}` for contract `{self.contract_id2.hex()}`'
        )
        with pytest.raises(NCFail, match=re.escape(msg)):
            self.runner.call_public_method(
                self.contract_id1,
                'test_public_allow_single_blueprint_invalid',
                self.create_context(),
                other_id=self.contract_id2,
                name='alice',
            )

    def test_public_allow_multiple_blueprints_valid(self) -> None:
        ret = self.runner.call_public_method(
            self.contract_id1,
            'test_public_allow_multiple_blueprints_valid',
            self.create_context(),
            other_id=self.contract_id2,
            name='alice',
        )
        assert ret == 'hello "alice" from simple public method with actions: ()'

    def test_public_allow_multiple_blueprints_invalid(self) -> None:
        blueprint_id1 = b'\x11' * 32
        blueprint_id2 = b'\x22' * 32
        msg = (
            f"expected blueprint to be one of `('{blueprint_id1.hex()}', '{blueprint_id2.hex()}')`, "
            f"got `{self.blueprint_id.hex()}` for contract `{self.contract_id2.hex()}`"
        )
        with pytest.raises(NCFail, match=re.escape(msg)):
            self.runner.call_public_method(
                self.contract_id1,
                'test_public_allow_multiple_blueprints_invalid',
                self.create_context(),
                other_id=self.contract_id2,
                name='alice',
            )

    def test_other_syscalls(self) -> None:
        token_uid = self.gen_random_token_uid()
        self.runner.call_public_method(
            self.contract_id1,
            'test_other_syscalls',
            self.create_context(),
            other_id=self.contract_id2,
            token_uid=token_uid,
        )

    def test_visibility_combinations(self) -> None:
        """
        This test checks that method visibility is respected when using contract accessors.
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
            other_id=self.contract_id2,
        )

        with pytest.raises(NCInvalidMethodCall, match='method `simple_view_method` is not a public method'):
            self.runner.call_public_method(
                self.contract_id1,
                'test_visibility_combinations_public_public_view',
                self.create_context(),
                other_id=self.contract_id2,
            )

        with pytest.raises(NCInvalidMethodCall, match='`simple_public_method` is not a view method'):
            self.runner.call_public_method(
                self.contract_id1,
                'test_visibility_combinations_public_view_public',
                self.create_context(),
                other_id=self.contract_id2,
            )

        self.runner.call_public_method(
            self.contract_id1,
            'test_visibility_combinations_public_view_view',
            self.create_context(),
            other_id=self.contract_id2,
        )

        with pytest.raises(NCViewMethodError, match='@view method cannot call `syscall.call_public_method`'):
            self.runner.call_view_method(
                self.contract_id1,
                'test_visibility_combinations_view_public_public',
                other_id=self.contract_id2,
            )

        with pytest.raises(NCViewMethodError, match='@view method cannot call `syscall.call_public_method`'):
            self.runner.call_view_method(
                self.contract_id1,
                'test_visibility_combinations_view_public_view',
                other_id=self.contract_id2,
            )

        with pytest.raises(NCInvalidMethodCall, match='`simple_public_method` is not a view method'):
            self.runner.call_view_method(
                self.contract_id1,
                'test_visibility_combinations_view_view_public',
                other_id=self.contract_id2,
            )

        self.runner.call_view_method(
            self.contract_id1,
            'test_visibility_combinations_view_view_view',
            other_id=self.contract_id2,
        )
