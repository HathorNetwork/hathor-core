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
from hathor.nanocontracts.types import NCDepositAction
from hathor.transaction import Transaction
from hathor.transaction.nc_execution_state import NCExecutionState
from tests import unittest
from tests.dag_builder.builder import TestDAGBuilder
from tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from tests.nanocontracts.test_blueprint import STR_NC_TYPE
from tests.nanocontracts.test_blueprints import contract_accessor_blueprint


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

    def test_multiple_view_calls_on_contract(self) -> None:
        ret = self.runner.call_view_method(
            self.contract_id1, 'test_multiple_view_calls_on_contract', other_id=self.contract_id2, name='alice'
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

    def test_actions_clear_after_single_use(self) -> None:
        ret = self.runner.call_public_method(
            self.contract_id1,
            'test_actions_clear_after_single_use',
            self.create_context(),
            other_id=self.contract_id2,
            name='bob',
        )
        assert ret == (
            (
                "hello \"bob1\" from simple public method with actions: "
                "(NCDepositAction(token_uid=b'\\x00', amount=123),)"
            ),
            "hello \"bob2\" from simple public method with actions: ()",
        )

    def test_multiple_public_calls_on_method(self) -> None:
        msg = (
            'accessor for method `simple_public_method` was already used, '
            'you must use the contract instance to call it again'
        )
        with pytest.raises(NCFail, match=re.escape(msg)):
            self.runner.call_public_method(
                self.contract_id1,
                'test_multiple_public_calls_on_method',
                self.create_context(),
                other_id=self.contract_id2,
                name='bob',
            )

    def test_multiple_public_calls_on_method_no_actions(self) -> None:
        msg = (
            'accessor for method `simple_public_method` was already used, '
            'you must use the contract instance to call it again'
        )
        with pytest.raises(NCFail, match=re.escape(msg)):
            self.runner.call_public_method(
                self.contract_id1,
                'test_multiple_public_calls_on_method_no_actions',
                self.create_context(),
                other_id=self.contract_id2,
                name='bob',
            )

    def test_unused_actions_already_set(self) -> None:
        msg = "unused actions are already set: (NCDepositAction(token_uid=b'\\x00', amount=123),)"
        with pytest.raises(NCFail, match=re.escape(msg)):
            self.runner.call_public_method(
                self.contract_id1,
                'test_unused_actions_already_set',
                self.create_context(),
                other_id=self.contract_id2,
                name='bob',
            )

    def test_forbidden_initialize(self) -> None:
        msg = 'cannot call method `initialize` directly'
        with pytest.raises(NCFail, match=re.escape(msg)):
            self.runner.call_public_method(
                self.contract_id1,
                'test_forbidden_initialize',
                self.create_context(),
                other_id=self.contract_id2,
            )

    def test_forbidden_fallback(self) -> None:
        msg = 'cannot call method `fallback` directly'
        with pytest.raises(NCFail, match=re.escape(msg)):
            self.runner.call_public_method(
                self.contract_id1,
                'test_forbidden_fallback',
                self.create_context(),
                other_id=self.contract_id2,
            )

    # TODO: Is that the behavior we want? This means calling unknown methods with accessors will never call the
    #  fallback, but since we don't know if the user intended to call a view or a public method, we cannot do it.
    def test_unknown_method(self) -> None:
        msg = f'unknown method `unknown` on blueprint `{self.blueprint_id.hex()}` with class `MyBlueprint`'
        with pytest.raises(NCFail, match=re.escape(msg)):
            self.runner.call_public_method(
                self.contract_id1,
                'test_unknown_method',
                self.create_context(),
                other_id=self.contract_id2,
            )

    def test_call_attr(self) -> None:
        msg = (
            f'`message` is an attribute, not a method, on blueprint '
            f'`{self.blueprint_id.hex()}` with class `MyBlueprint`'
        )
        with pytest.raises(NCFail, match=re.escape(msg)):
            self.runner.call_public_method(
                self.contract_id1,
                'test_call_attr',
                self.create_context(),
                other_id=self.contract_id2,
            )

    def test_internal_method(self) -> None:
        msg = (
            f'cannot call internal method `internal_method` on blueprint '
            f'`{self.blueprint_id.hex()}` with class MyBlueprint`'
        )
        with pytest.raises(NCFail, match=re.escape(msg)):
            self.runner.call_public_method(
                self.contract_id1,
                'test_internal_method',
                self.create_context(),
                other_id=self.contract_id2,
            )

    def test_view_with_actions(self) -> None:
        msg = (
            "cannot call view method `simple_view_method` while using actions: "
            "(NCDepositAction(token_uid=b'\\x00', amount=123),)"
        )
        with pytest.raises(NCFail, match=re.escape(msg)):
            self.runner.call_public_method(
                self.contract_id1,
                'test_view_with_actions',
                self.create_context(),
                other_id=self.contract_id2,
                name='alice',
            )

    def test_accessor_on_ocb(self) -> None:
        """
        We have to make a test for OCB with the DagBuilder because the `get_contract` lazy import
        is instantiated through different paths for test blueprints, builtin blueprints, and OCBs.
        """
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()

        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..13]
            b10 < dummy

            ocb.ocb_private_key = "{private_key}"
            ocb.ocb_password = "{password}"
            ocb.ocb_code = contract_accessor_blueprint.py, MyBlueprint

            nc1.nc_id = ocb
            nc1.nc_method = initialize()
            nc1.nc_deposit = 1000 HTR

            nc2.nc_id = ocb
            nc2.nc_method = initialize()

            nc3.nc_id = nc1
            nc3.nc_method = test_simple_public_method(`nc2`, "alice")

            ocb <-- b11
            nc1 <-- nc2 <-- b12
            nc2 <-- nc3 <-- b13
        ''')

        artifacts.propagate_with(self.manager)
        nc1, nc2, nc3 = artifacts.get_typed_vertices(('nc1', 'nc2', 'nc3'), Transaction)

        assert nc1.get_metadata().nc_execution is NCExecutionState.SUCCESS
        assert nc2.get_metadata().nc_execution is NCExecutionState.SUCCESS
        assert nc3.get_metadata().nc_execution is NCExecutionState.SUCCESS

        storage1 = self.manager.get_best_block_nc_storage(nc1.hash)
        storage2 = self.manager.get_best_block_nc_storage(nc2.hash)

        assert storage1.get_obj(b'message', STR_NC_TYPE) == 'initialize called'
        assert storage2.get_obj(b'message', STR_NC_TYPE) == (
            "hello \"alice\" from simple public method with actions: "
            "(NCDepositAction(token_uid=b'\\x00', amount=123),)"
        )
