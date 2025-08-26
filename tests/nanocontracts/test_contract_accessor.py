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
            f'you must use `prepare_public_call` on the contract to call it again'
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
            'you must use `prepare_public_call` on the contract to call it again'
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

    @pytest.mark.xfail(strict=True, reason='''
        Support for builtin blueprints with lazy functions is currently not implemented, since it's not a priority
        while we don't have any builtin blueprints. In order to support it, we must change the NCCatalog to hold
        blueprint files instead of classes, because the class has to be loaded in runtime, just like OCBs, so we can
        inject the runner for the lazy imports.
        This means we have to update the `TransactionStorage.get_blueprint_class` method to pass the Runner to the
        builtin blueprint class (just like it already does for OCBs). Currently, it jus returns the preloaded class.
    ''')
    def test_accessor_on_builtin(self) -> None:
        """
        We have to make a test for a builtin blueprint with the DagBuilder because the `get_contract` lazy import
        is instantiated through different paths for test blueprints, builtin blueprints, and OCBs.
        """
        builtin_blueprint_id = self._register_blueprint_class(contract_accessor_blueprint.MyBlueprint)
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            nc1.nc_id = "{builtin_blueprint_id.hex()}"
            nc1.nc_method = initialize()
            nc1.nc_deposit = 1000 HTR

            nc2.nc_id = "{builtin_blueprint_id.hex()}"
            nc2.nc_method = initialize()

            nc3.nc_id = nc1
            nc3.nc_method = test_simple_public_method(`nc2`, "alice")

            nc1 <-- nc2 <-- b11
            nc2 <-- nc3 <-- b12
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

    def test_import_during_runtime(self) -> None:
        """
        Make sure that importing `get_contract` during a method call is also supported,
        that is, not at module-level.
        """
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()

        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..13]
            b10 < dummy

            ocb.ocb_private_key = "{private_key}"
            ocb.ocb_password = "{password}"

            nc1.nc_id = ocb
            nc1.nc_method = initialize(null)

            nc2.nc_id = ocb
            nc2.nc_method = initialize(`nc1`)

            ocb <-- b11
            nc1 <-- b12
            nc1 <-- nc2 <-- b13

            ocb.ocb_code = ```
                from hathor.nanocontracts import Blueprint
                from hathor.nanocontracts.context import Context
                from hathor.nanocontracts.types import public, ContractId

                class MyBlueprint(Blueprint):
                    message: str

                    @public
                    def initialize(self, ctx: Context, other_id: ContractId | None) -> None:
                        self.message = 'initialize called'
                        if other_id is not None:
                            from hathor.nanocontracts import get_contract
                            other = get_contract(other_id, blueprint_id=None)
                            other.prepare_public_call().public_method()

                    @public
                    def public_method(self, ctx: Context) -> None:
                        self.message = 'public_method called'

                __blueprint__ = MyBlueprint
            ```
        ''')

        artifacts.propagate_with(self.manager)
        nc1, nc2 = artifacts.get_typed_vertices(('nc1', 'nc2'), Transaction)

        assert nc1.get_metadata().nc_execution is NCExecutionState.SUCCESS
        assert nc2.get_metadata().nc_execution is NCExecutionState.SUCCESS

        storage1 = self.manager.get_best_block_nc_storage(nc1.hash)
        storage2 = self.manager.get_best_block_nc_storage(nc2.hash)

        assert storage1.get_obj(b'message', STR_NC_TYPE) == 'public_method called'
        assert storage2.get_obj(b'message', STR_NC_TYPE) == 'initialize called'

    def test_get_contract_at_module_level(self) -> None:
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()

        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            ocb.ocb_private_key = "{private_key}"
            ocb.ocb_password = "{password}"
            tx1 <-- ocb <-- b11

            ocb.ocb_code = ```
                from hathor.nanocontracts import Blueprint
                from hathor.nanocontracts.context import Context
                from hathor.nanocontracts.types import public, ContractId
                from hathor.nanocontracts import get_contract

                x = get_contract()

                class MyBlueprint(Blueprint):
                    @public
                    def initialize(self, ctx: Context) -> None:
                        pass

                __blueprint__ = MyBlueprint
            ```
        ''')

        artifacts.propagate_with(self.manager, up_to='tx1')

        with pytest.raises(Exception) as e:
            artifacts.propagate_with(self.manager)

        assert isinstance(e.value.__cause__, ImportError)
        assert e.value.__cause__.args[0] == (
            '`get_contract` cannot be called without a runtime, probably outside a method call'
        )
