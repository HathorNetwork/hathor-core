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

from hathor.nanocontracts import Blueprint, Context, NCFail, public
from hathor.nanocontracts.runner.types import NCArgs
from hathor.nanocontracts.types import ContractId, fallback, view
from tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class MyBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def public_method(self, ctx: Context, a: int) -> None:
        pass

    @public
    def public_method_wrong_return_type(self, ctx: Context) -> int:
        return 'abc'  # type: ignore[return-value]

    @view
    def view_method(self, a: int) -> None:
        pass

    @view
    def view_method_wrong_return_type(self) -> int:
        return 'abc'  # type: ignore[return-value]

    @public
    def call_public_wrong_arg_type(self, ctx: Context, other_id: ContractId) -> None:
        self.syscall.call_public_method(other_id, 'public_method', [], 'abc')

    @public
    def call_public_wrong_kwarg_type(self, ctx: Context, other_id: ContractId) -> None:
        self.syscall.call_public_method(other_id, 'public_method', [], a='abc')

    @public
    def call_public_wrong_return_type(self, ctx: Context, other_id: ContractId) -> None:
        self.syscall.call_public_method(other_id, 'public_method_wrong_return_type', [])

    @view
    def call_view_wrong_arg_type(self, other_id: ContractId) -> None:
        self.syscall.call_view_method(other_id, 'view_method', 'abc')

    @view
    def call_view_wrong_kwarg_type(self, other_id: ContractId) -> None:
        self.syscall.call_view_method(other_id, 'view_method', a='abc')

    @view
    def call_view_wrong_return_type(self, other_id: ContractId) -> None:
        self.syscall.call_view_method(other_id, 'view_method_wrong_return_type')

    @fallback
    def fallback(self, ctx: Context, method_name: str, nc_args: NCArgs) -> int:
        return 'abc'  # type: ignore[return-value]


class TestTypesAcrossContracts(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.blueprint_id = self._register_blueprint_class(MyBlueprint)
        self.contract_id1 = self.gen_random_contract_id()
        self.contract_id2 = self.gen_random_contract_id()
        self.runner.create_contract(self.contract_id1, self.blueprint_id, self.create_context())
        self.runner.create_contract(self.contract_id2, self.blueprint_id, self.create_context())

    def test_public_wrong_arg_type(self) -> None:
        with pytest.raises(NCFail) as e:
            self.runner.call_public_method(
                self.contract_id1,
                'call_public_wrong_arg_type',
                self.create_context(),
                self.contract_id2,
            )
        assert isinstance(e.value.__cause__, TypeError)
        assert e.value.__cause__.args[0] == 'expected integer'

    def test_public_wrong_kwarg_type(self) -> None:
        with pytest.raises(NCFail) as e:
            self.runner.call_public_method(
                self.contract_id1,
                'call_public_wrong_kwarg_type',
                self.create_context(),
                self.contract_id2,
            )
        assert isinstance(e.value.__cause__, TypeError)
        assert e.value.__cause__.args[0] == 'expected integer'

    def test_public_wrong_return_type(self) -> None:
        with pytest.raises(NCFail) as e:
            self.runner.call_public_method(
                self.contract_id1,
                'call_public_wrong_return_type',
                self.create_context(),
                self.contract_id2,
            )
        assert isinstance(e.value.__cause__, TypeError)
        assert e.value.__cause__.args[0] == 'expected integer'

    def test_view_wrong_arg_type(self) -> None:
        with pytest.raises(NCFail) as e:
            self.runner.call_view_method(
                self.contract_id1,
                'call_view_wrong_arg_type',
                self.contract_id2,
            )
        assert isinstance(e.value.__cause__, TypeError)
        assert e.value.__cause__.args[0] == 'expected integer'

    def test_view_wrong_kwarg_type(self) -> None:
        with pytest.raises(NCFail) as e:
            self.runner.call_view_method(
                self.contract_id1,
                'call_view_wrong_kwarg_type',
                self.contract_id2,
            )
        assert isinstance(e.value.__cause__, TypeError)
        assert e.value.__cause__.args[0] == 'expected integer'

    def test_view_wrong_return_type(self) -> None:
        with pytest.raises(NCFail) as e:
            self.runner.call_view_method(
                self.contract_id1,
                'call_view_wrong_return_type',
                self.contract_id2,
            )
        assert isinstance(e.value.__cause__, TypeError)
        assert e.value.__cause__.args[0] == 'expected integer'

    def test_fallback_wrong_return_type(self) -> None:
        with pytest.raises(NCFail) as e:
            self.runner.call_public_method(
                self.contract_id1,
                'unknown',
                self.create_context(),
                self.contract_id2,
            )
        assert isinstance(e.value.__cause__, TypeError)
        assert e.value.__cause__.args[0] == 'expected integer'
