# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import pytest

from hathor.nanocontracts import Blueprint, Context, NCFail, public
from hathor.nanocontracts.types import ContractId, NCArgs, fallback, view
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


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
        self.syscall.get_contract(other_id, blueprint_id=None) \
            .public() \
            .public_method('abc')

    @public
    def call_public_wrong_kwarg_type(self, ctx: Context, other_id: ContractId) -> None:
        self.syscall.get_contract(other_id, blueprint_id=None) \
            .public() \
            .public_method(a='abc')

    @public
    def call_public_wrong_return_type(self, ctx: Context, other_id: ContractId) -> None:
        self.syscall.get_contract(other_id, blueprint_id=None) \
            .public() \
            .public_method_wrong_return_type()

    @view
    def call_view_wrong_arg_type(self, other_id: ContractId) -> None:
        self.syscall.get_contract(other_id, blueprint_id=None) \
            .view() \
            .view_method('abc')

    @view
    def call_view_wrong_kwarg_type(self, other_id: ContractId) -> None:
        self.syscall.get_contract(other_id, blueprint_id=None) \
            .view() \
            .view_method(a='abc')

    @view
    def call_view_wrong_return_type(self, other_id: ContractId) -> None:
        self.syscall.get_contract(other_id, blueprint_id=None) \
            .view() \
            .view_method_wrong_return_type()

    @fallback
    def fallback(self, ctx: Context, method_name: str, nc_args: NCArgs) -> int:
        return 'abc'  # type: ignore[return-value]

    @public
    def call_mutate_list(self, ctx: Context, other_id: ContractId) -> None:
        items = [1, 2, 3]
        self.syscall.get_contract(other_id, blueprint_id=None) \
            .public() \
            .mutate_list(items)
        assert items == [1, 2, 3]

    @public
    def mutate_list(self, ctx: Context, items: list[int]) -> None:
        assert items == [1, 2, 3]
        items.append(4)
        assert items == [1, 2, 3, 4]


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

    def test_arg_mutation(self) -> None:
        self.runner.call_public_method(
            self.contract_id1,
            'call_mutate_list',
            self.create_context(),
            self.contract_id2,
        )
