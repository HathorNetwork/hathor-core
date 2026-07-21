# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import re

import pytest

from hathor import Blueprint, Context, public, view
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from hathorlib.nanocontracts import NCFail
from hathorlib.nanocontracts.types import BlueprintId, ContractId
from hathorlib.token_amount_version import TokenAmountVersion


class MyBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def public_nop(self, ctx: Context) -> None:
        pass

    @view
    def view_nop(self) -> None:
        pass

    @public
    def create_another(self, ctx: Context, blueprint_id: BlueprintId) -> None:
        self.syscall.setup_new_contract(blueprint_id, salt=b'1').initialize()

    @public
    def call_another_public(self, ctx: Context, contract_id: ContractId) -> None:
        contract = self.syscall.get_contract(contract_id, blueprint_id=None)
        contract.public().public_nop()

    @view
    def call_another_view(self, contract_id: ContractId) -> None:
        contract = self.syscall.get_contract(contract_id, blueprint_id=None)
        contract.view().view_nop()

    @public
    def call_proxy_public(self, ctx: Context, blueprint_id: BlueprintId) -> None:
        self.syscall.get_proxy(blueprint_id).public().public_nop()

    @view
    def call_proxy_view(self, blueprint_id: BlueprintId) -> None:
        self.syscall.get_proxy(blueprint_id).view().view_nop()

    @public
    def change_blueprint(self, ctx: Context, blueprint_id: BlueprintId) -> None:
        self.syscall.change_blueprint(blueprint_id)

    @public
    def change_blueprint_then_call_other(self, ctx: Context, blueprint_id: BlueprintId, other_id: ContractId) -> None:
        self.syscall.change_blueprint(blueprint_id)
        contract = self.syscall.get_contract(other_id, blueprint_id=None)
        contract.public().public_nop()


class TestTokenAmountVersion(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.blueprint_id1 = self._register_blueprint_class(MyBlueprint, token_amount_version=TokenAmountVersion.V1)
        self.blueprint_id2 = self._register_blueprint_class(MyBlueprint, token_amount_version=TokenAmountVersion.V2)
        self.contract_id1 = self.gen_random_contract_id()
        self.contract_id2 = self.gen_random_contract_id()

    def test_can_create_v1_contract_with_v1_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V1)
        runner.create_contract(self.contract_id1, self.blueprint_id1, self.create_context())
        assert runner.has_contract_been_initialized(self.contract_id1)

    def test_can_create_v2_contract_with_v2_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)
        runner.create_contract(self.contract_id2, self.blueprint_id2, self.create_context())
        assert runner.has_contract_been_initialized(self.contract_id2)

    def test_cannot_create_v1_contract_with_v2_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)

        msg = 'cannot call blueprints across token amount versions (tx = 2, blueprint = 1)'
        with pytest.raises(NCFail, match=re.escape(msg)):
            runner.create_contract(self.contract_id1, self.blueprint_id1, self.create_context())

    def test_cannot_create_v2_contract_with_v1_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V1)

        msg = 'cannot call blueprints across token amount versions (tx = 1, blueprint = 2)'
        with pytest.raises(NCFail, match=re.escape(msg)):
            runner.create_contract(self.contract_id2, self.blueprint_id2, self.create_context())

    def test_can_call_v1_public_method_with_v1_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V1)
        runner.create_contract(self.contract_id1, self.blueprint_id1, self.create_context())
        assert runner.call_public_method(self.contract_id1, 'public_nop', self.create_context()) is None

    def test_can_call_v2_public_method_with_v2_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)
        runner.create_contract(self.contract_id2, self.blueprint_id2, self.create_context())
        assert runner.call_public_method(self.contract_id2, 'public_nop', self.create_context()) is None

    def test_cannot_call_v1_public_method_with_v2_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V1)
        runner.create_contract(self.contract_id1, self.blueprint_id1, self.create_context())
        runner._runner.token_amount_version = TokenAmountVersion.V2

        msg = 'cannot call blueprints across token amount versions (tx = 2, blueprint = 1)'
        with pytest.raises(NCFail, match=re.escape(msg)):
            runner.call_public_method(self.contract_id1, 'public_nop', self.create_context())

    def test_cannot_call_v2_public_method_with_v1_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)
        runner.create_contract(self.contract_id2, self.blueprint_id2, self.create_context())
        runner._runner.token_amount_version = TokenAmountVersion.V1

        msg = 'cannot call blueprints across token amount versions (tx = 1, blueprint = 2)'
        with pytest.raises(NCFail, match=re.escape(msg)):
            runner.call_public_method(self.contract_id2, 'public_nop', self.create_context())

    def test_can_call_v1_view_method_with_v1_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V1)
        runner.create_contract(self.contract_id1, self.blueprint_id1, self.create_context())
        assert runner.call_view_method(self.contract_id1, 'view_nop') is None

    def test_can_call_v2_view_method_with_v2_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)
        runner.create_contract(self.contract_id2, self.blueprint_id2, self.create_context())
        assert runner.call_view_method(self.contract_id2, 'view_nop') is None

    def test_cannot_call_v1_view_method_with_v2_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V1)
        runner.create_contract(self.contract_id1, self.blueprint_id1, self.create_context())
        runner._runner.token_amount_version = TokenAmountVersion.V2

        msg = 'cannot call blueprints across token amount versions (tx = 2, blueprint = 1)'
        with pytest.raises(NCFail, match=re.escape(msg)):
            runner.call_view_method(self.contract_id1, 'view_nop', self.create_context())

    def test_cannot_call_v2_view_method_with_v1_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)
        runner.create_contract(self.contract_id2, self.blueprint_id2, self.create_context())
        runner._runner.token_amount_version = TokenAmountVersion.V1

        msg = 'cannot call blueprints across token amount versions (tx = 1, blueprint = 2)'
        with pytest.raises(NCFail, match=re.escape(msg)):
            runner.call_view_method(self.contract_id2, 'view_nop', self.create_context())

    def test_can_create_another_v1_contract_with_v1_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V1)
        runner.create_contract(self.contract_id1, self.blueprint_id1, self.create_context())
        assert runner.call_public_method(
            self.contract_id1, 'create_another', self.create_context(), self.blueprint_id1
        ) is None

    def test_can_create_another_v2_contract_with_v2_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)
        runner.create_contract(self.contract_id2, self.blueprint_id2, self.create_context())
        assert runner.call_public_method(
            self.contract_id2, 'create_another', self.create_context(), self.blueprint_id2
        ) is None

    def test_cannot_create_another_v2_contract_with_v1_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V1)
        runner.create_contract(self.contract_id1, self.blueprint_id1, self.create_context())

        msg = 'cannot call blueprints across token amount versions (tx = 1, blueprint = 2)'
        with pytest.raises(NCFail, match=re.escape(msg)):
            runner.call_public_method(self.contract_id1, 'create_another', self.create_context(), self.blueprint_id2)

    def test_cannot_create_another_v1_contract_with_v2_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)
        runner.create_contract(self.contract_id2, self.blueprint_id2, self.create_context())

        msg = 'cannot call blueprints across token amount versions (tx = 2, blueprint = 1)'
        with pytest.raises(NCFail, match=re.escape(msg)):
            runner.call_public_method(self.contract_id2, 'create_another', self.create_context(), self.blueprint_id1)

    def test_can_call_another_v1_public_method_with_v1_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V1)
        other_contract_id = self.gen_random_contract_id()
        runner.create_contract(self.contract_id1, self.blueprint_id1, self.create_context())
        runner.create_contract(other_contract_id, self.blueprint_id1, self.create_context())
        assert runner.call_public_method(
            self.contract_id1, 'call_another_public', self.create_context(), other_contract_id
        ) is None

    def test_can_call_another_v2_public_method_with_v2_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)
        other_contract_id = self.gen_random_contract_id()
        runner.create_contract(self.contract_id2, self.blueprint_id2, self.create_context())
        runner.create_contract(other_contract_id, self.blueprint_id2, self.create_context())
        assert runner.call_public_method(
            self.contract_id2, 'call_another_public', self.create_context(), other_contract_id
        ) is None

    def test_cannot_call_another_v2_public_method_with_v1_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V1)
        runner.create_contract(self.contract_id1, self.blueprint_id1, self.create_context())
        runner._runner.token_amount_version = TokenAmountVersion.V2
        runner.create_contract(self.contract_id2, self.blueprint_id2, self.create_context())
        runner._runner.token_amount_version = TokenAmountVersion.V1

        msg = 'cannot call blueprints across token amount versions (tx = 1, blueprint = 2)'
        with pytest.raises(NCFail, match=re.escape(msg)):
            runner.call_public_method(
                self.contract_id1, 'call_another_public', self.create_context(), self.contract_id2
            )

    def test_cannot_call_another_v1_public_method_with_v2_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)
        runner.create_contract(self.contract_id2, self.blueprint_id2, self.create_context())
        runner._runner.token_amount_version = TokenAmountVersion.V1
        runner.create_contract(self.contract_id1, self.blueprint_id1, self.create_context())
        runner._runner.token_amount_version = TokenAmountVersion.V2

        msg = 'cannot call blueprints across token amount versions (tx = 2, blueprint = 1)'
        with pytest.raises(NCFail, match=re.escape(msg)):
            runner.call_public_method(
                self.contract_id2, 'call_another_public', self.create_context(), self.contract_id1
            )

    def test_can_call_another_v1_view_method_with_v1_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V1)
        other_contract_id = self.gen_random_contract_id()
        runner.create_contract(self.contract_id1, self.blueprint_id1, self.create_context())
        runner.create_contract(other_contract_id, self.blueprint_id1, self.create_context())
        assert runner.call_view_method(self.contract_id1, 'call_another_view', other_contract_id) is None

    def test_can_call_another_v2_view_method_with_v2_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)
        other_contract_id = self.gen_random_contract_id()
        runner.create_contract(self.contract_id2, self.blueprint_id2, self.create_context())
        runner.create_contract(other_contract_id, self.blueprint_id2, self.create_context())
        assert runner.call_view_method(self.contract_id2, 'call_another_view', other_contract_id) is None

    def test_cannot_call_another_v2_view_method_with_v1_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V1)
        runner.create_contract(self.contract_id1, self.blueprint_id1, self.create_context())
        runner._runner.token_amount_version = TokenAmountVersion.V2
        runner.create_contract(self.contract_id2, self.blueprint_id2, self.create_context())
        runner._runner.token_amount_version = TokenAmountVersion.V1

        msg = 'cannot call blueprints across token amount versions (tx = 1, blueprint = 2)'
        with pytest.raises(NCFail, match=re.escape(msg)):
            runner.call_view_method(self.contract_id1, 'call_another_view', self.contract_id2)

    def test_cannot_call_another_v1_view_method_with_v2_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)
        runner.create_contract(self.contract_id2, self.blueprint_id2, self.create_context())
        runner._runner.token_amount_version = TokenAmountVersion.V1
        runner.create_contract(self.contract_id1, self.blueprint_id1, self.create_context())
        runner._runner.token_amount_version = TokenAmountVersion.V2

        msg = 'cannot call blueprints across token amount versions (tx = 2, blueprint = 1)'
        with pytest.raises(NCFail, match=re.escape(msg)):
            runner.call_view_method(self.contract_id2, 'call_another_view', self.contract_id1)

    def test_can_call_proxy_v1_public_method_with_v1_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V1)
        other_blueprint_id = self._register_blueprint_class(MyBlueprint, token_amount_version=TokenAmountVersion.V1)
        runner.create_contract(self.contract_id1, self.blueprint_id1, self.create_context())
        assert runner.call_public_method(
            self.contract_id1, 'call_proxy_public', self.create_context(), other_blueprint_id
        ) is None

    def test_can_call_proxy_v2_public_method_with_v2_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)
        other_blueprint_id = self._register_blueprint_class(MyBlueprint, token_amount_version=TokenAmountVersion.V2)
        runner.create_contract(self.contract_id2, self.blueprint_id2, self.create_context())
        assert runner.call_public_method(
            self.contract_id2, 'call_proxy_public', self.create_context(), other_blueprint_id
        ) is None

    def test_cannot_call_proxy_v2_public_method_with_v1_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V1)
        runner.create_contract(self.contract_id1, self.blueprint_id1, self.create_context())

        msg = 'cannot call blueprints across token amount versions (tx = 1, blueprint = 2)'
        with pytest.raises(NCFail, match=re.escape(msg)):
            runner.call_public_method(
                self.contract_id1, 'call_proxy_public', self.create_context(), self.blueprint_id2
            )

    def test_cannot_call_proxy_v1_public_method_with_v2_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)
        runner.create_contract(self.contract_id2, self.blueprint_id2, self.create_context())

        msg = 'cannot call blueprints across token amount versions (tx = 2, blueprint = 1)'
        with pytest.raises(NCFail, match=re.escape(msg)):
            runner.call_public_method(
                self.contract_id2, 'call_proxy_public', self.create_context(), self.blueprint_id1
            )

    def test_can_call_proxy_v1_view_method_with_v1_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V1)
        other_blueprint_id = self._register_blueprint_class(MyBlueprint, token_amount_version=TokenAmountVersion.V1)
        runner.create_contract(self.contract_id1, self.blueprint_id1, self.create_context())
        assert runner.call_view_method(self.contract_id1, 'call_proxy_view', other_blueprint_id) is None

    def test_can_call_proxy_v2_view_method_with_v2_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)
        other_blueprint_id = self._register_blueprint_class(MyBlueprint, token_amount_version=TokenAmountVersion.V2)
        runner.create_contract(self.contract_id2, self.blueprint_id2, self.create_context())
        assert runner.call_view_method(self.contract_id2, 'call_proxy_view', other_blueprint_id) is None

    def test_cannot_call_proxy_v2_view_method_with_v1_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V1)
        runner.create_contract(self.contract_id1, self.blueprint_id1, self.create_context())

        msg = 'cannot call blueprints across token amount versions (tx = 1, blueprint = 2)'
        with pytest.raises(NCFail, match=re.escape(msg)):
            runner.call_view_method(self.contract_id1, 'call_proxy_view', self.blueprint_id2)

    def test_cannot_call_proxy_v1_view_method_with_v2_runner(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)
        runner.create_contract(self.contract_id2, self.blueprint_id2, self.create_context())

        msg = 'cannot call blueprints across token amount versions (tx = 2, blueprint = 1)'
        with pytest.raises(NCFail, match=re.escape(msg)):
            runner.call_view_method(self.contract_id2, 'call_proxy_view', self.blueprint_id1)

    def test_can_change_blueprint_from_v1_to_v1(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V1)
        other_blueprint_id = self._register_blueprint_class(MyBlueprint, token_amount_version=TokenAmountVersion.V1)
        runner.create_contract(self.contract_id1, self.blueprint_id1, self.create_context())
        runner.call_public_method(self.contract_id1, 'change_blueprint', self.create_context(), other_blueprint_id)
        assert runner.get_storage(self.contract_id1).get_blueprint_id() == other_blueprint_id

    def test_can_change_blueprint_from_v1_to_v2(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V1)
        runner.create_contract(self.contract_id1, self.blueprint_id1, self.create_context())
        runner.call_public_method(self.contract_id1, 'change_blueprint', self.create_context(), self.blueprint_id2)
        assert runner.get_storage(self.contract_id1).get_blueprint_id() == self.blueprint_id2

    def test_cannot_change_blueprint_from_v2_to_v1(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)
        runner.create_contract(self.contract_id2, self.blueprint_id2, self.create_context())

        msg = 'cannot change blueprint to an older token amount version (current = 2, new = 1)'
        with pytest.raises(NCFail, match=re.escape(msg)):
            runner.call_public_method(
                self.contract_id2, 'change_blueprint', self.create_context(), self.blueprint_id1
            )

    def test_can_change_blueprint_from_v2_to_v2(self) -> None:
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)
        other_blueprint_id = self._register_blueprint_class(MyBlueprint, token_amount_version=TokenAmountVersion.V2)
        runner.create_contract(self.contract_id2, self.blueprint_id2, self.create_context())
        runner.call_public_method(self.contract_id2, 'change_blueprint', self.create_context(), other_blueprint_id)
        assert runner.get_storage(self.contract_id2).get_blueprint_id() == other_blueprint_id

    def test_update_blueprint_then_call_other_v1(self) -> None:
        """Updating a blueprint does not change its runtime version, therefore a call to a V1 blueprint works."""
        runner_v1 = self.build_runner(token_amount_version=TokenAmountVersion.V1)
        other_v1 = self.gen_random_contract_id()
        runner_v1.create_contract(self.contract_id1, self.blueprint_id1, self.create_context())
        runner_v1.create_contract(other_v1, self.blueprint_id1, self.create_context())

        runner_v1.call_public_method(
            self.contract_id1,
            'change_blueprint_then_call_other',
            self.create_context(),
            self.blueprint_id2,
            other_v1,
        )
        assert runner_v1.get_storage(self.contract_id1).get_blueprint_id() == self.blueprint_id2

    def test_update_blueprint_then_call_other_v2(self) -> None:
        """Updating a blueprint does not change its runtime version, therefore a call to a V2 blueprint fails."""
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)
        runner.create_contract(self.contract_id2, self.blueprint_id2, self.create_context())
        runner._runner.token_amount_version = TokenAmountVersion.V1
        runner.create_contract(self.contract_id1, self.blueprint_id1, self.create_context())

        msg = 'cannot call blueprints across token amount versions (tx = 1, blueprint = 2)'
        with pytest.raises(NCFail, match=re.escape(msg)):
            runner.call_public_method(
                self.contract_id1,
                'change_blueprint_then_call_other',
                self.create_context(),
                self.blueprint_id2,
                self.contract_id2,
            )

        assert runner.get_storage(self.contract_id1).get_blueprint_id() == self.blueprint_id1

