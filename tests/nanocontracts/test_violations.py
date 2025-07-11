import pytest

from hathor.nanocontracts import Blueprint, public
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCUnhandledUserException
from hathor.nanocontracts.types import NCDepositAction
from tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class MyBlueprint(Blueprint):
    total: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.total = 3

    @public
    def modify_actions(self, ctx: Context) -> None:
        ctx.actions[b'\00'] = NCDepositAction(token_uid=b'\00', amount=1_000)  # type: ignore

    @public
    def modify_vertex(self, ctx: Context) -> None:
        ctx.vertex.inputs[0] = None  # type: ignore

    @public
    def assign_declared_attribute(self, ctx: Context) -> None:
        self.total += 1

    @public
    def assign_non_declared_attribute(self, ctx: Context) -> None:
        self.unknown = 1


class ViolationsTestCase(BlueprintTestCase):
    def setUp(self):
        super().setUp()

        self.blueprint_id = self.gen_random_blueprint_id()
        self.contract_id = self.gen_random_contract_id()
        self.nc_catalog.blueprints[self.blueprint_id] = MyBlueprint
        self.tx = self.get_genesis_tx()
        self.address = self.gen_random_address()

    def test_modify_actions(self) -> None:
        context = Context(
            actions=[],
            vertex=self.tx,
            address=self.address,
            timestamp=self.now
        )
        self.runner.create_contract(self.contract_id, self.blueprint_id, context)

        with pytest.raises(NCUnhandledUserException) as e:
            self.runner.call_public_method(self.contract_id, 'modify_actions', context)
        assert isinstance(e.value.__cause__, TypeError)
        assert e.value.__cause__.args[0] == "'mappingproxy' object does not support item assignment"

    def test_modify_vertex(self) -> None:
        context = Context(
            actions=[],
            vertex=self.tx,
            address=self.address,
            timestamp=self.now
        )
        self.runner.create_contract(self.contract_id, self.blueprint_id, context)
        with pytest.raises(NCUnhandledUserException) as e:
            self.runner.call_public_method(self.contract_id, 'modify_vertex', context)
        assert isinstance(e.value.__cause__, TypeError)
        assert e.value.__cause__.args[0] == "'tuple' object does not support item assignment"

    def test_assign_non_declared_attribute(self) -> None:
        context = Context(
            actions=[],
            vertex=self.tx,
            address=self.address,
            timestamp=self.now
        )
        self.runner.create_contract(self.contract_id, self.blueprint_id, context)
        self.runner.call_public_method(self.contract_id, 'assign_declared_attribute', context)
        with pytest.raises(NCUnhandledUserException) as e:
            self.runner.call_public_method(self.contract_id, 'assign_non_declared_attribute', context)
        assert isinstance(e.value.__cause__, AttributeError)
        assert e.value.__cause__.args[0] == "'MyBlueprint' object has no attribute 'unknown'"
