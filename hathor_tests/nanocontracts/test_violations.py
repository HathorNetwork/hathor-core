from hathor.nanocontracts import Blueprint, public
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.types import NCDepositAction
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


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
        context = self.create_context(
            actions=[],
            vertex=self.tx,
            caller_id=self.address,
            timestamp=self.now
        )
        self.runner.create_contract(self.contract_id, self.blueprint_id, context)

        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(self.contract_id, 'modify_actions', context)
        exc = cm.exception
        self.assertIsInstance(exc.__cause__, TypeError)

    def test_modify_vertex(self) -> None:
        context = self.create_context(
            actions=[],
            vertex=self.tx,
            caller_id=self.address,
            timestamp=self.now
        )
        self.runner.create_contract(self.contract_id, self.blueprint_id, context)
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(self.contract_id, 'modify_vertex', context)
        exc = cm.exception
        self.assertIsInstance(exc.__cause__, TypeError)

    def test_assign_non_declared_attribute(self) -> None:
        context = self.create_context(
            actions=[],
            vertex=self.tx,
            caller_id=self.address,
            timestamp=self.now
        )
        self.runner.create_contract(self.contract_id, self.blueprint_id, context)
        self.runner.call_public_method(self.contract_id, 'assign_declared_attribute', context)
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(self.contract_id, 'assign_non_declared_attribute', context)
        exc = cm.exception
        self.assertIsInstance(exc.__cause__, AttributeError)
