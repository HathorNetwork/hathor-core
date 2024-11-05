from hathor.nanocontracts import Blueprint, public
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.types import NCAction, NCActionType
from tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class MyBlueprint(Blueprint):
    total: int
    token_uid: bytes
    counter: int

    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def modify_actions(self, ctx: Context) -> None:
        ctx.actions[b'\00'] = NCAction(NCActionType.DEPOSIT, b'\00', 1_000)  # type: ignore

    @public
    def modify_vertex(self, ctx: Context) -> None:
        ctx.vertex.inputs[0] = None  # type: ignore


class ViolationsTestCase(BlueprintTestCase):
    def setUp(self):
        super().setUp()

        self.contract_id = self.gen_random_nanocontract_id()
        self.runner.register_contract(MyBlueprint, self.contract_id)
        self.nc_storage = self.runner.get_storage(self.contract_id)
        self.tx = self.get_genesis_tx()
        self.address = self.gen_random_address()

    def test_modify_actions(self) -> None:
        context = Context(
            actions=[],
            vertex=self.tx,
            address=self.address,
            timestamp=self.now
        )
        self.runner.call_public_method(self.contract_id, 'initialize', context)

        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(self.contract_id, 'modify_actions', context)
        exc = cm.exception
        self.assertIsInstance(exc.__cause__, TypeError)

    def test_modify_vertex(self) -> None:
        context = Context(
            actions=[],
            vertex=self.tx,
            address=self.address,
            timestamp=self.now
        )
        self.runner.call_public_method(self.contract_id, 'initialize', context)
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(self.contract_id, 'modify_vertex', context)
        exc = cm.exception
        self.assertIsInstance(exc.__cause__, TypeError)
