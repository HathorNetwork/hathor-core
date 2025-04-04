from typing import Optional

from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.types import BlueprintId, ContractId, public
from tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class MyBlueprint(Blueprint):
    my_nc_id: ContractId
    my_blueprint_id: BlueprintId

    other_nc_id: Optional[ContractId]
    other_blueprint_id: Optional[BlueprintId]

    @public
    def initialize(self, ctx: Context, other_nc_id: ContractId) -> None:
        self.my_nc_id = self.get_contract_id()
        self.my_blueprint_id = self.get_blueprint_id()

        self.other_nc_id = other_nc_id
        self.other_blueprint_id = self.get_blueprint_id(other_nc_id)


class OtherBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass


class NCNanoContractTestCase(BlueprintTestCase):
    def test_basics(self) -> None:
        my_blueprint_id = self.gen_random_blueprint_id()
        other_blueprint_id = self.gen_random_blueprint_id()

        self.nc_catalog.blueprints[my_blueprint_id] = MyBlueprint
        self.nc_catalog.blueprints[other_blueprint_id] = OtherBlueprint

        nc1_id = self.gen_random_nanocontract_id()
        nc2_id = self.gen_random_nanocontract_id()

        tx = self.get_genesis_tx()

        ctx = Context([], tx, b'', timestamp=0)
        self.runner.create_contract(nc1_id, other_blueprint_id, ctx)
        self.runner.create_contract(nc2_id, my_blueprint_id, ctx, nc1_id)

        storage2 = self.runner.get_storage(nc2_id)

        assert storage2.get('my_nc_id') == nc2_id
        assert storage2.get('other_nc_id') == nc1_id

        assert storage2.get('my_blueprint_id') == my_blueprint_id
        assert storage2.get('other_blueprint_id') == other_blueprint_id
