from hathor.manager import HathorManager
from hathor.nanocontracts import Blueprint, OnChainBlueprint
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.types import BlueprintId
from hathor_tests.resources.base_resource import _BaseResourceTest


class GenericNanoResourceTest(_BaseResourceTest._ResourceTest):
    __test__ = False

    def create_builtin_blueprint(
        self,
        manager: HathorManager,
        blueprint_id: BlueprintId,
        blueprint_class: type[Blueprint],
    ) -> None:
        manager.tx_storage.nc_catalog = NCBlueprintCatalog({
            blueprint_id: blueprint_class,
        })

    def create_on_chain_blueprint(self, manager: HathorManager, nc_code: str) -> OnChainBlueprint:
        from hathor.nanocontracts.on_chain_blueprint import Code
        from hathor_tests.nanocontracts.on_chain_blueprints.utils import get_ocb_private_key
        code = Code.from_python_code(nc_code, self._settings)
        timestamp = manager.tx_storage.latest_timestamp + 1
        parents = manager.get_new_tx_parents(timestamp)
        blueprint = OnChainBlueprint(
            weight=1,
            inputs=[],
            outputs=[],
            parents=parents,
            storage=manager.tx_storage,
            timestamp=timestamp,
            code=code,
        )
        blueprint.weight = manager.daa.minimum_tx_weight(blueprint)
        blueprint.sign(get_ocb_private_key())
        manager.cpu_mining_service.resolve(blueprint)
        manager.reactor.advance(2)  # type: ignore
        return blueprint
