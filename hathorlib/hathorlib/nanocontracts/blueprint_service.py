
#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from __future__ import annotations

from typing import TYPE_CHECKING

from structlog import get_logger

from hathorlib.nanocontracts.catalog import NCBlueprintCatalog
from hathorlib.nanocontracts.tx_storage_protocol import NCTransactionStorageProtocol
from hathorlib.nanocontracts.types import BlueprintId

if TYPE_CHECKING:
    from hathorlib.conf.settings import HathorSettings
    from hathorlib.nanocontracts.blueprint import Blueprint

logger = get_logger()


class BlueprintService:
    __slots__ = ('log', 'settings', 'nc_catalog', 'tx_storage')

    def __init__(
        self,
        *,
        settings: HathorSettings,
        tx_storage: NCTransactionStorageProtocol,
    ) -> None:
        self.log = logger.new()
        self.settings = settings
        self.nc_catalog = NCBlueprintCatalog()
        self.tx_storage = tx_storage

        if settings.ENABLE_NANO_CONTRACTS:
            blueprints = NCBlueprintCatalog.generate_blueprints_from_settings(settings)
            self.register_blueprints(blueprints)

    def get_blueprint_class(self, blueprint_id: BlueprintId) -> type[Blueprint]:
        """Returns the blueprint class associated with the given blueprint_id.

        The blueprint class could be in the catalog (first search), or it could be the tx_id of an on-chain blueprint.
        """
        if blueprint_class := self.nc_catalog.get_blueprint_class(blueprint_id):
            return blueprint_class

        return self.tx_storage.get_blueprint_class(blueprint_id)

    def get_blueprint_source(self, blueprint_id: BlueprintId) -> str:
        """Returns the source code associated with the given blueprint_id.

        The blueprint class could be in the catalog (first search), or it could be the tx_id of an on-chain blueprint.
        """
        import inspect

        if blueprint_class := self.nc_catalog.get_blueprint_class(blueprint_id):
            module = inspect.getmodule(blueprint_class)
            assert module is not None
            return inspect.getsource(module)

        return self.tx_storage.get_blueprint_source(blueprint_id)

    def register_blueprint(self, blueprint_id: bytes, blueprint: type[Blueprint], *, strict: bool = False) -> None:
        """Register a single blueprint in the catalog."""
        self.nc_catalog.register_blueprints({blueprint_id: blueprint}, strict=strict)

    def register_blueprints(self, blueprints: dict[bytes, type[Blueprint]], *, strict: bool = False) -> None:
        """Register multiple blueprints in the catalog."""
        self.nc_catalog.register_blueprints(blueprints, strict=strict)
