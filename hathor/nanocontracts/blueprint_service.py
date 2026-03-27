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

from hathor.conf.settings import HathorSettings
from hathor.feature_activation.feature_service import FeatureService
from hathor.nanocontracts import OnChainBlueprint
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.exception import (
    BlueprintDoesNotExist,
    OCBBlueprintNotConfirmed,
    OCBInvalidBlueprintVertexType,
)
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathorlib.nanocontracts.types import BlueprintId

if TYPE_CHECKING:
    from hathor import Blueprint

logger = get_logger()


class BlueprintService:
    __slots__ = ('log', 'settings', 'nc_catalog', 'tx_storage', 'feature_service')

    def __init__(
        self,
        *,
        settings: HathorSettings,
        tx_storage: TransactionStorage,
        feature_service: FeatureService,
    ) -> None:
        self.log = logger.new()
        self.settings = settings
        self.nc_catalog = NCBlueprintCatalog()
        self.tx_storage = tx_storage
        self.feature_service = feature_service

        if settings.ENABLE_NANO_CONTRACTS:
            blueprints = NCBlueprintCatalog.generate_blueprints_from_settings(settings)
            self.register_blueprints(blueprints)

    def get_on_chain_blueprint(self, blueprint_id: BlueprintId) -> OnChainBlueprint:
        """Return an on-chain blueprint transaction."""
        try:
            blueprint_tx = self.tx_storage.get_transaction(blueprint_id)
        except TransactionDoesNotExist:
            self.log.debug('no transaction with the given id found', blueprint_id=blueprint_id.hex())
            raise BlueprintDoesNotExist(blueprint_id.hex())
        if not isinstance(blueprint_tx, OnChainBlueprint):
            raise OCBInvalidBlueprintVertexType(blueprint_id.hex())
        tx_meta = blueprint_tx.get_metadata()
        if tx_meta.voided_by or not tx_meta.first_block:
            raise OCBBlueprintNotConfirmed(blueprint_id.hex())
        # XXX: maybe use N blocks confirmation, like reward-locks
        return blueprint_tx

    def get_blueprint_class(self, blueprint_id: BlueprintId) -> type[Blueprint]:
        """Returns the blueprint class associated with the given blueprint_id.

        The blueprint class could be in the catalog (first search), or it could be the tx_id of an on-chain blueprint.
        """
        from hathor.nanocontracts import OnChainBlueprint
        blueprint = self._get_blueprint(blueprint_id)
        if isinstance(blueprint, OnChainBlueprint):
            return blueprint.get_blueprint_class()
        else:
            return blueprint

    def get_blueprint_source(self, blueprint_id: BlueprintId) -> str:
        """Returns the source code associated with the given blueprint_id.

        The blueprint class could be in the catalog (first search), or it could be the tx_id of an on-chain blueprint.
        """
        import inspect

        from hathor.nanocontracts import OnChainBlueprint

        blueprint = self._get_blueprint(blueprint_id)
        if isinstance(blueprint, OnChainBlueprint):
            return self.get_on_chain_blueprint(blueprint_id).code.text
        else:
            module = inspect.getmodule(blueprint)
            assert module is not None
            return inspect.getsource(module)

    def _get_blueprint(self, blueprint_id: BlueprintId) -> type[Blueprint] | OnChainBlueprint:
        if blueprint_class := self.nc_catalog.get_blueprint_class(blueprint_id):
            return blueprint_class

        self.log.debug(
            'blueprint_id not in the catalog, looking for on-chain blueprint',
            blueprint_id=blueprint_id.hex()
        )
        return self.get_on_chain_blueprint(blueprint_id)

    def register_blueprint(self, blueprint_id: bytes, blueprint: type[Blueprint], *, strict: bool = False) -> None:
        """Register a single blueprint in the catalog."""
        self.nc_catalog.register_blueprints({blueprint_id: blueprint}, strict=strict)

    def register_blueprints(self, blueprints: dict[bytes, type[Blueprint]], *, strict: bool = False) -> None:
        """Register multiple blueprints in the catalog."""
        self.nc_catalog.register_blueprints(blueprints, strict=strict)
