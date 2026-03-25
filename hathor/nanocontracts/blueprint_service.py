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

import inspect
from typing import TYPE_CHECKING

from structlog import get_logger

from hathor.conf.settings import HathorSettings
from hathor.feature_activation.feature_service import FeatureService
from hathor.feature_activation.utils import Features
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
from hathorlib.nanocontracts.versions import BlueprintVersion

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
        blueprint, _ = self.get_blueprint_class_and_version(blueprint_id)
        return blueprint

    def get_blueprint_class_and_version(self, blueprint_id: BlueprintId) -> tuple[type[Blueprint], BlueprintVersion]:
        if blueprint_and_version := self.nc_catalog.get_blueprint_class_and_version(blueprint_id):
            return blueprint_and_version
        return self._get_ocb_class_and_version(blueprint_id)

    def get_blueprint_source(self, blueprint_id: BlueprintId) -> str:
        """Returns the source code associated with the given blueprint_id.

        The blueprint class could be in the catalog (first search), or it could be the tx_id of an on-chain blueprint.
        """
        if source := self._get_builtin_blueprint_source(blueprint_id):
            return source
        return self._get_ocb_source(blueprint_id)

    def _get_builtin_blueprint_source(self, blueprint_id: BlueprintId) -> str | None:
        if blueprint_and_version := self.nc_catalog.get_blueprint_class_and_version(blueprint_id):
            blueprint_class, _ = blueprint_and_version
            module = inspect.getmodule(blueprint_class)
            assert module is not None
            return inspect.getsource(module)

        return None

    def _get_ocb_class_and_version(self, blueprint_id: BlueprintId) -> tuple[type[Blueprint], BlueprintVersion]:
        ocb = self.get_on_chain_blueprint(blueprint_id)
        first_block_hash = ocb.get_metadata().first_block
        assert first_block_hash is not None
        first_block = self.tx_storage.get_block(first_block_hash)
        first_block_parent = first_block.get_block_parent()

        # We get the feature state of the first_block's parent instead of the OCB transaction itself (which
        # would use the closest ancestor block), so we don't depend on block rewards being spent by miners.
        # This is safe to do here because the OCB class is by definition only available after it is confirmed,
        # and also because a change of first_block can only be caused by a reorg, which would re-execute all
        # nanos that depend on this Blueprint anyway.
        # Considering BlueprintVersion.V2 for example, this means that OCBs deployed before its activation date can be
        # confirmed by either V1 or V2 blocks, but OCBs deployed after the activation date are guaranteed to be V2.
        features = Features.from_vertex(
            settings=self.settings,
            feature_service=self.feature_service,
            vertex=first_block_parent,
        )
        return ocb.get_blueprint_class(), features.blueprint_version

    def _get_ocb_source(self, blueprint_id: BlueprintId) -> str:
        ocb = self.get_on_chain_blueprint(blueprint_id)
        return ocb.code.text

    def register_blueprint(
        self,
        blueprint_id: bytes,
        blueprint: type[Blueprint],
        *,
        strict: bool = False,
        blueprint_version: BlueprintVersion = BlueprintVersion.V1,  # TODO: Change to V2 after all tests are updated
    ) -> None:
        """Register a single blueprint in the catalog."""
        self.nc_catalog.register_blueprints(
            {blueprint_id: blueprint},
            strict=strict,
            blueprint_version=blueprint_version,
        )

    def register_blueprints(self, blueprints: dict[bytes, type[Blueprint]], *, strict: bool = False) -> None:
        """Register multiple blueprints in the catalog."""
        # TODO: Change to V2 after all tests are updated
        self.nc_catalog.register_blueprints(blueprints, strict=strict, blueprint_version=BlueprintVersion.V1)
