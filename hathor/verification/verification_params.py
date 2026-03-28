#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from __future__ import annotations

from dataclasses import dataclass

from hathor.conf.settings import HathorSettings
from hathor.feature_activation.feature_service import FeatureService
from hathor.feature_activation.utils import Features
from hathor.transaction import Block
from hathor.transaction.storage import TransactionStorage


@dataclass(slots=True, frozen=True, kw_only=True)
class VerificationParams:
    """Contains every parameter/setting to run a single verification."""

    nc_block_root_id: bytes | None
    skip_block_weight_verification: bool = False
    features: Features

    @classmethod
    def for_block(
        cls,
        *,
        settings: HathorSettings,
        feature_service: FeatureService,
        block: Block,
    ) -> VerificationParams:
        meta = block.get_metadata()
        features = Features.for_vertex(settings=settings, feature_service=feature_service, vertex=block)
        return cls(nc_block_root_id=meta.nc_block_root_id, features=features)

    @classmethod
    def for_mempool(
        cls,
        *,
        settings: HathorSettings,
        tx_storage: TransactionStorage,
        feature_service: FeatureService,
    ) -> VerificationParams:
        """This is the appropriate parameters for verifying mempool transactions, realtime blocks and API pushes.

        Other cases should instantiate `VerificationParams` manually with the appropriate parameter values.
        """
        best_block = tx_storage.get_best_block()
        meta = best_block.get_metadata()
        if meta.nc_block_root_id is None:
            assert best_block.is_genesis

        features = Features.for_mempool(settings=settings, feature_service=feature_service, best_block=best_block)
        return cls(nc_block_root_id=meta.nc_block_root_id, features=features)

    @classmethod
    def for_apis(cls, tx_storage: TransactionStorage) -> VerificationParams:
        best_block = tx_storage.get_best_block()
        meta = best_block.get_metadata()
        return cls(nc_block_root_id=meta.nc_block_root_id, features=Features.all_enabled())
