# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
    apply_mempool_restrictions: bool = False
    features: Features

    @classmethod
    def for_block(
        cls,
        *,
        settings: HathorSettings,
        feature_service: FeatureService,
        parent_block: Block,
    ) -> VerificationParams:
        """Parameters for verifying blocks entering via sync."""
        parent_meta = parent_block.get_metadata()
        features = Features.for_vertex(settings=settings, feature_service=feature_service, vertex=parent_block)
        return cls(nc_block_root_id=parent_meta.nc_block_root_id, features=features)

    @classmethod
    def for_mempool(
        cls,
        *,
        settings: HathorSettings,
        tx_storage: TransactionStorage,
        feature_service: FeatureService,
    ) -> VerificationParams:
        """Parameters for verifying transactions entering the mempool via mempool sync."""
        best_block, root_id = _get_best_block_root_id(tx_storage)
        features = Features.for_mempool(settings=settings, feature_service=feature_service, best_block=best_block)
        return cls(
            nc_block_root_id=root_id,
            apply_mempool_restrictions=True,
            features=features,
        )

    @classmethod
    def for_relay(
        cls,
        *,
        settings: HathorSettings,
        tx_storage: TransactionStorage,
        feature_service: FeatureService,
    ) -> VerificationParams:
        """Parameters for verifying relayed/locally-created blocks and trusted locally-injected vertices.

        These use the current feature states at the best block but do not apply the mempool-entry restrictions.
        Transactions coming from the network or from APIs must use `for_mempool`/`for_apis` instead.
        """
        best_block, root_id = _get_best_block_root_id(tx_storage)
        features = Features.for_mempool(settings=settings, feature_service=feature_service, best_block=best_block)
        return cls(nc_block_root_id=root_id, features=features)

    @classmethod
    def for_apis(cls, tx_storage: TransactionStorage) -> VerificationParams:
        """Parameters for verifying transactions submitted through public APIs.

        API submissions are mempool-entry points, so they apply the same mempool-entry restrictions
        (`apply_mempool_restrictions`) as `for_mempool`: `verify_old_timestamp`, `verify_tokens`,
        `verify_conflict`, and the nano method-call/seqnum checks. All feature-gated verifications are
        enabled so that submissions are checked against the full feature set.
        """
        _, root_id = _get_best_block_root_id(tx_storage)
        return cls(
            nc_block_root_id=root_id,
            apply_mempool_restrictions=True,
            features=Features.all_enabled(),
        )


def _get_best_block_root_id(tx_storage: TransactionStorage) -> tuple[Block, bytes | None]:
    best_block = tx_storage.get_best_block()
    meta = best_block.get_metadata()
    if meta.nc_block_root_id is None:
        assert best_block.is_genesis
    return best_block, meta.nc_block_root_id
