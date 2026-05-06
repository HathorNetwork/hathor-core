# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""DAAFactory: builds DifficultyAdjustmentAlgorithm instances with the right config for a block."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Optional

from hathor.daa.common import (
    DAAConfig,
    TestMode,
    _get_weight_decay_amount,
    _minimum_tx_weight,
)
from hathor.daa.daa import DifficultyAdjustmentAlgorithm
from hathor.feature_activation.feature import Feature

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.feature_activation.feature_service import FeatureService
    from hathor.transaction import Block, Transaction


class DAAFactory:
    """Builds ``DifficultyAdjustmentAlgorithm`` instances with the right config for a block.

    Carries the dispatch context (settings, feature_service) once, and offers factory methods
    (``create_from_block``, ``create_from_parent``, ``create_v1``, ``create_v2``) that return
    a DAA configured for that context.

    The ``TEST_MODE`` and ``MIN_BLOCK_WEIGHT`` fields are mutable and propagate to every
    DAA created after they are set — matching the previous facade behavior used by tests.

    Version-INDEPENDENT helpers (``minimum_tx_weight``, ``get_weight_decay_amount``) are
    exposed directly on the factory so callers don't have to construct a per-block DAA
    just to compute a value that doesn't depend on which version applies.
    """

    # TODO: This singleton is temporary, and only used in Peer. It should be removed from there, and then from here.
    singleton: ClassVar[Optional['DAAFactory']] = None

    # Networks where TEST_MODE may bypass weight verification. Anywhere else
    # (mainnet, testnet-*, nano-testnet-*) requires TEST_MODE.DISABLED.
    _TEST_MODE_NETWORKS: ClassVar[frozenset[str]] = frozenset({'unittests', 'privatenet'})

    __slots__ = ('_settings', '_feature_service', 'TEST_MODE', 'MIN_BLOCK_WEIGHT')

    def __init__(
        self,
        *,
        settings: HathorSettings,
        feature_service: FeatureService | None = None,
        test_mode: TestMode = TestMode.DISABLED,
    ) -> None:
        assert test_mode == TestMode.DISABLED or settings.NETWORK_NAME in self._TEST_MODE_NETWORKS, (
            f'TEST_MODE must be DISABLED on production networks (got {test_mode!r} on '
            f'{settings.NETWORK_NAME!r}); only allowed on {sorted(self._TEST_MODE_NETWORKS)}'
        )
        self._settings = settings
        self._feature_service = feature_service
        self.TEST_MODE = test_mode
        self.MIN_BLOCK_WEIGHT: int = settings.MIN_BLOCK_WEIGHT
        DAAFactory.singleton = self

    def _build(self, config: DAAConfig) -> DifficultyAdjustmentAlgorithm:
        return DifficultyAdjustmentAlgorithm(
            settings=self._settings,
            config=config,
            test_mode=self.TEST_MODE,
            min_block_weight=self.MIN_BLOCK_WEIGHT,
        )

    def create_v1(self) -> DifficultyAdjustmentAlgorithm:
        """Build a DAA with the V1 config.

        Use this for code paths without a feature_service wired (CLI tools, the
        dag_builder's V1-only mode) — production paths that need feature-aware
        selection should go through ``create_from_block`` / ``create_from_parent``.
        """
        return self._build(DAAConfig.for_v1(self._settings))

    def create_v2(self, *, v2_start_height: int | None = None) -> DifficultyAdjustmentAlgorithm:
        """Build a DAA with the V2 config.

        ``v2_start_height`` — the height of the first V2 block — is required for
        ``get_mined_tokens`` (otherwise it asserts). It is *not* required for the per-block
        methods (``get_tokens_issued_per_block`` etc.), so callers that only need those can
        omit it. The factory's own ``create_from_parent`` always supplies it.
        """
        return self._build(DAAConfig.for_v2(self._settings, v2_start_height=v2_start_height))

    def create_from_parent(self, parent_block: Block) -> DifficultyAdjustmentAlgorithm:
        """Build a DAA with the version that applies to a block whose parent is `parent_block`.

        Shape B semantics: V2 takes effect on the block AFTER the activation block.

        Production-only: requires ``feature_service`` to be wired, and ``parent_block``
        to carry static metadata. CLI/synthetic-block paths must call ``create_v1``
        directly instead.
        """
        return self._build(self._select_config(parent_block))

    def create_from_block(self, block: Block) -> DifficultyAdjustmentAlgorithm:
        """Build a DAA for `block` — selection uses its parent's feature state.

        Genesis falls back to V1; otherwise see ``create_from_parent``'s preconditions.
        """
        if block.is_genesis:
            return self.create_v1()
        return self.create_from_parent(block.get_block_parent())

    def _select_config(self, parent_block: Block) -> DAAConfig:
        assert self._feature_service is not None, (
            'create_from_block/create_from_parent require a feature_service; '
            'use create_v1() directly for code paths without one'
        )
        assert parent_block._static_metadata is not None, (
            'create_from_block/create_from_parent require parent_block to carry static metadata; '
            'use create_v1() directly for synthetic blocks'
        )
        if not self._feature_service.is_feature_active(vertex=parent_block, feature=Feature.REDUCE_DAA_TARGET):
            return DAAConfig.for_v1(self._settings)
        activation_height = self._feature_service.get_activation_height(
            block=parent_block, feature=Feature.REDUCE_DAA_TARGET,
        )
        assert activation_height is not None, 'feature_service.is_feature_active=True must imply an activation height'
        # Shape B: first V2 block is the one immediately after the activation block.
        return DAAConfig.for_v2(self._settings, v2_start_height=activation_height + 1)

    # Block-independent helpers — exposed on the factory so callers don't have to construct
    # a per-block DAA just to compute a value that doesn't depend on which version applies.

    def minimum_tx_weight(self, tx: Transaction) -> float:
        """Return the minimum weight for `tx`. Independent of the DAA version."""
        return _minimum_tx_weight(self._settings, tx, self.TEST_MODE)

    def get_weight_decay_amount(self, distance: int) -> float:
        """Return the amount to be reduced in the weight of the block. Independent of the DAA version."""
        return _get_weight_decay_amount(self._settings, distance)
