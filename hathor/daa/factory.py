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
    _get_base_tokens_issued_per_block,
    _get_mined_tokens,
    _get_weight_decay_amount,
    _minimum_tx_weight,
)
from hathor.daa.daa import DifficultyAdjustmentAlgorithm

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.feature_activation.feature_service import FeatureService
    from hathor.transaction import Block, Transaction


class DAAFactory:
    """Builds ``DifficultyAdjustmentAlgorithm`` instances configured for a given context.

    Carries the dispatch context (settings, feature_service) once, and offers factory methods
    (``create_from_block``, ``create_from_parent``, ``create_v1``) that return a DAA configured
    for that context. ``feature_service`` is kept in the constructor surface so future
    feature-gated DAA versions can plug into ``_select_config`` without changing every call
    site.

    The ``TEST_MODE`` and ``MIN_BLOCK_WEIGHT`` fields are mutable and propagate to every
    DAA created after they are set — matching the previous facade behavior used by tests.
    """

    # TODO: This singleton is temporary, and only used in Peer. It should be removed from there, and then from here.
    singleton: ClassVar[Optional['DAAFactory']] = None

    __slots__ = ('_settings', '_feature_service', 'TEST_MODE', 'MIN_BLOCK_WEIGHT')

    def __init__(
        self,
        *,
        settings: HathorSettings,
        feature_service: FeatureService | None = None,
        test_mode: TestMode = TestMode.DISABLED,
    ) -> None:
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
        """Build a DAA with the V1 config."""
        return self._build(DAAConfig.for_v1(self._settings))

    def create_from_parent(self, parent_block: Block) -> DifficultyAdjustmentAlgorithm:
        """Build a DAA with the version that applies to a block whose parent is `parent_block`.

        Currently always returns V1 — the seam exists so future feature-gated versions can
        select a different ``DAAConfig`` based on the parent's feature state.
        """
        return self._build(self._select_config(parent_block))

    def create_from_block(self, block: Block) -> DifficultyAdjustmentAlgorithm:
        """Build a DAA for `block` — selection uses its parent's feature state."""
        if block.is_genesis:
            return self.create_v1()
        return self.create_from_parent(block.get_block_parent())

    def _select_config(self, parent_block: Block) -> DAAConfig:
        # Currently V1-only. Future feature-gated DAA versions plug in here.
        return DAAConfig.for_v1(self._settings)

    # Block-independent helpers — exposed on the factory so callers don't have to construct
    # a per-block DAA just to compute a value that doesn't depend on which version applies.

    def minimum_tx_weight(self, tx: Transaction) -> float:
        """Return the minimum weight for `tx`. Independent of the DAA version."""
        return _minimum_tx_weight(self._settings, tx, self.TEST_MODE)

    def get_weight_decay_amount(self, distance: int) -> float:
        """Return the amount to be reduced in the weight of the block. Independent of the DAA version."""
        return _get_weight_decay_amount(self._settings, distance)

    def get_tokens_issued_per_block(self, height: int) -> int:
        """Return the number of tokens issued (aka reward) per block of a given height."""
        return _get_base_tokens_issued_per_block(self._settings, height)

    def get_reward_for_next_block(self, parent_block: Block) -> int:
        """Return the reward for the next block after `parent_block`."""
        return self.get_tokens_issued_per_block(parent_block.get_height() + 1)

    def get_mined_tokens(self, height: int) -> int:
        """Return the number of tokens mined in total at height."""
        return _get_mined_tokens(self._settings, height)
