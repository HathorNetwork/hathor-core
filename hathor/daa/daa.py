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

"""DifficultyAdjustmentAlgorithm: Feature-aware facade that auto-selects V1 or V2."""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable, ClassVar, Optional

from hathor.daa.common import TestMode
from hathor.daa.v1 import DifficultyAdjustmentAlgorithmV1
from hathor.daa.v2 import DifficultyAdjustmentAlgorithmV2
from hathor.types import VertexId

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.feature_activation.feature_service import FeatureService
    from hathor.transaction import Block, Transaction


class DifficultyAdjustmentAlgorithm:
    """Feature-aware facade that auto-selects V1 or V2 based on feature activation state.

    Preserves the existing public API — all callers (BlockVerifier, HathorManager,
    TransactionVerifier, etc.) use this class unchanged.
    """

    # TODO: This singleton is temporary, and only used in Peer. It should be removed from there, and then from here.
    singleton: ClassVar[Optional['DifficultyAdjustmentAlgorithm']] = None

    __slots__ = ('_feature_service', '_v1', '_v2', 'TEST_MODE', 'MIN_BLOCK_WEIGHT')

    def __init__(
        self,
        *,
        settings: HathorSettings,
        feature_service: FeatureService | None = None,
        test_mode: TestMode = TestMode.DISABLED,
    ) -> None:
        self._feature_service = feature_service
        self._v1 = DifficultyAdjustmentAlgorithmV1(settings=settings, test_mode=test_mode)
        self._v2 = DifficultyAdjustmentAlgorithmV2(settings=settings, test_mode=test_mode)
        self.TEST_MODE = test_mode
        self.MIN_BLOCK_WEIGHT = settings.MIN_BLOCK_WEIGHT
        DifficultyAdjustmentAlgorithm.singleton = self

    def _select(self, block: Block) -> DifficultyAdjustmentAlgorithmV1 | DifficultyAdjustmentAlgorithmV2:
        """Select V1 or V2 based on feature activation state for the given block."""
        if self._feature_service is None:
            return self._v1
        from hathor.feature_activation.feature import Feature
        if self._feature_service.is_feature_active(vertex=block, feature=Feature.REDUCE_DAA_TARGET):
            return self._v2
        return self._v1

    def calculate_block_difficulty(self, block: Block, parent_block_getter: Callable[[Block], Block]) -> float:
        """Calculate block weight according to the ascendants of `block`."""
        return self._select(block).calculate_block_difficulty(block, parent_block_getter)

    def calculate_next_weight(
        self,
        parent_block: Block,
        timestamp: int,
        parent_block_getter: Callable[[Block], Block],
    ) -> float:
        """Public method for template creation. Selects version based on parent block's feature state."""
        return self._select(parent_block).calculate_next_weight(parent_block, timestamp, parent_block_getter)

    def get_tokens_issued_per_block(self, height: int, *, block: Block | None = None) -> int:
        """Return the number of tokens issued per block of a given height.

        When a block is provided, checks feature state and reduces the reward proportionally
        if REDUCE_DAA_TARGET is active.
        """
        if block is not None:
            return self._select(block).get_tokens_issued_per_block(height)
        return self._v1.get_tokens_issued_per_block(height)

    def get_reward_for_next_block(self, parent_block: Block) -> int:
        """Return the reward for the next block after parent_block."""
        height = parent_block.get_height() + 1
        return self._select(parent_block).get_tokens_issued_per_block(height)

    def minimum_tx_weight(self, tx: Transaction) -> float:
        """Returns the minimum weight for the param tx. Version-independent."""
        return self._v1.minimum_tx_weight(tx)

    def get_mined_tokens(self, height: int) -> int:
        """Return the number of tokens mined in total at height. Version-independent."""
        return self._v1.get_mined_tokens(height)

    def get_weight_decay_amount(self, distance: int) -> float:
        """Return the amount to be reduced in the weight of the block. Version-independent."""
        return self._v1.get_weight_decay_amount(distance)

    def get_block_dependencies(
        self,
        block: Block,
        parent_block_getter: Callable[[Block], Block],
    ) -> list[VertexId]:
        """Return the ids of the required blocks to call `calculate_block_difficulty`."""
        return self._v1.get_block_dependencies(block, parent_block_getter)
