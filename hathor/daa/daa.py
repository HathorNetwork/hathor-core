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

"""DifficultyAdjustmentAlgorithm: facade preserving the public API used by callers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable, ClassVar, Optional

from hathor.daa.common import TestMode
from hathor.daa.v1 import DifficultyAdjustmentAlgorithmV1
from hathor.types import VertexId

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.transaction import Block, Transaction


class DifficultyAdjustmentAlgorithm:
    """Public DAA entry point.

    Preserves the existing public API — all callers (BlockVerifier, HathorManager,
    TransactionVerifier, etc.) use this class unchanged. Internally delegates to
    a single ``DifficultyAdjustmentAlgorithmV1`` instance.
    """

    # TODO: This singleton is temporary, and only used in Peer. It should be removed from there, and then from here.
    singleton: ClassVar[Optional['DifficultyAdjustmentAlgorithm']] = None

    __slots__ = ('_v1',)

    def __init__(self, *, settings: HathorSettings, test_mode: TestMode = TestMode.DISABLED) -> None:
        self._v1 = DifficultyAdjustmentAlgorithmV1(settings=settings, test_mode=test_mode)
        DifficultyAdjustmentAlgorithm.singleton = self

    @property
    def TEST_MODE(self) -> TestMode:
        return self._v1.TEST_MODE

    @TEST_MODE.setter
    def TEST_MODE(self, value: TestMode) -> None:
        self._v1.TEST_MODE = value

    @property
    def MIN_BLOCK_WEIGHT(self) -> int:
        return self._v1.MIN_BLOCK_WEIGHT

    @MIN_BLOCK_WEIGHT.setter
    def MIN_BLOCK_WEIGHT(self, value: int) -> None:
        self._v1.MIN_BLOCK_WEIGHT = value

    @property
    def AVG_TIME_BETWEEN_BLOCKS(self) -> float:
        return self._v1.avg_time_between_blocks

    @AVG_TIME_BETWEEN_BLOCKS.setter
    def AVG_TIME_BETWEEN_BLOCKS(self, value: float) -> None:
        # Legacy compatibility: some tests set this attribute directly.
        # The value is sourced from settings; this setter is a no-op.
        pass

    def calculate_block_difficulty(self, block: Block, parent_block_getter: Callable[[Block], Block]) -> float:
        """Calculate block weight according to the ascendants of `block`."""
        return self._v1.calculate_block_difficulty(block, parent_block_getter)

    def calculate_next_weight(
        self,
        parent_block: Block,
        timestamp: int,
        parent_block_getter: Callable[[Block], Block],
    ) -> float:
        """Public method for template creation."""
        return self._v1.calculate_next_weight(parent_block, timestamp, parent_block_getter)

    def get_tokens_issued_per_block(self, height: int) -> int:
        """Return the number of tokens issued (aka reward) per block of a given height."""
        return self._v1.get_tokens_issued_per_block(height)

    def minimum_tx_weight(self, tx: Transaction) -> float:
        """Returns the minimum weight for the param tx."""
        return self._v1.minimum_tx_weight(tx)

    def get_mined_tokens(self, height: int) -> int:
        """Return the number of tokens mined in total at height."""
        return self._v1.get_mined_tokens(height)

    def get_weight_decay_amount(self, distance: int) -> float:
        """Return the amount to be reduced in the weight of the block."""
        return self._v1.get_weight_decay_amount(distance)

    def get_block_dependencies(
        self,
        block: Block,
        parent_block_getter: Callable[[Block], Block],
    ) -> list[VertexId]:
        """Return the ids of the required blocks to call calculate_block_difficulty."""
        return self._v1.get_block_dependencies(block, parent_block_getter)
