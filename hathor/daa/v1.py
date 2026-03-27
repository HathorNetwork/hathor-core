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

"""DifficultyAdjustmentAlgorithmV1: Original 30s target, normal rewards."""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from hathor.daa.common import (
    TestMode,
    _calculate_next_weight,
    _get_base_tokens_issued_per_block,
    _get_block_dependencies,
    _get_mined_tokens,
    _get_weight_decay_amount,
    _minimum_tx_weight,
)
from hathor.profiler import get_cpu_profiler
from hathor.types import VertexId

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.transaction import Block, Transaction

cpu = get_cpu_profiler()


class DifficultyAdjustmentAlgorithmV1:
    """Original DAA with 30s block target and normal rewards.

    Each method explicitly calls the appropriate utility function.
    """

    __slots__ = ('_settings', 'TEST_MODE', 'MIN_BLOCK_WEIGHT')

    def __init__(self, *, settings: HathorSettings, test_mode: TestMode = TestMode.DISABLED) -> None:
        self._settings = settings
        self.TEST_MODE = test_mode
        self.MIN_BLOCK_WEIGHT = settings.MIN_BLOCK_WEIGHT

    @property
    def avg_time_between_blocks(self) -> float:
        return self._settings.AVG_TIME_BETWEEN_BLOCKS

    @cpu.profiler(key=lambda _, block: 'calculate_block_difficulty!{}'.format(block.hash.hex()))
    def calculate_block_difficulty(self, block: Block, parent_block_getter: Callable[[Block], Block]) -> float:
        """Calculate block weight according to the ascendants of `block`."""
        if self.TEST_MODE & TestMode.TEST_BLOCK_WEIGHT:
            return 1.0
        if block.is_genesis:
            return self.MIN_BLOCK_WEIGHT
        parent_block = parent_block_getter(block)
        return _calculate_next_weight(
            self._settings, parent_block, block.timestamp, parent_block_getter,
            avg_time=self.avg_time_between_blocks, min_block_weight=self.MIN_BLOCK_WEIGHT,
            test_mode=self.TEST_MODE,
        )

    def calculate_next_weight(
        self,
        parent_block: Block,
        timestamp: int,
        parent_block_getter: Callable[[Block], Block],
    ) -> float:
        """Public method for template creation."""
        if self.TEST_MODE & TestMode.TEST_BLOCK_WEIGHT:
            return 1.0
        return _calculate_next_weight(
            self._settings, parent_block, timestamp, parent_block_getter,
            avg_time=self.avg_time_between_blocks, min_block_weight=self.MIN_BLOCK_WEIGHT,
            test_mode=self.TEST_MODE,
        )

    def get_block_dependencies(
        self,
        block: Block,
        parent_block_getter: Callable[[Block], Block],
    ) -> list[VertexId]:
        """Return the ids of the required blocks to call calculate_block_difficulty."""
        return _get_block_dependencies(self._settings, block, parent_block_getter)

    def get_tokens_issued_per_block(self, height: int) -> int:
        """Return the number of tokens issued (aka reward) per block of a given height."""
        return _get_base_tokens_issued_per_block(self._settings, height)

    def get_mined_tokens(self, height: int) -> int:
        """Return the number of tokens mined in total at height."""
        return _get_mined_tokens(self._settings, height)

    def minimum_tx_weight(self, tx: Transaction) -> float:
        """Returns the minimum weight for the param tx."""
        return _minimum_tx_weight(self._settings, tx, self.TEST_MODE)

    def get_weight_decay_amount(self, distance: int) -> float:
        """Return the amount to be reduced in the weight of the block."""
        return _get_weight_decay_amount(self._settings, distance)
