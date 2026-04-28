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

"""DifficultyAdjustmentAlgorithm: the Hathor DAA, parameterized by a `DAAConfig`."""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from hathor.daa.common import (
    DAAConfig,
    TestMode,
    _calculate_next_weight,
    _get_block_dependencies,
)
from hathor.profiler import get_cpu_profiler
from hathor.types import VertexId

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.transaction import Block

cpu = get_cpu_profiler()


class DifficultyAdjustmentAlgorithm:
    """The Hathor DAA — calculates block weight, rewards, and transaction weight.

    A single instance is parameterized by a ``DAAConfig`` value object that captures
    the per-version values (currently just the target block time). Use ``DAAFactory``
    to build instances configured for a given block's context.
    """

    __slots__ = ('_settings', '_config', 'TEST_MODE', 'MIN_BLOCK_WEIGHT')

    def __init__(
        self,
        *,
        settings: HathorSettings,
        config: DAAConfig,
        test_mode: TestMode = TestMode.DISABLED,
        min_block_weight: int | None = None,
    ) -> None:
        self._settings = settings
        self._config = config
        self.TEST_MODE = test_mode
        self.MIN_BLOCK_WEIGHT = settings.MIN_BLOCK_WEIGHT if min_block_weight is None else min_block_weight

    @property
    def avg_time_between_blocks(self) -> float:
        return self._config.avg_time_between_blocks

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
            avg_time=self._config.avg_time_between_blocks, min_block_weight=self.MIN_BLOCK_WEIGHT,
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
            avg_time=self._config.avg_time_between_blocks, min_block_weight=self.MIN_BLOCK_WEIGHT,
        )

    def get_block_dependencies(
        self,
        block: Block,
        parent_block_getter: Callable[[Block], Block],
    ) -> list[VertexId]:
        """Return the ids of the required blocks to call calculate_block_difficulty."""
        return _get_block_dependencies(self._settings, block, parent_block_getter)
