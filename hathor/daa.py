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

"""
Functions related to DAA (Difficulty Adjustment Algorithm) are here. As well as calculating a transaction weight and
block rewards.

NOTE: This module could use a better name.
"""

from __future__ import annotations

from enum import IntFlag
from math import log
from typing import TYPE_CHECKING, Callable, ClassVar, Optional

from structlog import get_logger

from hathor.profiler import get_cpu_profiler
from hathor.types import VertexId
from hathor.util import iwindows

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.transaction import Block, Transaction

logger = get_logger()
cpu = get_cpu_profiler()


class TestMode(IntFlag):
    __test__ = False

    DISABLED = 0
    TEST_TX_WEIGHT = 1
    TEST_BLOCK_WEIGHT = 2
    TEST_ALL_WEIGHT = 3


class DifficultyAdjustmentAlgorithm:
    # TODO: This singleton is temporary, and only used in Peer. It should be removed from there, and then from here.
    singleton: ClassVar[Optional['DifficultyAdjustmentAlgorithm']] = None

    def __init__(self, *, settings: HathorSettings, test_mode: TestMode = TestMode.DISABLED) -> None:
        self._settings = settings
        self.AVG_TIME_BETWEEN_BLOCKS = self._settings.AVG_TIME_BETWEEN_BLOCKS
        self.MIN_BLOCK_WEIGHT = self._settings.MIN_BLOCK_WEIGHT
        self.TEST_MODE = test_mode
        DifficultyAdjustmentAlgorithm.singleton = self

    @cpu.profiler(key=lambda _, block: 'calculate_block_difficulty!{}'.format(block.hash.hex()))
    def calculate_block_difficulty(self, block: 'Block', parent_block_getter: Callable[['Block'], 'Block']) -> float:
        """ Calculate block weight according to the ascendants of `block`, using calculate_next_weight."""
        if self.TEST_MODE & TestMode.TEST_BLOCK_WEIGHT:
            return 1.0

        if block.is_genesis:
            return self.MIN_BLOCK_WEIGHT

        parent_block = parent_block_getter(block)
        return self.calculate_next_weight(parent_block, block.timestamp, parent_block_getter)

    def _calculate_N(self, parent_block: 'Block') -> int:
        """Calculate the N value for the `calculate_next_weight` algorithm."""
        return min(2 * self._settings.BLOCK_DIFFICULTY_N_BLOCKS, parent_block.get_height() - 1)

    def get_block_dependencies(
        self,
        block: 'Block',
        parent_block_getter: Callable[['Block'], 'Block'],
    ) -> list[VertexId]:
        """Return the ids of the required blocks to call `calculate_block_difficulty` for the provided block."""
        parent_block = parent_block_getter(block)
        N = self._calculate_N(parent_block)
        ids: list[VertexId] = [parent_block.hash]

        while len(ids) <= N + 1:
            parent_block = parent_block_getter(parent_block)
            ids.append(parent_block.hash)

        return ids

    def calculate_next_weight(
        self,
        parent_block: 'Block',
        timestamp: int,
        parent_block_getter: Callable[['Block'], 'Block'],
    ) -> float:
        """ Calculate the next block weight, aka DAA/difficulty adjustment algorithm.

        The algorithm used is described in [RFC 22](https://gitlab.com/HathorNetwork/rfcs/merge_requests/22).

        The weight must not be less than `MIN_BLOCK_WEIGHT`.
        """
        if self.TEST_MODE & TestMode.TEST_BLOCK_WEIGHT:
            return 1.0

        from hathor.transaction import sum_weights

        root = parent_block
        N = self._calculate_N(parent_block)
        K = N // 2
        T = self.AVG_TIME_BETWEEN_BLOCKS
        S = 5
        if N < 10:
            return self.MIN_BLOCK_WEIGHT

        blocks: list['Block'] = []
        while len(blocks) < N + 1:
            blocks.append(root)
            root = parent_block_getter(root)

        # TODO: revise if this assertion can be safely removed
        assert blocks == sorted(blocks, key=lambda tx: -tx.timestamp)
        blocks = list(reversed(blocks))

        assert len(blocks) == N + 1
        solvetimes, weights = zip(*(
            (block.timestamp - prev_block.timestamp, block.weight)
            for prev_block, block in iwindows(blocks, 2)
        ))
        assert len(solvetimes) == len(weights) == N, f'got {len(solvetimes)}, {len(weights)} expected {N}'

        sum_solvetimes = 0.0
        logsum_weights = 0.0

        prefix_sum_solvetimes = [0]
        for st in solvetimes:
            prefix_sum_solvetimes.append(prefix_sum_solvetimes[-1] + st)

        # Loop through N most recent blocks. N is most recently solved block.
        for i in range(K, N):
            solvetime = solvetimes[i]
            weight = weights[i]
            x = (prefix_sum_solvetimes[i + 1] - prefix_sum_solvetimes[i - K]) / K
            ki = K * (x - T)**2 / (2 * T * T)
            ki = max(1, ki / S)
            sum_solvetimes += ki * solvetime
            logsum_weights = sum_weights(logsum_weights, log(ki, 2) + weight)

        weight = logsum_weights - log(sum_solvetimes, 2) + log(T, 2)

        # Apply weight decay
        weight -= self.get_weight_decay_amount(timestamp - parent_block.timestamp)

        # Apply minimum weight
        if weight < self.MIN_BLOCK_WEIGHT:
            weight = self.MIN_BLOCK_WEIGHT

        return weight

    def get_weight_decay_amount(self, distance: int) -> float:
        """Return the amount to be reduced in the weight of the block."""
        if not self._settings.WEIGHT_DECAY_ENABLED:
            return 0.0
        if distance < self._settings.WEIGHT_DECAY_ACTIVATE_DISTANCE:
            return 0.0

        dt = distance - self._settings.WEIGHT_DECAY_ACTIVATE_DISTANCE

        # Calculate the number of windows.
        n_windows = 1 + (dt // self._settings.WEIGHT_DECAY_WINDOW_SIZE)
        return n_windows * self._settings.WEIGHT_DECAY_AMOUNT

    def minimum_tx_weight(self, tx: 'Transaction') -> float:
        """ Returns the minimum weight for the param tx
            The minimum is calculated by the following function:

            w = alpha * log(size, 2) +       4.0         + 4.0
                                       ----------------
                                        1 + k / amount

            :param tx: tx to calculate the minimum weight
            :type tx: :py:class:`hathor.transaction.transaction.Transaction`

            :return: minimum weight for the tx
            :rtype: float
        """
        # In test mode we don't validate the minimum weight for tx
        # We do this to allow generating many txs for testing
        if self.TEST_MODE & TestMode.TEST_TX_WEIGHT:
            return 1.0

        if tx.is_genesis:
            return self._settings.MIN_TX_WEIGHT

        from hathor.transaction.vertex_parser import vertex_serializer
        tx_size = len(vertex_serializer.serialize(tx))

        # We need to take into consideration the decimal places because it is inside the amount.
        # For instance, if one wants to transfer 20 HTRs, the amount will be 2000.
        # Max below is preventing division by 0 when handling authority methods that have no outputs
        amount = max(1, tx.sum_outputs) / (10 ** self._settings.DECIMAL_PLACES)
        weight = (
            + self._settings.MIN_TX_WEIGHT_COEFFICIENT * log(tx_size, 2)
            + 4 / (1 + self._settings.MIN_TX_WEIGHT_K / amount) + 4
        )

        # Make sure the calculated weight is at least the minimum
        weight = max(weight, self._settings.MIN_TX_WEIGHT)

        return weight

    def get_tokens_issued_per_block(self, height: int) -> int:
        """Return the number of tokens issued (aka reward) per block of a given height."""
        if self._settings.BLOCKS_PER_HALVING is None:
            assert self._settings.MINIMUM_TOKENS_PER_BLOCK == self._settings.INITIAL_TOKENS_PER_BLOCK
            return self._settings.MINIMUM_TOKENS_PER_BLOCK

        number_of_halvings = (height - 1) // self._settings.BLOCKS_PER_HALVING
        number_of_halvings = max(0, number_of_halvings)

        if number_of_halvings > self._settings.MAXIMUM_NUMBER_OF_HALVINGS:
            return self._settings.MINIMUM_TOKENS_PER_BLOCK

        amount = self._settings.INITIAL_TOKENS_PER_BLOCK // (2**number_of_halvings)
        amount = max(amount, self._settings.MINIMUM_TOKENS_PER_BLOCK)
        return amount

    def get_mined_tokens(self, height: int) -> int:
        """Return the number of tokens mined in total at height
        """
        assert self._settings.BLOCKS_PER_HALVING is not None
        number_of_halvings = (height - 1) // self._settings.BLOCKS_PER_HALVING
        number_of_halvings = max(0, number_of_halvings)

        blocks_in_this_halving = height - number_of_halvings * self._settings.BLOCKS_PER_HALVING

        tokens_per_block = self._settings.INITIAL_TOKENS_PER_BLOCK
        mined_tokens = 0

        # Sum the past halvings
        for _ in range(number_of_halvings):
            mined_tokens += self._settings.BLOCKS_PER_HALVING * tokens_per_block
            tokens_per_block //= 2
            tokens_per_block = max(tokens_per_block, self._settings.MINIMUM_TOKENS_PER_BLOCK)

        # Sum the blocks in the current halving
        mined_tokens += blocks_in_this_halving * tokens_per_block

        return mined_tokens
