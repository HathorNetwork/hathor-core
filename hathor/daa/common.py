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

"""Shared types, the DAA config value object, and utility functions for the DAA module."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, IntFlag
from math import log
from typing import TYPE_CHECKING, Callable

from hathor.types import VertexId
from hathor.util import iwindows

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.transaction import Block, Transaction


class DAAVersion(IntEnum):
    V1 = 1  # Original 30s target
    V2 = 2  # Reduced target (REDUCE_DAA_TARGET)


class TestMode(IntFlag):
    __test__ = False

    DISABLED = 0
    TEST_TX_WEIGHT = 1
    TEST_BLOCK_WEIGHT = 2
    TEST_ALL_WEIGHT = 3


@dataclass(frozen=True, slots=True)
class DAAConfig:
    """The values that distinguish one DAA version from another.

    A DAA version (V1, V2, ...) is fully described by a `DAAConfig` instance: the target
    block time, the reward reduction factor, and (for V2) the height where the reduction
    takes effect. The algorithm itself is shared and parameterized by this object — see
    ``hathor.daa.daa.DifficultyAdjustmentAlgorithm``.

    ``v2_start_height`` — the height of the first V2 block — is required for
    ``get_mined_tokens`` to split the cumulative sum between V1 and V2 ranges. It is
    None for V1 configs, and may be None for V2 configs built outside the per-block
    factory (e.g. tests that only exercise per-block reward methods).
    """

    avg_time_between_blocks: float
    reward_reduction_factor: int
    v2_start_height: int | None = None

    @classmethod
    def for_v1(cls, settings: HathorSettings) -> DAAConfig:
        """V1: original block target, no reward reduction."""
        return cls(
            avg_time_between_blocks=settings.AVG_TIME_BETWEEN_BLOCKS,
            reward_reduction_factor=1,
        )

    @classmethod
    def for_v2(cls, settings: HathorSettings, *, v2_start_height: int | None = None) -> DAAConfig:
        """V2: shorter block target, reward reduced proportionally to the speed-up."""
        return cls(
            avg_time_between_blocks=settings.REDUCED_AVG_TIME_BETWEEN_BLOCKS_10X / 10,
            reward_reduction_factor=(
                (settings.AVG_TIME_BETWEEN_BLOCKS * 10) // settings.REDUCED_AVG_TIME_BETWEEN_BLOCKS_10X
            ),
            v2_start_height=v2_start_height,
        )


def _calculate_N(settings: HathorSettings, parent_block: Block) -> int:
    """Calculate the N value for the DAA algorithm."""
    return min(2 * settings.BLOCK_DIFFICULTY_N_BLOCKS, parent_block.get_height() - 1)


def _calculate_next_weight(
    settings: HathorSettings,
    parent_block: Block,
    timestamp: int,
    parent_block_getter: Callable[[Block], Block],
    *,
    avg_time: float,
    min_block_weight: float,
) -> float:
    """Calculate the next block weight, aka DAA/difficulty adjustment algorithm.

    The algorithm used is described in RFC 22:
    https://gitlab.com/HathorNetwork/rfcs/merge_requests/22

    The weight must not be less than ``min_block_weight``.
    """
    from hathor.transaction import sum_weights

    root = parent_block
    N = _calculate_N(settings, parent_block)
    K = N // 2
    T = avg_time
    S = 5
    if N < 10:
        return min_block_weight

    blocks: list[Block] = []
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
    weight -= _get_weight_decay_amount(settings, timestamp - parent_block.timestamp)

    # Apply minimum weight
    if weight < min_block_weight:
        weight = min_block_weight

    return weight


def _get_weight_decay_amount(settings: HathorSettings, distance: int) -> float:
    """Return the amount to be reduced in the weight of the block."""
    if not settings.WEIGHT_DECAY_ENABLED:
        return 0.0
    if distance < settings.WEIGHT_DECAY_ACTIVATE_DISTANCE:
        return 0.0

    dt = distance - settings.WEIGHT_DECAY_ACTIVATE_DISTANCE

    # Calculate the number of windows.
    n_windows = 1 + (dt // settings.WEIGHT_DECAY_WINDOW_SIZE)
    return n_windows * settings.WEIGHT_DECAY_AMOUNT


def _minimum_tx_weight(settings: HathorSettings, tx: 'Transaction', test_mode: TestMode) -> float:
    """Returns the minimum weight for the param tx.

    The minimum is calculated by the following function:

    w = alpha * log(size, 2) +       4.0         + 4.0
                                  ----------------
                                   1 + k / amount
    """
    # In test mode we don't validate the minimum weight for tx
    # We do this to allow generating many txs for testing
    if test_mode & TestMode.TEST_TX_WEIGHT:
        return 1.0

    if tx.is_genesis:
        return settings.MIN_TX_WEIGHT

    tx_size = len(tx.get_struct())

    # We need to take into consideration the decimal places because it is inside the amount.
    # For instance, if one wants to transfer 20 HTRs, the amount will be 2000.
    # Max below is preventing division by 0 when handling authority methods that have no outputs
    decimal_places = tx.get_decimal_version().get_decimal_places(settings)
    amount = max(1, tx.sum_outputs) / (10 ** decimal_places)
    weight = (
        + settings.MIN_TX_WEIGHT_COEFFICIENT * log(tx_size, 2)
        + 4 / (1 + settings.MIN_TX_WEIGHT_K / amount) + 4
    )

    # Make sure the calculated weight is at least the minimum
    weight = max(weight, settings.MIN_TX_WEIGHT)

    return weight


def _get_base_tokens_issued_per_block(settings: HathorSettings, height: int) -> int:
    """Return the base number of tokens issued per block (before any reduction)."""
    if settings.BLOCKS_PER_HALVING is None:
        assert settings.MINIMUM_TOKEN_ATOMIC_UNITS_PER_BLOCK == settings.INITIAL_TOKEN_ATOMIC_UNITS_PER_BLOCK
        return settings.MINIMUM_TOKEN_ATOMIC_UNITS_PER_BLOCK

    number_of_halvings = (height - 1) // settings.BLOCKS_PER_HALVING
    number_of_halvings = max(0, number_of_halvings)

    if number_of_halvings > settings.MAXIMUM_NUMBER_OF_HALVINGS:
        return settings.MINIMUM_TOKEN_ATOMIC_UNITS_PER_BLOCK

    amount = settings.INITIAL_TOKEN_ATOMIC_UNITS_PER_BLOCK // (2**number_of_halvings)
    return max(amount, settings.MINIMUM_TOKEN_ATOMIC_UNITS_PER_BLOCK)


def _sum_block_rewards_in_range(
    settings: HathorSettings,
    *,
    start_height: int,
    end_height: int,
    reward_reduction_factor: int,
) -> int:
    """Sum per-block rewards for heights ``[start_height, end_height]``, dividing each
    block's base reward by ``reward_reduction_factor``.
    """
    if start_height > end_height:
        return 0

    assert settings.BLOCKS_PER_HALVING is not None

    total = 0
    h = start_height
    while h <= end_height:
        halving = max(0, (h - 1) // settings.BLOCKS_PER_HALVING)
        tokens_per_block = settings.INITIAL_TOKEN_ATOMIC_UNITS_PER_BLOCK // (2 ** halving)
        tokens_per_block = max(tokens_per_block, settings.MINIMUM_TOKEN_ATOMIC_UNITS_PER_BLOCK)

        next_halving_first_height = (halving + 1) * settings.BLOCKS_PER_HALVING + 1
        chunk_end = min(end_height, next_halving_first_height - 1)
        chunk_blocks = chunk_end - h + 1
        total += chunk_blocks * (tokens_per_block // reward_reduction_factor)
        h = chunk_end + 1

    return total


def _get_mined_tokens(
    settings: HathorSettings,
    height: int,
    *,
    reward_reduction_factor: int,
    v2_start_height: int | None,
) -> int:
    """Return the number of tokens mined in total at height.

    Heights below ``v2_start_height`` are treated as V1 (no reduction). Heights at or above
    ``v2_start_height`` get their per-block reward divided by ``reward_reduction_factor``.
    When ``v2_start_height`` is ``None`` or beyond ``height``, the entire range is V1.
    """
    if v2_start_height is None or v2_start_height > height:
        return _sum_block_rewards_in_range(
            settings, start_height=1, end_height=height, reward_reduction_factor=1,
        )
    return (
        _sum_block_rewards_in_range(
            settings, start_height=1, end_height=v2_start_height - 1, reward_reduction_factor=1,
        )
        + _sum_block_rewards_in_range(
            settings, start_height=v2_start_height, end_height=height,
            reward_reduction_factor=reward_reduction_factor,
        )
    )


def _get_block_dependencies(
    settings: HathorSettings,
    block: Block,
    parent_block_getter: Callable[[Block], Block],
) -> list[VertexId]:
    """Return the ids of the required blocks to call calculate_block_difficulty."""
    parent_block = parent_block_getter(block)
    N = _calculate_N(settings, parent_block)
    ids: list[VertexId] = [parent_block.hash]

    while len(ids) <= N + 1:
        parent_block = parent_block_getter(parent_block)
        ids.append(parent_block.hash)

    return ids
