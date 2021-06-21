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

from enum import IntFlag
from math import log
from typing import TYPE_CHECKING, List

from structlog import get_logger

from hathor.conf import HathorSettings
from hathor.profiler import get_cpu_profiler
from hathor.util import iwindows

if TYPE_CHECKING:
    from hathor.transaction import Block, Transaction

logger = get_logger()
settings = HathorSettings()
cpu = get_cpu_profiler()

MIN_BLOCK_WEIGHT = settings.MIN_BLOCK_WEIGHT
AVG_TIME_BETWEEN_BLOCKS = settings.AVG_TIME_BETWEEN_BLOCKS


class TestMode(IntFlag):
    DISABLED = 0
    TEST_TX_WEIGHT = 1
    TEST_BLOCK_WEIGHT = 2
    TEST_ALL_WEIGHT = 3


TEST_MODE = TestMode.DISABLED


def _set_test_mode(mode: TestMode) -> None:
    global TEST_MODE
    logger.debug('change DAA test mode', from_mode=TEST_MODE.name, to_mode=mode.name)
    TEST_MODE = mode


@cpu.profiler(key=lambda block: 'calculate_block_difficulty!{}'.format(block.hash.hex()))
def calculate_block_difficulty(block: 'Block') -> float:
    """ Calculate block weight according to the ascendents of `block`, using calculate_next_weight."""
    if TEST_MODE & TestMode.TEST_BLOCK_WEIGHT:
        return 1.0

    if block.is_genesis:
        return MIN_BLOCK_WEIGHT

    return calculate_next_weight(block.get_block_parent(), block.timestamp)


def calculate_next_weight(parent_block: 'Block', timestamp: int) -> float:
    """ Calculate the next block weight, aka DAA/difficulty adjustment algorithm.

    The algorithm used is described in [RFC 22](https://gitlab.com/HathorNetwork/rfcs/merge_requests/22).

    The weight must not be less than `MIN_BLOCK_WEIGHT`.
    """
    if TEST_MODE & TestMode.TEST_BLOCK_WEIGHT:
        return 1.0

    from hathor.transaction import sum_weights

    root = parent_block
    N = min(2 * settings.BLOCK_DIFFICULTY_N_BLOCKS, parent_block.get_metadata().height - 1)
    K = N // 2
    T = AVG_TIME_BETWEEN_BLOCKS
    S = 5
    if N < 10:
        return MIN_BLOCK_WEIGHT

    blocks: List['Block'] = []
    while len(blocks) < N + 1:
        blocks.append(root)
        root = root.get_block_parent()
        assert root is not None

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
    weight -= get_weight_decay_amount(timestamp - parent_block.timestamp)

    # Apply minimum weight
    if weight < MIN_BLOCK_WEIGHT:
        weight = MIN_BLOCK_WEIGHT

    return weight


def get_weight_decay_amount(distance: int) -> float:
    """Return the amount to be reduced in the weight of the block."""
    if not settings.WEIGHT_DECAY_ENABLED:
        return 0.0
    if distance < settings.WEIGHT_DECAY_ACTIVATE_DISTANCE:
        return 0.0

    dt = distance - settings.WEIGHT_DECAY_ACTIVATE_DISTANCE

    # Calculate the number of windows.
    n_windows = 1 + (dt // settings.WEIGHT_DECAY_WINDOW_SIZE)
    return n_windows * settings.WEIGHT_DECAY_AMOUNT


def minimum_tx_weight(tx: 'Transaction') -> float:
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
    if TEST_MODE & TestMode.TEST_TX_WEIGHT:
        return 1.0

    if tx.is_genesis:
        return settings.MIN_TX_WEIGHT

    tx_size = len(tx.get_struct())

    # We need to take into consideration the decimal places because it is inside the amount.
    # For instance, if one wants to transfer 20 HTRs, the amount will be 2000.
    # Max below is preventing division by 0 when handling authority methods that have no outputs
    amount = max(1, tx.sum_outputs) / (10 ** settings.DECIMAL_PLACES)
    weight = (
        + settings.MIN_TX_WEIGHT_COEFFICIENT * log(tx_size, 2)
        + 4 / (1 + settings.MIN_TX_WEIGHT_K / amount) + 4
    )

    # Make sure the calculated weight is at least the minimum
    weight = max(weight, settings.MIN_TX_WEIGHT)

    return weight


def get_tokens_issued_per_block(height: int) -> int:
    """Return the number of tokens issued (aka reward) per block of a given height."""
    if settings.BLOCKS_PER_HALVING is None:
        assert settings.MINIMUM_TOKENS_PER_BLOCK == settings.INITIAL_TOKENS_PER_BLOCK
        return settings.MINIMUM_TOKENS_PER_BLOCK

    number_of_halvings = (height - 1) // settings.BLOCKS_PER_HALVING
    number_of_halvings = max(0, number_of_halvings)

    if number_of_halvings > settings.MAXIMUM_NUMBER_OF_HALVINGS:
        return settings.MINIMUM_TOKENS_PER_BLOCK

    amount = settings.INITIAL_TOKENS_PER_BLOCK // (2**number_of_halvings)
    amount = max(amount, settings.MINIMUM_TOKENS_PER_BLOCK)
    return amount


def get_mined_tokens(height: int) -> int:
    """Return the number of tokens mined in total at height
    """
    assert settings.BLOCKS_PER_HALVING is not None
    number_of_halvings = (height - 1) // settings.BLOCKS_PER_HALVING
    number_of_halvings = max(0, number_of_halvings)

    blocks_in_this_halving = height - number_of_halvings * settings.BLOCKS_PER_HALVING

    tokens_per_block = settings.INITIAL_TOKENS_PER_BLOCK
    mined_tokens = 0

    # Sum the past halvings
    for _ in range(number_of_halvings):
        mined_tokens += settings.BLOCKS_PER_HALVING * tokens_per_block
        tokens_per_block //= 2
        tokens_per_block = max(tokens_per_block, settings.MINIMUM_TOKENS_PER_BLOCK)

    # Sum the blocks in the current halving
    mined_tokens += blocks_in_this_halving * tokens_per_block

    return mined_tokens
