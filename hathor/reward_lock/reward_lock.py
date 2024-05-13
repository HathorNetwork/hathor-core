#  Copyright 2024 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from typing import TYPE_CHECKING, Callable, Optional

from hathor.conf.get_settings import get_global_settings
from hathor.transaction import Block, Vertex
from hathor.types import VertexId

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage
    from hathor.transaction.transaction import RewardLockedInfo, Transaction


def is_spent_reward_locked(tx: 'Transaction', storage: 'TransactionStorage') -> bool:
    """ Check whether any spent reward is currently locked, considering only the block rewards spent by this tx
    itself, and not the inherited `min_height`"""
    info = get_spent_reward_locked_info(tx, storage.get_vertex, storage.get_best_block_tips)
    return info is not None


def get_spent_reward_locked_info(
    tx: 'Transaction',
    vertex_getter: Callable[[VertexId], Vertex],
    best_block_tips_getter: Callable[[], list[VertexId]],
) -> Optional['RewardLockedInfo']:
    """Check if any input block reward is locked, returning the locked information if any, or None if they are all
    unlocked."""
    from hathor.transaction.transaction import RewardLockedInfo
    best_height = get_minimum_best_height(vertex_getter, best_block_tips_getter)
    for tx_input in tx.inputs:
        spent_tx = vertex_getter(tx_input.tx_id)
        if isinstance(spent_tx, Block):
            needed_height = _spent_reward_needed_height(spent_tx, best_height)
            if needed_height > 0:
                return RewardLockedInfo(spent_tx.hash, needed_height)

    return None


def get_minimum_best_height(
    vertex_getter: Callable[[VertexId], Vertex],
    best_block_tips_getter: Callable[[], list[VertexId]],
) -> int:
    """Return the height of the current best block that shall be used for `min_height` verification."""
    import math
    tips = best_block_tips_getter()
    assert len(tips) > 0
    best_height = math.inf
    for tip in tips:
        block = vertex_getter(tip)
        assert isinstance(block, Block)
        best_height = min(best_height, block.static_metadata.height)
    assert isinstance(best_height, int)
    return best_height


def _spent_reward_needed_height(block: Block, best_height: int) -> int:
    """ Returns height still needed to unlock this `block` reward: 0 means it's unlocked."""
    spent_height = block.get_height()
    spend_blocks = best_height - spent_height
    settings = get_global_settings()
    needed_height = settings.REWARD_SPEND_MIN_BLOCKS - spend_blocks
    return max(needed_height, 0)
