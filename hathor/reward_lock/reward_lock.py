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

from typing import TYPE_CHECKING, Iterator, Optional

from hathor.conf.get_settings import get_global_settings
from hathor.transaction import Block
from hathor.util import not_none

if TYPE_CHECKING:
    from hathor.transaction.storage.vertex_storage_protocol import VertexStorageProtocol
    from hathor.transaction.transaction import RewardLockedInfo, Transaction


def iter_spent_rewards(tx: 'Transaction', storage: 'VertexStorageProtocol') -> Iterator[Block]:
    """Iterate over all the rewards being spent, assumes tx has been verified."""
    for input_tx in tx.inputs:
        spent_tx = storage.get_vertex(input_tx.tx_id)
        if spent_tx.is_block:
            assert isinstance(spent_tx, Block)
            yield spent_tx


def is_spent_reward_locked(tx: 'Transaction') -> bool:
    """ Check whether any spent reward is currently locked, considering only the block rewards spent by this tx
    itself, and not the inherited `min_height`"""
    return get_spent_reward_locked_info(tx, not_none(tx.storage)) is not None


def get_spent_reward_locked_info(tx: 'Transaction', storage: 'VertexStorageProtocol') -> Optional['RewardLockedInfo']:
    """Check if any input block reward is locked, returning the locked information if any, or None if they are all
    unlocked."""
    from hathor.transaction.transaction import RewardLockedInfo
    for blk in iter_spent_rewards(tx, storage):
        needed_height = _spent_reward_needed_height(blk, storage)
        if needed_height > 0:
            return RewardLockedInfo(blk.hash, needed_height)
    return None


def _spent_reward_needed_height(block: Block, storage: 'VertexStorageProtocol') -> int:
    """ Returns height still needed to unlock this `block` reward: 0 means it's unlocked."""
    import math

    # omitting timestamp to get the current best block, this will usually hit the cache instead of being slow
    tips = storage.get_best_block_tips()
    assert len(tips) > 0
    best_height = math.inf
    for tip in tips:
        blk = storage.get_block(tip)
        best_height = min(best_height, blk.get_height())
    assert isinstance(best_height, int)
    spent_height = block.get_height()
    spend_blocks = best_height - spent_height
    settings = get_global_settings()
    needed_height = settings.REWARD_SPEND_MIN_BLOCKS - spend_blocks
    return max(needed_height, 0)
