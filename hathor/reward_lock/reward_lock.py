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

from typing import TYPE_CHECKING, Collection, Optional

from hathor.conf.get_settings import get_global_settings
from hathor.transaction import BaseTransaction, Block

if TYPE_CHECKING:
    from hathor.transaction.transaction import RewardLockedInfo, Transaction


def is_spent_reward_locked(tx: 'Transaction') -> bool:
    """ Check whether any spent reward is currently locked, considering only the block rewards spent by this tx
    itself, and not the inherited `min_height`"""
    assert tx.storage is not None
    tips_heights = tx.storage.get_tips_heights()
    spent_txs = tx.storage.get_spent_txs(tx).values()
    reward_locked_info = get_spent_reward_locked_info(spent_txs, tips_heights)
    return reward_locked_info is not None


def get_spent_reward_locked_info(
    spent_txs: Collection[BaseTransaction],
    tips_heights: list[int],
) -> Optional['RewardLockedInfo']:
    """Check if any input block reward is locked, returning the locked information if any, or None if they are all
    unlocked."""
    from hathor.transaction.transaction import RewardLockedInfo
    for spent_tx in spent_txs:
        if isinstance(spent_tx, Block):
            needed_height = _spent_reward_needed_height(spent_tx, tips_heights)
            if needed_height > 0:
                return RewardLockedInfo(spent_tx.hash, needed_height)
    return None


def _spent_reward_needed_height(block: Block, tips_heights: list[int]) -> int:
    """ Returns height still needed to unlock this `block` reward: 0 means it's unlocked."""
    # omitting timestamp to get the current best block, this will usually hit the cache instead of being slow
    assert len(tips_heights) > 0
    best_height = min(tips_heights)
    spent_height = block.get_height()
    spend_blocks = best_height - spent_height
    settings = get_global_settings()
    needed_height = settings.REWARD_SPEND_MIN_BLOCKS - spend_blocks
    return max(needed_height, 0)
