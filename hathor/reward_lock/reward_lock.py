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

from __future__ import annotations

from typing import TYPE_CHECKING, Iterator, Optional

from hathor.transaction import Block
from hathor.util import not_none

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.transaction.storage.vertex_storage_protocol import VertexStorageProtocol
    from hathor.transaction.transaction import RewardLockedInfo, Transaction


def iter_spent_rewards(tx: Transaction, storage: VertexStorageProtocol) -> Iterator[Block]:
    """Iterate over all the rewards being spent, assumes tx has been verified."""
    for input_tx in tx.inputs:
        spent_tx = storage.get_vertex(input_tx.tx_id)
        if spent_tx.is_block:
            assert isinstance(spent_tx, Block)
            yield spent_tx


def is_spent_reward_locked(settings: HathorSettings, tx: Transaction) -> bool:
    """ Check whether any spent reward is currently locked, considering only the block rewards spent by this tx
    itself, and not the inherited `min_height`"""
    return get_spent_reward_locked_info(settings, tx, not_none(tx.storage)) is not None


def get_spent_reward_locked_info(
    settings: HathorSettings,
    tx: Transaction,
    storage: VertexStorageProtocol,
) -> Optional[RewardLockedInfo]:
    """Check if any input block reward is locked, returning the locked information if any, or None if they are all
    unlocked."""
    from hathor.transaction.transaction import RewardLockedInfo
    best_height = get_minimum_best_height(storage)
    for blk in iter_spent_rewards(tx, storage):
        needed_height = _spent_reward_needed_height(settings, blk, best_height)
        if needed_height > 0:
            return RewardLockedInfo(blk.hash, needed_height)
    return None


def get_minimum_best_height(storage: VertexStorageProtocol) -> int:
    """Return the height of the current best block that shall be used for `min_height` verification."""
    # XXX: only use methods available in VertexStorageProtocol, otherwise TransactionStorage.get_height_best_block
    # would give the same result but more efficiently by using a cache and an index
    return storage.get_block(storage.get_best_block_hash()).get_height()


def _spent_reward_needed_height(settings: HathorSettings, block: Block, best_height: int) -> int:
    """ Returns height still needed to unlock this `block` reward: 0 means it's unlocked."""
    spent_height = block.get_height()
    spend_blocks = best_height - spent_height
    needed_height = settings.REWARD_SPEND_MIN_BLOCKS - spend_blocks
    return max(needed_height, 0)
