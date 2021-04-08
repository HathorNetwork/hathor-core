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

from typing import List, NamedTuple, Optional, Tuple

from hathor.transaction.genesis import BLOCK_GENESIS
from hathor.util import not_none


class _IndexEntry(NamedTuple):
    hash: bytes
    timestamp: int


BLOCK_GENESIS_ENTRY: _IndexEntry = _IndexEntry(not_none(BLOCK_GENESIS.hash), BLOCK_GENESIS.timestamp)


class BlockHeightIndex:
    """Store the block hash for each given height
    """

    _index: List[_IndexEntry]

    def __init__(self) -> None:
        self._index = [BLOCK_GENESIS_ENTRY]

    def add(self, height: int, block_hash: bytes, timestamp: int, *, can_reorg: bool = False) -> None:
        """Add new element to the cache. Must not be called for re-orgs.
        """
        if len(self._index) < height:
            raise ValueError(f'parent hash required (current height: {len(self._index)}, new height: {height})')
        elif len(self._index) == height:
            self._index.append(_IndexEntry(block_hash, timestamp))
        elif self._index[height] != block_hash:
            if can_reorg:
                del self._index[height:]
                self._index.append(_IndexEntry(block_hash, timestamp))
            else:
                raise ValueError('adding would cause a re-org, use can_reorg=True to accept re-orgs')
        else:
            # nothing to do (there are more blocks, but the block at height currently matches the added block)
            pass

    def get(self, height: int) -> Optional[bytes]:
        """ Return the block hash for the given height, or None if it is not set.
        """
        if len(self._index) <= height:
            return None
        return self._index[height].hash

    def get_tip(self) -> bytes:
        """ Return the best block hash, it returns the genesis when there is no other block
        """
        return self._index[-1].hash

    def get_height_tip(self) -> Tuple[int, bytes]:
        """ Return the best block height and hash, it returns the genesis when there is no other block
        """
        height = len(self._index) - 1
        return height, self._index[height].hash

    def search_previous_best_block(self, timestamp: float) -> Optional[bytes]:
        """Get the hash of the block with highest timestamp that isn't higher then the given timestamp."""
        # XXX: commented simple O(N) search, use when in doubt
        # for entry in reversed(self._index):
        #     if entry.timestamp <= timestamp:
        #         return entry.hash
        # return None
        # XXX: interpolation search, timestamp is very linearly correlated to height, so O(log(log(N))) on average,
        #      but the worst case will be O(N), which can happen often on tests because the genesis timestamp is fixed
        low = 0
        low_entry = self._index[low]
        if low_entry.timestamp > timestamp:
            return None
        high = len(self._index) - 1
        high_entry = self._index[high]
        if high_entry.timestamp <= timestamp:
            return high_entry.hash
        while low != high:
            assert low_entry.timestamp <= timestamp <= high_entry.timestamp
            # next key proportional to timestamp difference, greatly reduces iterations
            mid = low + int((timestamp - low_entry.timestamp) * (high - low) //
                            (high_entry.timestamp - low_entry.timestamp))

            assert low <= mid <= high
            mid_entry = self._index[mid]
            if mid_entry.timestamp > timestamp:
                high = mid - 1
                high_entry = self._index[high]
                if high_entry.timestamp < timestamp:
                    # flipped, return new lower
                    return high_entry.hash
            elif mid_entry.timestamp < timestamp:
                low = mid + 1
                low_entry = self._index[low]
                if low_entry.timestamp > timestamp:
                    # flipped, return previous lower
                    return mid_entry.hash
            else:
                # exact match
                return mid_entry.hash
        # XXX: I'm not sure this is actually reachable because we check for flips on both changes and exact match
        return low_entry.hash
