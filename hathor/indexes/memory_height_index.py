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

from typing import Optional

from hathor.indexes.height_index import BLOCK_GENESIS_ENTRY, HeightIndex, IndexEntry


class MemoryHeightIndex(HeightIndex):
    """Store the block hash for each given height
    """

    _index: list[IndexEntry]

    def __init__(self) -> None:
        super().__init__()
        self.force_clear()

    def get_db_name(self) -> Optional[str]:
        return None

    def force_clear(self) -> None:
        self._index = [BLOCK_GENESIS_ENTRY]

    def _add(self, height: int, block_hash: bytes, timestamp: int, *, can_reorg: bool) -> None:
        if len(self._index) < height:
            raise ValueError(f'parent hash required (current height: {len(self._index)}, new height: {height})')
        elif len(self._index) == height:
            self._index.append(IndexEntry(block_hash, timestamp))
        elif self._index[height].hash != block_hash:
            if can_reorg:
                del self._index[height:]
                self._index.append(IndexEntry(block_hash, timestamp))
            else:
                self.log.error(
                    'adding would cause a re-org',
                    height=height,
                    current_block=self._index[height].hash.hex(),
                    new_block=block_hash.hex()
                )
                raise ValueError('adding would cause a re-org, use can_reorg=True to accept re-orgs')
        else:
            # nothing to do (there are more blocks, but the block at height currently matches the added block)
            pass

    def add_new(self, height: int, block_hash: bytes, timestamp: int) -> None:
        self._add(height, block_hash, timestamp, can_reorg=False)

    def add_reorg(self, height: int, block_hash: bytes, timestamp: int) -> None:
        self._add(height, block_hash, timestamp, can_reorg=True)

    def get(self, height: int) -> Optional[bytes]:
        if len(self._index) <= height:
            return None
        return self._index[height].hash

    def get_tip(self) -> bytes:
        return self._index[-1].hash

    def get_height_tip(self) -> tuple[int, bytes]:
        height = len(self._index) - 1
        return height, self._index[height].hash
