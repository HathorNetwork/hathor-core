# Copyright 2024 Hathor Labs
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

from hathor.conf.settings import HathorSettings
from hathor.indexes.json_extended_cache import JsonExtendedCache
from hathor.types import VertexId


class MemoryJsonExtendedCache(JsonExtendedCache):
    """Store the block hash for each given height
    """

    def __init__(self, *, settings: HathorSettings | None = None) -> None:
        super().__init__(settings=settings)
        self.force_clear()

    def get_db_name(self) -> Optional[str]:
        return None

    def force_clear(self) -> None:
        self._cache: dict[VertexId, bytes] = {}

    def get(self, vertex_id: VertexId) -> Optional[bytes]:
        return self._cache.get(vertex_id)

    def set(self, vertex_id: VertexId, data: bytes) -> None:
        self._cache[vertex_id] = data

    def invalidate(self, vertex_id: VertexId) -> None:
        self._cache.pop(vertex_id, None)
