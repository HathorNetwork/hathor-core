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

from typing import Iterable, Optional

from structlog import get_logger

from hathor.indexes.mempool_tips_index import ByteCollectionMempoolTipsIndex
from hathor.vertex_metadata import VertexMetadataService

logger = get_logger()


class MemoryMempoolTipsIndex(ByteCollectionMempoolTipsIndex):
    _index: set[bytes]

    def __init__(self, metadata_service: VertexMetadataService) -> None:
        super().__init__(metadata_service=metadata_service)
        self.log = logger.new()
        self.force_clear()

    def get_db_name(self) -> Optional[str]:
        return None

    def force_clear(self) -> None:
        self._index = set()

    def _discard(self, tx: bytes) -> None:
        self._index.discard(tx)

    def _add(self, tx: bytes) -> None:
        self._index.add(tx)

    def _add_many(self, txs: Iterable[bytes]) -> None:
        self._index.update(txs)
