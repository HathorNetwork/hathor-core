# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import Iterable, Optional

from structlog import get_logger

from hathor.conf.settings import HathorSettings
from hathor.indexes.mempool_tips_index import ByteCollectionMempoolTipsIndex

logger = get_logger()


class MemoryMempoolTipsIndex(ByteCollectionMempoolTipsIndex):
    _index: set[bytes]

    def __init__(self, *, settings: HathorSettings) -> None:
        super().__init__(settings=settings)
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
