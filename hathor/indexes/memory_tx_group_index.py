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

from collections import defaultdict
from typing import Iterator, Optional, Sized, TypeVar

from structlog import get_logger
from typing_extensions import override

from hathor.indexes.tx_group_index import TxGroupIndex
from hathor.transaction import BaseTransaction

logger = get_logger()

KT = TypeVar('KT', bound=Sized)


class MemoryTxGroupIndex(TxGroupIndex[KT]):
    """Memory implementation of the TxGroupIndex. This class is abstract and cannot be used directly.
    """

    index: defaultdict[KT, set[tuple[int, bytes]]]

    def __init__(self) -> None:
        self.force_clear()

    @override
    def get_db_name(self) -> Optional[str]:
        return None

    def force_clear(self) -> None:
        self.index = defaultdict(set)

    def _add_tx(self, key: KT, tx: BaseTransaction) -> None:
        self.index[key].add((tx.timestamp, tx.hash))

    def add_tx(self, tx: BaseTransaction) -> None:

        for key in self._extract_keys(tx):
            self._add_tx(key, tx)

    def remove_tx(self, tx: BaseTransaction) -> None:

        for key in self._extract_keys(tx):
            self.index[key].discard((tx.timestamp, tx.hash))

    def _get_sorted_from_key(self,
                             key: KT,
                             tx_start: Optional[BaseTransaction] = None,
                             reverse: bool = False) -> Iterator[bytes]:
        sorted_elements = sorted(self.index[key])
        if reverse:
            sorted_elements.reverse()

        found = False
        for _, h in sorted_elements:
            if tx_start and h == tx_start.hash:
                found = True

            if found or not tx_start:
                yield h

    def _is_key_empty(self, key: KT) -> bool:
        return not bool(self.index[key])

    @override
    def get_latest_tx_timestamp(self, key: KT) -> int | None:
        elements = self.index.get(key)
        if elements is None:
            return None
        sorted_elements = sorted(self.index[key], reverse=True)
        timestamp, _ = sorted_elements[0]
        return timestamp
