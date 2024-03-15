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

from typing import TYPE_CHECKING, Iterable, Optional

from structlog import get_logger

from hathor.indexes.address_index import AddressIndex
from hathor.indexes.memory_tx_group_index import MemoryTxGroupIndex
from hathor.transaction import BaseTransaction

if TYPE_CHECKING:  # pragma: no cover
    from hathor.pubsub import PubSubManager

logger = get_logger()


class MemoryAddressIndex(MemoryTxGroupIndex[str], AddressIndex):
    """ Index of inputs/outputs by address
    """

    def __init__(self, pubsub: Optional['PubSubManager'] = None) -> None:
        super().__init__()
        self.pubsub = pubsub
        if self.pubsub:
            self._subscribe_pubsub_events()

    def get_db_name(self) -> Optional[str]:
        return None

    def _extract_keys(self, tx: BaseTransaction) -> Iterable[str]:
        return tx.get_related_addresses()

    def add_tx(self, tx: BaseTransaction) -> None:
        super().add_tx(tx)
        self._publish_tx(tx)

    def get_from_address(self, address: str) -> list[bytes]:
        return list(self._get_from_key(address))

    def get_sorted_from_address(self, address: str, tx: Optional[BaseTransaction] = None) -> Iterable[bytes]:
        return self._get_sorted_from_key(address, tx)

    def is_address_empty(self, address: str) -> bool:
        return self._is_key_empty(address)
