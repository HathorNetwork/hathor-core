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

from hathor.conf.settings import HathorSettings
from hathor.indexes.address_index import AddressIndex
from hathor.indexes.rocksdb_tx_group_index import RocksDBTxGroupIndex
from hathor.indexes.rocksdb_utils import RocksDBIndexUtils
from hathor.transaction import BaseTransaction

if TYPE_CHECKING:  # pragma: no cover
    import rocksdb

    from hathor.pubsub import PubSubManager

logger = get_logger()

_CF_NAME_ADDRESS_INDEX = b'address-index'
_DB_NAME: str = 'address'


class RocksDBAddressIndex(RocksDBTxGroupIndex[str], AddressIndex, RocksDBIndexUtils):
    """ Index of inputs/outputs by address.
    """

    _KEY_SIZE = 34

    def __init__(self, db: 'rocksdb.DB', *, settings: HathorSettings, cf_name: Optional[bytes] = None,
                 pubsub: Optional['PubSubManager'] = None) -> None:
        RocksDBTxGroupIndex.__init__(self, db, cf_name or _CF_NAME_ADDRESS_INDEX)
        AddressIndex.__init__(self, settings=settings)

        self.pubsub = pubsub
        if self.pubsub:
            self._subscribe_pubsub_events()

    def _serialize_key(self, key: str) -> bytes:
        return key.encode('ascii')

    def _deserialize_key(self, key_bytes: bytes) -> str:
        return key_bytes.decode('ascii')

    def _extract_keys(self, tx: BaseTransaction) -> Iterable[str]:
        return tx.get_related_addresses()

    def get_db_name(self) -> Optional[str]:
        # XXX: we don't need it to be parametrizable, so this is fine
        return _DB_NAME

    def add_tx(self, tx: BaseTransaction) -> None:
        super().add_tx(tx)
        self._publish_tx(tx)

    def get_from_address(self, address: str) -> list[bytes]:
        return list(self._get_from_key(address))

    def get_sorted_from_address(self, address: str, tx_start: Optional[BaseTransaction] = None) -> Iterable[bytes]:
        return self._get_sorted_from_key(address, tx_start)

    def is_address_empty(self, address: str) -> bool:
        return self._is_key_empty(address)
