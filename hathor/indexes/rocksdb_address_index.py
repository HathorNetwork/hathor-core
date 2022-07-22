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

from typing import TYPE_CHECKING, Iterable, List, Optional, Tuple

from structlog import get_logger

from hathor.indexes.address_index import AddressIndex
from hathor.indexes.rocksdb_utils import RocksDBIndexUtils
from hathor.pubsub import HathorEvents
from hathor.transaction import BaseTransaction

if TYPE_CHECKING:  # pragma: no cover
    import rocksdb

    from hathor.pubsub import EventArguments, PubSubManager

logger = get_logger()

_CF_NAME_ADDRESS_INDEX = b'address-index'
_DB_NAME: str = 'address'


class RocksDBAddressIndex(AddressIndex, RocksDBIndexUtils):
    """ Index of inputs/outputs by address.

    This index uses rocksdb and the following key format:

        key = [address][tx.timestamp][tx.hash]
              |--34b--||--4 bytes---||--32b--|

    It works nicely because rocksdb uses a tree sorted by key under the hood.

    The timestamp must be serialized in big-endian, so ts1 > ts2 implies that bytes(ts1) > bytes(ts2),
    hence the transactions are sorted by timestamp.
    """
    def __init__(self, db: 'rocksdb.DB', *, cf_name: Optional[bytes] = None,
                 pubsub: Optional['PubSubManager'] = None) -> None:
        self.log = logger.new()
        RocksDBIndexUtils.__init__(self, db, cf_name or _CF_NAME_ADDRESS_INDEX)

        self.pubsub = pubsub
        if self.pubsub:
            self.subscribe_pubsub_events()

    def get_db_name(self) -> Optional[str]:
        # XXX: we don't need it to be parametrizable, so this is fine
        return _DB_NAME

    def force_clear(self) -> None:
        self.clear()

    def _to_key(self, address: str, tx: Optional[BaseTransaction] = None) -> bytes:
        import struct
        assert len(address) == 34
        key = address.encode('ascii')
        if tx:
            assert tx.hash is not None
            assert len(tx.hash) == 32
            key += struct.pack('>I', tx.timestamp) + tx.hash
            assert len(key) == 34 + 4 + 32
        return key

    def _from_key(self, key: bytes) -> Tuple[str, int, bytes]:
        import struct
        assert len(key) == 34 + 4 + 32
        address = key[:34].decode('ascii')
        timestamp: int
        (timestamp,) = struct.unpack('>I', key[34:38])
        tx_hash = key[38:]
        assert len(address) == 34
        assert len(tx_hash) == 32
        return address, timestamp, tx_hash

    def subscribe_pubsub_events(self) -> None:
        """ Subscribe wallet index to receive voided/winner tx pubsub events
        """
        assert self.pubsub is not None
        # Subscribe to voided/winner events
        events = [HathorEvents.STORAGE_TX_VOIDED, HathorEvents.STORAGE_TX_WINNER]
        for event in events:
            self.pubsub.subscribe(event, self.handle_tx_event)

    def add_tx(self, tx: BaseTransaction) -> None:
        """ Add tx inputs and outputs to the wallet index (indexed by its addresses).
        """
        assert tx.hash is not None

        addresses = tx.get_related_addresses()
        for address in addresses:
            self.log.debug('put address', address=address)
            self._db.put((self._cf, self._to_key(address, tx)), b'')

        self.publish_tx(tx, addresses=addresses)

    def remove_tx(self, tx: BaseTransaction) -> None:
        """ Remove tx inputs and outputs from the wallet index (indexed by its addresses).
        """
        assert tx.hash is not None

        addresses = tx.get_related_addresses()
        for address in addresses:
            self.log.debug('delete address', address=address)
            self._db.delete((self._cf, self._to_key(address, tx)))

    def handle_tx_event(self, key: HathorEvents, args: 'EventArguments') -> None:
        """ This method is called when pubsub publishes an event that we subscribed
        """
        data = args.__dict__
        tx = data['tx']
        meta = tx.get_metadata()
        if meta.has_voided_by_changed_since_last_call() or meta.has_spent_by_changed_since_last_call():
            self.publish_tx(tx)

    def _get_from_address_iter(self, address: str) -> Iterable[bytes]:
        self.log.debug('seek to', address=address)
        it = self._db.iterkeys(self._cf)
        it.seek(self._to_key(address))
        for _cf, key in it:
            addr, _, tx_hash = self._from_key(key)
            if addr != address:
                break
            self.log.debug('seek found', tx=tx_hash.hex())
            yield tx_hash
        self.log.debug('seek end')

    def get_from_address(self, address: str) -> List[bytes]:
        """ Get list of transaction hashes of an address
        """
        return list(self._get_from_address_iter(address))

    def get_sorted_from_address(self, address: str) -> List[bytes]:
        """ Get a sorted list of transaction hashes of an address
        """
        return list(self._get_from_address_iter(address))

    def is_address_empty(self, address: str) -> bool:
        self.log.debug('seek to', address=address)
        it = self._db.iterkeys(self._cf)
        it.seek(self._to_key(address))
        res = it.get()
        if not res:
            return True
        _cf, key = res
        addr, _, _ = self._from_key(key)
        is_empty = addr != address
        self.log.debug('seek empty', is_empty=is_empty)
        return is_empty
