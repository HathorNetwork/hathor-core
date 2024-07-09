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

from dataclasses import asdict, dataclass, field
from typing import Callable, Iterator

from structlog import get_logger
from typing_extensions import override

from hathor.p2p.peer_id import PeerId
from hathor.storage.rocksdb_storage import RocksDBStorage
from hathor.util import json_dumpb, json_loadb

from .peer_discovery import PeerDiscovery

logger = get_logger()

_CF_NAME: bytes = b'known-peers'
PEER_FORGET_TIMEOUT = 3 * 24 * 3600  # forget a peer after 3 days


@dataclass
class _Record:
    """Python object to load each entry of the database into, to be used only within this module."""
    peer_id: str
    entrypoints: list[str] = field(default_factory=list)
    last_connection: int | None = None
    last_connection_attempt: int | None = None
    to_remove: bool = False


def record_to_bytes(record: _Record) -> bytes:
    """Serialize _Records into bytes using JSON."""
    return json_dumpb(asdict(record))


def bytes_to_record(raw_record: bytes) -> _Record:
    """Parse bytes into _Record entry."""
    return _Record(**json_loadb(raw_record))


def peerid_to_bytes(peerid: str) -> bytes:
    """Serialize peer-id into bytes by simply using byte equivalent of its hexadecimal representation."""
    return bytes.fromhex(peerid)


def bytes_to_peerid(raw_peerid: bytes) -> str:
    """Parse bytes into peer-id."""
    return raw_peerid.hex()


class StoragePeerDiscovery(PeerDiscovery):
    """ It implements a peer discovery strategy by simply trying to connect to known peers from previous starts.

    Entries use the following pattern:

        key   = [peer_id | 32 bytes]
        value = [JSON encoded record | variable size]

    Only peers which have had a sucessful handshake will be added to the storage because that's the only way to confirm
    their peer-id so they can have a unique key. All of their entrypoints will be tried as part of the "discover and
    connect" phase.

    After a failed connection attempt if it has passed more than PEER_FORGET_TIMEOUT, the entry will be marked for
    removal (which it means we won't try to connect to it on discovery), and then after another PEER_FORGET_TIMEOUT it
    will be removed (to give a chance for any peer that was just connected in the mean time).
    """

    def __init__(self, storage: RocksDBStorage):
        """ We need an RocksDBStorage to store entries into."""
        super().__init__()
        self.log = logger.new()
        self._db = storage.get_db()
        self._cf = storage.get_or_create_column_family(_CF_NAME)
        self.peer_forget_timeout = PEER_FORGET_TIMEOUT

    def _iter_records(self) -> Iterator[_Record]:
        """ Iterate over all records in the database."""
        it = self._db.itervalues(self._cf)
        it.seek_to_first()
        for raw_record in it:
            yield bytes_to_record(raw_record)

    def _iter_descriptors(self) -> Iterator[str]:
        """ Iterate over known peer descriptors that are stored in the database and are not marked for removal."""
        for record in self._iter_records():
            if record.to_remove:
                continue
            yield from iter(record.entrypoints)

    @override
    async def discover_and_connect(self, connect_to: Callable[[str], None]) -> None:
        for description in self._iter_descriptors():
            connect_to(description)

    def _remove(self, peer_id: str) -> None:
        """ Remove entry from database."""
        raw_peerid = peerid_to_bytes(peer_id)
        self._db.delete((self._cf, raw_peerid))

    def _get(self, peer_id: str) -> _Record | None:
        """ Get record with given peer_id, returns None if there's no record with the given peer_id."""
        raw_record = self._db.get((self._cf, peerid_to_bytes(peer_id)))
        if raw_record is None:
            return None
        record = bytes_to_record(raw_record)
        assert record.peer_id == peer_id
        return record

    def _put(self, record: _Record) -> None:
        """ Add or update record into the database, previous entry is replaced."""
        raw_peerid = peerid_to_bytes(record.peer_id)
        raw_record = record_to_bytes(record)
        self._db.put((self._cf, raw_peerid), raw_record)

    def _get_or_create(self, peer_id: str) -> _Record:
        """ Get a record with given peer_id, or create one if it doesn't exist."""
        if (record := self._get(peer_id)) is not None:
            return record
        else:
            return _Record(peer_id)

    def add_connected(self, peer: PeerId, now_timestamp: int) -> None:
        """ Add a peer that just connected, will update the last connection with the given timestamp."""
        assert peer.id is not None
        record = self._get_or_create(peer.id)
        record.to_remove = False  # if this node was marked for removal
        record.entrypoints = peer.entrypoints
        record.last_connection = now_timestamp
        self._put(record)

    def mark_try_to_connect(self, peer: PeerId, now_timestamp: int) -> None:
        """ Update the timestamp when we last tried to connect to a peer."""
        assert peer.id is not None
        record = self._get_or_create(peer.id)
        record.last_connection_attempt = now_timestamp
        self._put(record)

    def run_cleanup(self, now_timestamp: int) -> None:
        """ This should be called periodically so the database can be cleaned up."""
        for record in self._iter_records():
            # immediately remove record previously marked for removal
            if record.to_remove:
                self._remove(record.peer_id)
                continue

            # if for any reason there isn't a last_connection, we mark it for removal
            if record.last_connection is None:
                record.to_remove = True
                self._put(record)
                continue

            # if it passed too long, we mark for removal
            last_connection_delta = now_timestamp - record.last_connection
            if last_connection_delta > self.peer_forget_timeout:
                record.to_remove = True
                self._put(record)
                continue
