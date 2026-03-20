# Copyright 2022 Hathor Labs
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

from typing import TYPE_CHECKING, Iterable, Iterator, Optional, Union

from hathor.event.model.base_event import BaseEvent
from hathor.event.model.node_state import NodeState
from hathor.event.storage.event_storage import EventStorage
from hathor.storage.rocksdb_storage import RocksDBStorage
from hathor.transaction.util import bytes_to_int, int_to_bytes
from hathor.util import json_dumpb

if TYPE_CHECKING:
    import rocksdb


_CF_NAME_EVENT = b'event'
_CF_NAME_META = b'event-metadata'
_KEY_LAST_GROUP_ID = b'last-group-id'
_KEY_NODE_STATE = b'node-state'
_KEY_EVENT_QUEUE_ENABLED = b'event-queue-enabled'
_KEY_STREAM_ID = b'stream-id'


class EventRocksDBStorage(EventStorage):
    def __init__(self, rocksdb_storage: RocksDBStorage):
        self._rocksdb_storage = rocksdb_storage

        self._db = self._rocksdb_storage.get_db()
        self._cf_event = self._rocksdb_storage.get_or_create_column_family(_CF_NAME_EVENT)
        self._cf_meta = self._rocksdb_storage.get_or_create_column_family(_CF_NAME_META)

        self._last_event: Optional[BaseEvent] = self._db_get_last_event()
        self._last_group_id: Optional[int] = self._db_get_last_group_id()

    def iter_from_event(self, key: int) -> Iterator[BaseEvent]:
        if key < 0:
            raise ValueError(f'event.id \'{key}\' must be non-negative')

        it = self._db.itervalues(self._cf_event)
        it.seek(int_to_bytes(key, 8))

        for event_bytes in it:
            yield BaseEvent.model_validate_json(event_bytes)

        # XXX: on Python 3.12, not deleting it here can cause EXC_BAD_ACCESS if the db is released before the iterator
        #      in the garbage collector. This race condition might happen between tests.
        del it

    def _db_get_last_event(self) -> Optional[BaseEvent]:
        last_element: Optional[bytes] = None
        it = self._db.itervalues(self._cf_event)
        it.seek_to_last()
        # XXX: get last element by iterating once, this is simpler than a try/except
        for i in it:
            last_element = i
            break
        return None if last_element is None else BaseEvent.model_validate_json(last_element)

    def _db_get_last_group_id(self) -> Optional[int]:
        last_group_id = self._db.get((self._cf_meta, _KEY_LAST_GROUP_ID))
        if last_group_id is None:
            return None
        return bytes_to_int(last_group_id)

    def save_event(self, event: BaseEvent) -> None:
        self._save_event(event, database=self._db)

    def _save_event(self, event: BaseEvent, *, database: Union['rocksdb.DB', 'rocksdb.WriteBatch']) -> None:
        if (self._last_event is None and event.id != 0) or \
                (self._last_event is not None and event.id != self._last_event.id + 1):
            raise ValueError('invalid event.id, ids must be sequential and leave no gaps')
        event_data = json_dumpb(event.model_dump())
        key = int_to_bytes(event.id, 8)
        database.put((self._cf_event, key), event_data)
        self._last_event = event
        if event.group_id is not None:
            database.put((self._cf_meta, _KEY_LAST_GROUP_ID), int_to_bytes(event.group_id, 8))
            self._last_group_id = event.group_id

    def save_events(self, events: Iterable[BaseEvent]) -> None:
        import rocksdb
        batch = rocksdb.WriteBatch()

        for event in events:
            self._save_event(event, database=batch)

        self._db.write(batch)

    def get_event(self, key: int) -> Optional[BaseEvent]:
        if key < 0:
            raise ValueError(f'event.id \'{key}\' must be non-negative')
        event = self._db.get((self._cf_event, int_to_bytes(key, 8)))
        if event is None:
            return None
        return BaseEvent.model_validate_json(event)

    def get_last_event(self) -> Optional[BaseEvent]:
        return self._last_event

    def get_last_group_id(self) -> Optional[int]:
        return self._last_group_id

    def reset_events(self) -> None:
        self._last_event = None
        self._last_group_id = None

        self._db.delete((self._cf_meta, _KEY_LAST_GROUP_ID))
        self._db.delete((self._cf_meta, _KEY_STREAM_ID))
        self._db.drop_column_family(self._cf_event)

        self._cf_event = self._rocksdb_storage.get_or_create_column_family(_CF_NAME_EVENT)

    def reset_all(self) -> None:
        self.reset_events()
        self._db.delete((self._cf_meta, _KEY_NODE_STATE))
        self._db.delete((self._cf_meta, _KEY_EVENT_QUEUE_ENABLED))

    def save_node_state(self, state: NodeState) -> None:
        self._db.put((self._cf_meta, _KEY_NODE_STATE), int_to_bytes(state.value, 8))

    def get_node_state(self) -> Optional[NodeState]:
        node_state_bytes = self._db.get((self._cf_meta, _KEY_NODE_STATE))

        if node_state_bytes is None:
            return None

        node_state_int = bytes_to_int(node_state_bytes)

        return NodeState(node_state_int)

    def save_event_queue_state(self, enabled: bool) -> None:
        self._db.put(
            (self._cf_meta, _KEY_EVENT_QUEUE_ENABLED),
            enabled.to_bytes(length=1, byteorder='big')
        )

    def get_event_queue_state(self) -> bool:
        enabled_bytes = self._db.get((self._cf_meta, _KEY_EVENT_QUEUE_ENABLED))

        if enabled_bytes is None:
            return False

        return bool.from_bytes(enabled_bytes, byteorder='big')

    def save_stream_id(self, stream_id: str) -> None:
        self._db.put(
            (self._cf_meta, _KEY_STREAM_ID),
            stream_id.encode('utf8')
        )

    def get_stream_id(self) -> Optional[str]:
        stream_id_bytes: bytes = self._db.get((self._cf_meta, _KEY_STREAM_ID))

        if stream_id_bytes is None:
            return None

        return stream_id_bytes.decode('utf8')
