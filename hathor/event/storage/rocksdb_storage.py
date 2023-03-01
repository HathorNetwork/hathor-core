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

from typing import Iterator, Optional

from hathor.event.model.base_event import BaseEvent
from hathor.event.storage.event_storage import EventStorage
from hathor.storage.rocksdb_storage import RocksDBStorage
from hathor.transaction.util import int_to_bytes
from hathor.util import json_dumpb

_CF_NAME_EVENT = b'event'
_CF_NAME_META = b'event-metadata'
_KEY_LAST_GROUP_ID = b'last-group-id'


class EventRocksDBStorage(EventStorage):
    def __init__(self, rocksdb_storage: RocksDBStorage):
        self._db = rocksdb_storage.get_db()
        self._cf_event = rocksdb_storage.get_or_create_column_family(_CF_NAME_EVENT)
        self._cf_meta = rocksdb_storage.get_or_create_column_family(_CF_NAME_META)
        self._last_event: Optional[BaseEvent] = self._db_get_last_event()
        self._last_group_id: Optional[int] = self._db_get_last_group_id()

    def iter_from_event(self, key: int) -> Iterator[BaseEvent]:
        if key < 0:
            raise ValueError(f'event.id \'{key}\' must be non-negative')

        it = self._db.itervalues(self._cf_event)
        it.seek(int_to_bytes(key, 8))

        for event_bytes in it:
            yield BaseEvent.parse_raw(event_bytes)

    def _db_get_last_event(self) -> Optional[BaseEvent]:
        last_element: Optional[bytes] = None
        it = self._db.itervalues(self._cf_event)
        it.seek_to_last()
        # XXX: get last element by iterating once, this is simpler than a try/except
        for i in it:
            last_element = i
            break
        return None if last_element is None else BaseEvent.parse_raw(last_element)

    def _db_get_last_group_id(self) -> Optional[int]:
        last_group_id = self._db.get((self._cf_meta, _KEY_LAST_GROUP_ID))
        if last_group_id is None:
            return None
        return int.from_bytes(last_group_id, byteorder='big', signed=False)

    def save_event(self, event: BaseEvent) -> None:
        if (self._last_event is None and event.id != 0) or \
                (self._last_event is not None and event.id > self._last_event.id + 1):
            raise ValueError('invalid event.id, ids must be sequential and leave no gaps')
        event_data = json_dumpb(event.dict())
        key = int_to_bytes(event.id, 8)
        self._db.put((self._cf_event, key), event_data)
        self._last_event = event
        if event.group_id is not None:
            self._db.put((self._cf_meta, _KEY_LAST_GROUP_ID), int_to_bytes(event.group_id, 8))
            self._last_group_id = event.group_id

    def get_event(self, key: int) -> Optional[BaseEvent]:
        if key < 0:
            raise ValueError(f'event.id \'{key}\' must be non-negative')
        event = self._db.get((self._cf_event, int_to_bytes(key, 8)))
        if event is None:
            return None
        return BaseEvent.parse_raw(event)

    def get_last_event(self) -> Optional[BaseEvent]:
        return self._last_event

    def get_last_group_id(self) -> Optional[int]:
        return self._last_group_id
