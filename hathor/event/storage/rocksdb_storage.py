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

import json
from typing import Optional

from hathor.event.base_event import BaseEvent
from hathor.event.storage.event_storage import EventStorage
from hathor.storage.rocksdb_storage import RocksDBStorage
from hathor.transaction.util import int_to_bytes

_CF_NAME_EVENT = b'event'


class EventRocksDBStorage(EventStorage):
    def __init__(self, rocksdb_storage: RocksDBStorage):
        self._db = rocksdb_storage.get_db()
        self._cf_event = rocksdb_storage.get_or_create_column_family(_CF_NAME_EVENT)

    def save_event(self, event: BaseEvent) -> None:
        """ Saves the dict representation of the event inside the database.
        """
        event_data = json.dumps(event.__dict__, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        key = int_to_bytes(event.id, 8)
        self._db.put((self._cf_event, key), event_data)

    def get_event(self, key: int) -> Optional[BaseEvent]:
        """ Get the event JSON representation as a string from the database
        """
        if key < 0:
            raise ValueError('key must be non-negative')

        event = self._db.get((self._cf_event, int_to_bytes(key, 8)))
        if event is None:
            return None

        return self._load_from_bytes(event_data=event)

    def _load_from_bytes(self, event_data: bytes) -> BaseEvent:
        event_json = event_data.decode('utf-8')
        event_dict = json.loads(event_json)

        return BaseEvent(
            id=event_dict['id'],
            peer_id=event_dict['peer_id'],
            timestamp=event_dict['timestamp'],
            type=event_dict['type'],
            group_id=event_dict['group_id'],
            data=event_dict['data'],
        )
