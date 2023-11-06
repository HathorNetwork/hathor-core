#  Copyright 2023 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import os
from typing import cast

from structlog import get_logger

from hathor.event.model.event_data import TxData
from hathor.event.model.event_type import EventType
from hathor.event.storage import EventRocksDBStorage
from hathor.storage import RocksDBStorage
from hathor.util import progress

ROCKSDB_PATH = os.environ['HATHOR_DATA']
OUTPUT_FILE = os.environ['DEBUG_EVENTS_OUTPUT_FILE']
TX_HASH = os.environ['DEBUG_EVENTS_TX_HASH']

log = get_logger().new()
rocksdb = RocksDBStorage(ROCKSDB_PATH)
event_storage = EventRocksDBStorage(rocksdb)

iter_events = event_storage.iter_from_event(0)
last_event = event_storage.get_last_event()
total_events = last_event.id + 1

log.info(f'total events: {total_events}')

event_counter = 1

with open(OUTPUT_FILE, mode='w') as file:
    for event in progress(iter_events, log=log, total=total_events):
        if (
            event.type in [EventType.NEW_VERTEX_ACCEPTED.value, EventType.VERTEX_METADATA_CHANGED.value]
            and cast(TxData, event.data).hash == TX_HASH
        ):
            file.write(event.json() + '\n')
            log.info(f'writing event #{event_counter} with id {event.id}')
            event_counter += 1
