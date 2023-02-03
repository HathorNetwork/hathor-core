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

from typing import Iterator, List, Optional

from hathor.event.base_event import BaseEvent
from hathor.event.storage.event_storage import EventStorage


class EventMemoryStorage(EventStorage):
    def __init__(self):
        self._events: List[BaseEvent] = []
        self._last_event: Optional[BaseEvent] = None
        self._last_group_id: Optional[int] = None

    def save_event(self, event: BaseEvent) -> None:
        if event.id < 0:
            raise ValueError('event.id must be non-negative')
        if event.id != len(self._events):
            raise ValueError('invalid event.id, ids must be sequential and leave no gaps')
        self._last_event = event
        if event.group_id is not None:
            self._last_group_id = event.group_id
        self._events.append(event)

    def get_event(self, key: int) -> Optional[BaseEvent]:
        if key < 0:
            raise ValueError('key must be non-negative')
        if key >= len(self._events):
            return None
        event = self._events[key]
        assert event.id == key
        return event

    def get_last_event(self) -> Optional[BaseEvent]:
        return self._last_event

    def get_last_group_id(self) -> Optional[int]:
        return self._last_group_id

    def iter_from_event(self, key: int) -> Iterator[BaseEvent]:
        while key < len(self._events):
            yield self._events[key]
            key += 1
