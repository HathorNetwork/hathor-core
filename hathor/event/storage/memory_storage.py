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

from hathor.event.model.base_event import BaseEvent
from hathor.event.model.node_state import NodeState
from hathor.event.storage.event_storage import EventStorage


class EventMemoryStorage(EventStorage):
    def __init__(self):
        self._events: List[BaseEvent] = []
        self._last_event: Optional[BaseEvent] = None
        self._last_group_id: Optional[int] = None
        self._node_state: Optional[NodeState] = None
        self._event_queue_enabled: bool = False

    def save_event(self, event: BaseEvent) -> None:
        if event.id != len(self._events):
            raise ValueError('invalid event.id, ids must be sequential and leave no gaps')
        self._last_event = event
        if event.group_id is not None:
            self._last_group_id = event.group_id
        self._events.append(event)

    def get_event(self, key: int) -> Optional[BaseEvent]:
        if key < 0:
            raise ValueError(f'event.id \'{key}\' must be non-negative')
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
        if key < 0:
            raise ValueError(f'event.id \'{key}\' must be non-negative')

        while key < len(self._events):
            yield self._events[key]
            key += 1

    def clear_events(self) -> None:
        self._events = []
        self._last_event = None
        self._last_group_id = None

    def save_node_state(self, state: NodeState) -> None:
        self._node_state = state

    def get_node_state(self) -> Optional[NodeState]:
        return self._node_state

    def save_event_queue_enabled(self) -> None:
        self._event_queue_enabled = True

    def save_event_queue_disabled(self) -> None:
        self._event_queue_enabled = False

    def get_event_queue_state(self) -> bool:
        return self._event_queue_enabled
