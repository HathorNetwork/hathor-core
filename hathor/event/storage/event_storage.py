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

from abc import ABC, abstractmethod
from typing import Iterable, Iterator, Optional

from hathor.event.model.base_event import BaseEvent
from hathor.event.model.node_state import NodeState


class EventStorage(ABC):
    @abstractmethod
    def save_event(self, event: BaseEvent) -> None:
        """ Saves an event in the storage"""
        raise NotImplementedError

    @abstractmethod
    def save_events(self, events: Iterable[BaseEvent]) -> None:
        """ Saves an event batch in the storage"""
        raise NotImplementedError

    @abstractmethod
    def get_event(self, key: int) -> Optional[BaseEvent]:
        """ Get a stored event by key"""
        raise NotImplementedError

    @abstractmethod
    def get_last_event(self) -> Optional[BaseEvent]:
        """ Get the last event that was emitted, this is used to help resume when restarting."""
        raise NotImplementedError

    @abstractmethod
    def get_last_group_id(self) -> Optional[int]:
        """ Get the last group-id that was emitted, this is used to help resume when restarting."""
        raise NotImplementedError

    @abstractmethod
    def iter_from_event(self, key: int) -> Iterator[BaseEvent]:
        """ Iterate through events starting from the event with the given key"""
        raise NotImplementedError

    @abstractmethod
    def reset_events(self) -> None:
        """
        Reset event-related data: events, last_event, last_group_id, and stream_id.
        This should be used to clear old events from the database when reloading events.
        """
        raise NotImplementedError

    @abstractmethod
    def reset_all(self) -> None:
        """
        Reset all data and metadata: events, last_event, last_group_id, stream_id, node_state, and event_queue_enabled.
        This should be used for a full wipe out of the event storage.
        """
        raise NotImplementedError

    @abstractmethod
    def save_node_state(self, state: NodeState) -> None:
        """Save a node state in the storage"""
        raise NotImplementedError

    @abstractmethod
    def get_node_state(self) -> Optional[NodeState]:
        """Get the node state from the storage"""
        raise NotImplementedError

    @abstractmethod
    def save_event_queue_state(self, enabled: bool) -> None:
        """Save whether the event queue feature is enabled in the storage"""
        raise NotImplementedError

    @abstractmethod
    def get_event_queue_state(self) -> bool:
        """Get whether the event queue feature is enabled from the storage"""
        raise NotImplementedError

    @abstractmethod
    def save_stream_id(self, stream_id: str) -> None:
        """Save the Stream ID."""
        raise NotImplementedError

    @abstractmethod
    def get_stream_id(self) -> Optional[str]:
        """Get the Stream ID."""
        raise NotImplementedError
