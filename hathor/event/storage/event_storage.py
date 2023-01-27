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
from typing import Iterator, Optional

from hathor.event.base_event import BaseEvent


class EventStorage(ABC):
    @abstractmethod
    def save_event(self, event: BaseEvent) -> None:
        """ Saves an event in the storage"""
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
    def iter_events(self, from_event_id: int, max_amount: int) -> Iterator[BaseEvent]:
        """ Iterate through events starting from the event with the given id, yielding up to the provided amount"""
        raise NotImplementedError
