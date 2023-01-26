# Copyright 2023 Hathor Labs
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

from dataclasses import dataclass, field
from enum import Enum
from typing import TypeVar, Generic

from hathor.event import BaseEvent

T = TypeVar('T')


class ResponseType(Enum):
    START_STREAMING_EVENTS = 'START_STREAMING_EVENTS'
    STOP_STREAMING_EVENTS = 'STOP_STREAMING_EVENTS'
    GET_EVENT = 'GET_EVENT'
    NEW_EVENT = 'NEW_EVENT'


@dataclass
class Response(Generic[T]):
    type: ResponseType
    data: T = field(default=None)


@dataclass
class StopStreamingResponseData:
    event_id: int


@dataclass
class EventResponseData:
    event: BaseEvent
