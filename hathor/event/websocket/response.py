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
from enum import Enum
from typing import Any, Dict, List

from pydantic import Field, NonNegativeInt

from hathor.event import BaseEvent
from hathor.utils.pydantic import BaseModel


class ResponseType(Enum):
    """Class representing event WebSocket response types."""

    EVENT = 'EVENT'
    BAD_REQUEST = 'BAD_REQUEST'
    EVENT_WS_NOT_RUNNING = 'EVENT_WS_NOT_RUNNING'


class EventResponse(BaseModel, use_enum_values=True):
    """Class that represents an event to be sent to the client.

    Args:
        event: The event.
        latest_event_id: The ID of the latest event known by the server.
    """

    type: str = Field(default=ResponseType.EVENT.value, const=True)
    event: BaseEvent
    latest_event_id: NonNegativeInt


class BadRequestResponse(BaseModel, use_enum_values=True):
    """Class to let the client know that it performed a bad request.

    Args:
        errors: A list of error details, as generated by ValidationError.errors().
    """

    type: str = Field(default=ResponseType.BAD_REQUEST.value, const=True)
    errors: List[Dict[str, Any]]


class EventWebSocketNotRunningResponse(BaseModel, use_enum_values=True):
    """Class to let the client know that WebSocket server is not running."""

    type: str = Field(default=ResponseType.EVENT_WS_NOT_RUNNING.value, const=True)
