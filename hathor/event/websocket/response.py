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
from typing import Optional

from pydantic import Field, NonNegativeInt

from hathor.event import BaseEvent
from hathor.utils.pydantic import BaseModel


class Response(BaseModel):
    pass


class EventResponse(Response):
    """Class that represents an event to be sent to the client.

    Args:
        type: The type of the response.
        event: The event.
        latest_event_id: The ID of the latest event known by the server.
    """

    type: str = Field(default='EVENT', const=True)
    event: BaseEvent
    latest_event_id: NonNegativeInt


class InvalidRequestType(Enum):
    EVENT_WS_NOT_RUNNING = 'EVENT_WS_NOT_RUNNING'
    STREAM_IS_ACTIVE = 'STREAM_IS_ACTIVE'
    STREAM_IS_INACTIVE = 'STREAM_IS_INACTIVE'
    VALIDATION_ERROR = 'VALIDATION_ERROR'
    ACK_TOO_SMALL = 'ACK_TOO_SMALL'
    ACK_TOO_LARGE = 'ACK_TOO_LARGE'


class InvalidRequestResponse(Response, use_enum_values=True):
    """Class to let the client know that it performed an invalid request.

    Args:
        type: The type of the response.
        invalid_request: The request that was invalid.
        error_message: A message describing why the request was invalid.
    """

    type: InvalidRequestType
    invalid_request: str
    error_message: Optional[str]
