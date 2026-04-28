# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from enum import Enum
from typing import Literal, Optional

from pydantic import ConfigDict, NonNegativeInt

from hathor.api.asyncapi.decorators import ws_message
from hathor.api.asyncapi.generator import MessageDirection
from hathor.event.model.base_event import BaseEvent
from hathor.utils.pydantic import BaseModel


class Response(BaseModel):
    pass


@ws_message(
    name='event',
    direction=MessageDirection.SEND,
    summary='Event notification',
    description='An event from the full node.',
    tags=['events'],
)
class EventResponse(Response):
    """Class that represents an event to be sent to the client.

    Args:
        type: The type of the response.
        peer_id: Full node id, because different full nodes can have different sequences of events.
        network: The network for which this event was generated.
        event: The event.
        latest_event_id: The ID of the latest event known by the server.
        stream_id: The ID of the current stream.
    """

    type: Literal['EVENT'] = 'EVENT'
    peer_id: str
    network: str
    event: BaseEvent
    latest_event_id: NonNegativeInt
    stream_id: str


class InvalidRequestType(Enum):
    EVENT_WS_NOT_RUNNING = 'EVENT_WS_NOT_RUNNING'
    STREAM_IS_ACTIVE = 'STREAM_IS_ACTIVE'
    STREAM_IS_INACTIVE = 'STREAM_IS_INACTIVE'
    VALIDATION_ERROR = 'VALIDATION_ERROR'
    ACK_TOO_SMALL = 'ACK_TOO_SMALL'
    ACK_TOO_LARGE = 'ACK_TOO_LARGE'


@ws_message(
    name='invalidRequest',
    direction=MessageDirection.SEND,
    summary='Invalid request error',
    description='Sent when the client sends an invalid request.',
    tags=['error'],
)
class InvalidRequestResponse(Response):
    """Class to let the client know that it performed an invalid request.

    Args:
        type: The type of the response.
        invalid_request: The request that was invalid.
        error_message: A message describing why the request was invalid.
    """
    model_config = ConfigDict(use_enum_values=True)

    type: InvalidRequestType
    invalid_request: Optional[str]
    error_message: Optional[str]
