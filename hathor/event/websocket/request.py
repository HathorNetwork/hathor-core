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

from typing import Annotated, Literal, Optional, Union

from pydantic import Discriminator, NonNegativeInt, RootModel, Tag

from hathor.utils.pydantic import BaseModel


class StartStreamRequest(BaseModel):
    """Class that represents a client request to start streaming events.

    Args:
        type: The type of the request.
        last_ack_event_id: The ID of the last event acknowledged by the client.
        window_size: The amount of events the client is able to process.
    """
    type: Literal['START_STREAM']
    last_ack_event_id: Optional[NonNegativeInt] = None
    window_size: NonNegativeInt


class AckRequest(BaseModel):
    """Class that represents a client request to ack and event and change the window size.

    Args:
        type: The type of the request.
        ack_event_id: The ID of the last event acknowledged by the client.
        window_size: The amount of events the client is able to process.
    """
    type: Literal['ACK']
    ack_event_id: NonNegativeInt
    window_size: NonNegativeInt


class StopStreamRequest(BaseModel):
    """Class that represents a client request to stop streaming events.

    Args:
        type: The type of the request.
    """
    type: Literal['STOP_STREAM']


Request = Annotated[
    Union[
        Annotated[StartStreamRequest, Tag('START_STREAM')],
        Annotated[AckRequest, Tag('ACK')],
        Annotated[StopStreamRequest, Tag('STOP_STREAM')],
    ],
    Discriminator('type')
]


class RequestWrapper(RootModel[Request]):
    """Class that wraps the Request union type for parsing."""

    @classmethod
    def parse_raw_request(cls, raw: bytes) -> Request:
        return cls.model_validate_json(raw).root
