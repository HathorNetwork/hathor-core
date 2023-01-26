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

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Union, Dict


class RequestType(Enum):
    START_STREAMING_EVENTS = 'START_STREAMING_EVENTS'
    STOP_STREAMING_EVENTS = 'STOP_STREAMING_EVENTS'
    GET_EVENT = 'GET_EVENT'

    @classmethod
    def values(cls):
        return [t.value for t in cls]


@dataclass
class RequestError:
    message: str


@dataclass
class Request:
    type: RequestType
    event_id: int

    @classmethod
    def from_dict(cls, request_dict: Dict) -> Union[Request | RequestError]:
        raw_request_type = request_dict.get('type')
        event_id = request_dict.get('event_id')

        try:
            request_type = RequestType[raw_request_type]
        except KeyError:
            return RequestError(
                f'Unknown request type \'{raw_request_type}\'. Known types are {RequestType.values()}.'
            )

        if request_type == RequestType.GET_EVENT and event_id is None:
            return RequestError(f'Missing \'event_id\'.')

        event_id = event_id or 0

        if request_type in [RequestType.START_STREAMING_EVENTS, RequestType.GET_EVENT]:
            if not isinstance(event_id, int) or event_id < 0:
                return RequestError(f'Invalid \'event_id\': {event_id}. Must be a positive integer.')

        return Request(request_type, event_id)
