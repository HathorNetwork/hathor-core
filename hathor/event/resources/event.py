#  Copyright 2023 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from itertools import islice
from typing import Optional

from pydantic import Field, NonNegativeInt
from twisted.web.http import Request

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, set_cors
from hathor.event import EventManager
from hathor.event.model.base_event import BaseEvent
from hathor.utils.api import ErrorResponse, QueryParams, Response

EVENT_API_DEFAULT_BATCH_SIZE: int = 100
EVENT_API_MAX_BATCH_SIZE: int = 1000


@register_resource
class EventResource(Resource):
    isLeaf = True

    def __init__(self, event_manager: Optional[EventManager]):
        super().__init__()
        self.event_manager = event_manager

    def render_GET(self, request: Request) -> bytes:
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        if not self.event_manager:
            request.setResponseCode(503)

            return ErrorResponse(error='EventManager unavailable.').json_dumpb()

        params = GetEventsParams.from_request(request)

        if isinstance(params, ErrorResponse):
            return params.json_dumpb()

        next_event_id = 0 if params.last_ack_event_id is None else params.last_ack_event_id + 1
        event_iter = self.event_manager.event_storage.iter_from_event(next_event_id)
        last_event = self.event_manager.event_storage.get_last_event()
        last_event_id = last_event.id if last_event is not None else None

        response = GetEventsResponse(
            latest_event_id=last_event_id,
            events=list(
                islice(event_iter, params.size)
            )
        )

        return response.json_dumpb()


class GetEventsParams(QueryParams):
    last_ack_event_id: Optional[NonNegativeInt] = None
    size: int = Field(default=EVENT_API_DEFAULT_BATCH_SIZE, ge=0, le=EVENT_API_MAX_BATCH_SIZE)


class GetEventsResponse(Response):
    events: list[BaseEvent]
    latest_event_id: Optional[int]


EventResource.openapi = {
    '/event': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '50r/s',
                    'burst': 100,
                    'delay': 50
                }
            ],
            'per-ip': [
                {
                    'rate': '1r/s',
                    'burst': 10,
                    'delay': 3
                }
            ]
        },
        'get': {
            'operationId': 'event',
            'summary': 'Hathor Events',
            'description': 'Returns information about past events',
            'parameters': [
                {
                    'name': 'last_ack_event_id',
                    'in': 'query',
                    'description': 'ID of last acknowledged event',
                    'required': False,
                    'schema': {
                        'type': 'int'
                    }
                },
                {
                    'name': 'size',
                    'in': 'query',
                    'description': 'Amount of events',
                    'required': False,
                    'schema': {
                        'type': 'int'
                    }
                }
            ],
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    "events": [
                                        {
                                            "peer_id": ("315d290c818091e5f01b8e52c45e7e24"
                                                        "f2558ba4376f423358fdc4c71d70da9a"),
                                            "id": 0,
                                            "timestamp": 1676332496.991634,
                                            "type": "consensus:tx_update",
                                            "data": {
                                                "hash": ("00000000030b86022eaea447484bd4d7"
                                                         "70be0fbd7e03678967f601c315673c5c")
                                            },
                                            "group_id": None
                                        },
                                        {
                                            "peer_id": ("315d290c818091e5f01b8e52c45e7e24"
                                                        "f2558ba4376f423358fdc4c71d70da9a"),
                                            "id": 1,
                                            "timestamp": 1676332497.1872509,
                                            "type": "network:new_tx_accepted",
                                            "data": {
                                                "hash": ("00000000030b86022eaea447484bd4d7"
                                                         "70be0fbd7e03678967f601c315673c5c")
                                            },
                                            "group_id": None
                                        }
                                    ],
                                    "latest_event_id": 342
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
