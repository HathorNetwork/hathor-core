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
from typing import List, Optional

from pydantic import NonNegativeInt, conint

from hathor.api_util import Resource, set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.conf import HathorSettings
from hathor.event import BaseEvent
from hathor.manager import HathorManager
from hathor.utils.api import QueryParams, ErrorResponse, Response

settings = HathorSettings()


@register_resource
class EventResource(Resource):
    isLeaf = True

    def __init__(self, manager: HathorManager):
        super().__init__()
        self.manager = manager

    def render_GET(self, request):
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        if not self.manager.event_manager:
            request.setResponseCode(503)

            return ErrorResponse(error='EventManager unavailable.').json_dumpb()

        params = GetEventsParams.from_request(request)

        if isinstance(params, ErrorResponse):
            return params.json_dumpb()

        next_event_id = 0 if params.last_ack_event_id is None else params.last_ack_event_id + 1
        event_iter = self.manager.event_manager.event_storage.iter_from_event(next_event_id)
        last_event = self.manager.event_manager.event_storage.get_last_event()
        last_event_id = last_event.id if last_event is not None else None

        response = GetEventsResponse(
            latest_event_id=last_event_id,
            events=list(
                islice(event_iter, params.size)
            )
        )

        return response.json_dumpb()

# MiningStatsResource.openapi = {


class GetEventsParams(QueryParams):
    last_ack_event_id: Optional[NonNegativeInt]
    size: conint(ge=0, le=settings.EVENT_API_MAX_BATCH_SIZE) = settings.EVENT_API_DEFAULT_BATCH_SIZE


class GetEventsResponse(Response):
    events: List[BaseEvent]
    latest_event_id: Optional[int]
