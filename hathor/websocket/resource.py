# Copyright 2021 Hathor Labs
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

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, set_cors
from hathor.util import json_dumpb


@register_resource
class WebsocketStatsResource(Resource):
    """ Implements a web server API to return stats from Websocket

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, websocket_factory):
        # Important to have the websocket_factory, so we can have the connections
        self.websocket_factory = websocket_factory

    def render_GET(self, request):
        """ GET request for /websocket_stats/ that returns the stats from Websocket

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        data = {
            'connections': len(self.websocket_factory.connections),
            'subscribed_addresses': len(self.websocket_factory.address_connections),
        }
        return json_dumpb(data)


WebsocketStatsResource.openapi = {
    '/websocket_stats': {
        'x-visibility': 'private',
        'get': {
            'operationId': 'websocket_stats',
            'summary': 'Websocket stats',
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Success',
                                    'value': {
                                        'connections': 4,
                                        'addresses': 6,
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
