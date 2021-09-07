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

import json

from twisted.web import resource

from hathor.api_util import render_options, set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.p2p.peer_discovery import BootstrapPeerDiscovery


@register_resource
class AddPeersResource(resource.Resource):
    """ Implements a web server API a POST to add p2p peers.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_POST(self, request):
        """ Add p2p peers
            It expects a list of peers, in the format protocol://host:port (tcp://172.121.212.12:40403)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        try:
            peers = json.loads(request.content.read().decode('utf-8'))
        except (json.JSONDecodeError, AttributeError):
            return json.dumps({'success': False, 'message': 'Invalid format for post data'}).encode('utf-8')

        if not isinstance(peers, list):
            return json.dumps({
                'success': False,
                'message': 'Invalid format for post data. It was expected a list of strings.'
            }).encode('utf-8')

        known_peers = self.manager.connections.peer_storage.values()

        def already_connected(connection_string: str) -> bool:
            # determines if given connection string is already among connected or connecting peers
            endpoint_url = connection_string.replace('//', '')

            # ignore peers that we're already trying to connect
            if endpoint_url in self.manager.connections.iter_not_ready_endpoints():
                return True

            # remove peers we already know about
            for peer in known_peers:
                if connection_string in peer.entrypoints:
                    return True

            return False

        filtered_peers = [connection_string for connection_string in peers if not already_connected(connection_string)]

        pd = BootstrapPeerDiscovery(filtered_peers)
        pd.discover_and_connect(self.manager.connections.connect_to)

        ret = {'success': True, 'peers': filtered_peers}
        return json.dumps(ret, indent=4).encode('utf-8')

    def render_OPTIONS(self, request):
        return render_options(request)


AddPeersResource.openapi = {
    '/p2p/peers': {
        'x-visibility': 'private',
        'post': {
            'tags': ['p2p'],
            'operationId': 'p2p_peers',
            'summary': 'Add p2p peers',
            'description': 'Connect to the given peers',
            'requestBody': {
                'description': 'Peers you want to connect to',
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {
                            'type': 'array',
                            'description': 'List of peers to connect in the format "protocol://host:port"',
                            'items': {
                                'type': 'string'
                            }
                        },
                        'examples': {
                            'peer_list': {
                                'summary': 'List of peers',
                                'value': ['tcp:localhost:8000', 'tcp:17.24.137.234:40403']
                            },
                        }
                    }
                }
            },
            'responses': {
                '200': {
                    'description': 'The peers we connected to (we don\'t try connecting to already known peers)',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Peers added',
                                    'value': {
                                        'success': True,
                                        'peers': ['tcp:localhost:8000', 'tcp:17.24.137.234:40403']
                                    }
                                },
                                'error': {
                                    'summary': 'Invalid data',
                                    'value': {
                                        'success': False,
                                        'message': 'Invalid format for post data',
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
