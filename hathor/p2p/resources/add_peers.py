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

from json import JSONDecodeError

from twisted.internet.defer import Deferred
from twisted.web.http import Request

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, render_options, set_cors
from hathor.manager import HathorManager
from hathor.p2p.peer_discovery import BootstrapPeerDiscovery
from hathor.p2p.peer_endpoint import PeerEndpoint
from hathor.util import json_dumpb, json_loadb


@register_resource
class AddPeersResource(Resource):
    """ Implements a web server API a POST to add p2p peers.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: HathorManager) -> None:
        self.manager = manager

    def render_POST(self, request: Request) -> bytes:
        """ Add p2p peers
            It expects a list of peers, in the format protocol://host:port (tcp://172.121.212.12:40403)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        assert request.content is not None
        raw_data = request.content.read()
        if raw_data is None:
            return json_dumpb({'success': False, 'message': 'No post data'})

        try:
            raw_entrypoints = json_loadb(raw_data)
        except (JSONDecodeError, AttributeError):
            return json_dumpb({'success': False, 'message': 'Invalid format for post data'})

        if not isinstance(raw_entrypoints, list):
            return json_dumpb({
                'success': False,
                'message': 'Invalid format for post data. It was expected a list of strings.'
            })

        try:
            entrypoints = list(map(PeerEndpoint.parse, raw_entrypoints))
        except ValueError:
            return json_dumpb({
                'success': False,
                'message': 'Malformed entrypoint found.'
            })

        known_peers = self.manager.connections.verified_peer_storage.values()

        def already_connected(endpoint: PeerEndpoint) -> bool:
            # ignore peers that we're already trying to connect
            for ready_endpoint in self.manager.connections.iter_not_ready_endpoints():
                if endpoint.addr == ready_endpoint.addr:
                    return True

            # remove peers we already know about
            for peer in known_peers:
                if endpoint.addr in peer.info.entrypoints:
                    return True

            return False

        filtered_peers = [entrypoint for entrypoint in entrypoints if not already_connected(entrypoint)]

        pd = BootstrapPeerDiscovery(filtered_peers)
        # this fires and forget the coroutine, which is compatible with the original behavior
        coro = pd.discover_and_connect(self.manager.connections.connect_to_endpoint)
        Deferred.fromCoroutine(coro)

        ret = {'success': True, 'peers': [str(p) for p in filtered_peers]}
        return json_dumpb(ret)

    def render_OPTIONS(self, request: Request) -> int:
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
