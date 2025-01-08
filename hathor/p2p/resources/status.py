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

import hathor
from hathor._openapi.register import register_resource
from hathor.api_util import Resource, set_cors
from hathor.conf.get_settings import get_global_settings
from hathor.p2p.utils import to_serializable_best_blockchain
from hathor.util import json_dumpb


@register_resource
class StatusResource(Resource):
    """ Implements an status web server API, which responds with a summary
    of the node state.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self._settings = get_global_settings()
        self.manager = manager
        self.reactor = manager.reactor

    def render_GET(self, request):
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        now = self.reactor.seconds()

        connecting_peers = []
        # TODO: refactor as not to use a private item
        for endpoint, deferred in self.manager.connections.connecting_peers.items():
            host = getattr(endpoint, '_host', '')
            port = getattr(endpoint, '_port', '')
            connecting_peers.append({'deferred': str(deferred), 'address': '{}:{}'.format(host, port)})

        handshaking_peers = []
        # TODO: refactor as not to use a private item
        for conn in self.manager.connections.handshaking_peers:
            remote = conn.transport.getPeer()
            handshaking_peers.append({
                'address': '{}:{}'.format(remote.host, remote.port),
                'state': conn.state.state_name,
                'uptime': now - conn.connection_time,
                'app_version': conn.app_version,
            })

        connected_peers = []
        for conn in self.manager.connections.iter_ready_connections():
            remote = conn.transport.getPeer()
            status = {}
            status[conn.state.sync_agent.name] = conn.state.sync_agent.get_status()
            connected_peers.append({
                'id': str(conn.peer.id),
                'app_version': conn.app_version,
                'current_time': now,
                'uptime': now - conn.connection_time,
                'address': '{}:{}'.format(remote.host, remote.port),
                'state': conn.state.state_name,
                # 'received_bytes': conn.received_bytes,
                'rtt': list(conn.state.rtt_window),
                'last_message': now - conn.last_message,
                'plugins': status,
                'warning_flags': [flag.value for flag in conn.warning_flags],
                'protocol_version': str(conn.sync_version),
                'peer_best_blockchain': to_serializable_best_blockchain(conn.state.peer_best_blockchain),
            })

        known_peers = []
        for peer in self.manager.connections.verified_peer_storage.values():
            known_peers.append({
                'id': str(peer.id),
                'entrypoints': peer.info.entrypoints_as_str(),
                'last_seen': now - peer.info.last_seen,
                'flags': [flag.value for flag in peer.info.flags],
            })

        app = 'Hathor v{}'.format(hathor.__version__)

        best_block = self.manager.tx_storage.get_best_block()
        raw_best_blockchain = self.manager.tx_storage.get_n_height_tips(self._settings.DEFAULT_BEST_BLOCKCHAIN_BLOCKS)
        best_blockchain = to_serializable_best_blockchain(raw_best_blockchain)
        best_block_tips = [{'hash': best_block.hash_hex, 'height': best_block.static_metadata.height}]

        data = {
            'server': {
                'id': str(self.manager.connections.my_peer.id),
                'app_version': app,
                'state': self.manager.state.value,
                'network': self.manager.network,
                'uptime': now - self.manager.start_time,
                'entrypoints': self.manager.connections.my_peer.info.entrypoints_as_str(),
            },
            'peers_whitelist': [str(peer_id) for peer_id in self.manager.peers_whitelist],
            'known_peers': known_peers,
            'connections': {
                'connected_peers': connected_peers,
                'handshaking_peers': handshaking_peers,
                'connecting_peers': connecting_peers,
            },
            'dag': {
                'first_timestamp': self.manager.tx_storage.first_timestamp,
                'latest_timestamp': self.manager.tx_storage.latest_timestamp,
                'best_block_tips': best_block_tips,
                'best_block': {
                    'hash': best_block.hash_hex,
                    'height': best_block.static_metadata.height,
                },
                'best_blockchain': best_blockchain,
            }
        }
        return json_dumpb(data)


_openapi_height_info = [59, '0000045de9ac8365c43ccc96222873cb80c340c6c9c8949b56d2e2e51b6a3dbe']
_openapi_connected_peer = {
    'id': '5578ab3bcaa861fb9d07135b8b167dd230d4487b147be8fd2c94a79bd349d123',
    'app_version': 'Hathor v0.14.0-beta',
    'uptime': 118.37029600143433,
    'address': '192.168.1.1:54321',
    'state': 'READY',
    'last_message': 1539271481,
    'plugins': {
        'node-sync-timestamp': {
            'is_enabled': True,
            'latest_timestamp': 1685310912,
            'synced_timestamp': 1685310912
         }
    },
    'warning_flags': ['no_entrypoints'],
    'protocol_version': 'sync-v1.1',
    'peer_best_blockchain': [_openapi_height_info]
}
_openapi_connecting_peer = {
    'deferred': '<bound method TCP4ClientEndpoint.connect of <twisted.internet.endpoints.TCP4ClientEndpoint object at 0x10b16b470>>',  # noqa
    'address': '192.168.1.1:54321'
}

StatusResource.openapi = {
    '/status': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '200r/s',
                    'burst': 200,
                    'delay': 100
                }
            ],
            'per-ip': [
                {
                    'rate': '3r/s',
                    'burst': 10,
                    'delay': 3
                }
            ]
        },
        'get': {
            'tags': ['p2p'],
            'operationId': 'status',
            'summary': 'Status of Hathor network',
            'description': 'Returns the server data and the details of peers',
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Server and peers data',
                                    'value': {
                                        'server': {
                                            'id': '5578ab3bcaa861fb9d07135b8b167dd230d4487b147be8fd2c94a79bd349d123',
                                            'app_version': 'Hathor v0.14.0-beta',
                                            'state': 'READY',
                                            'network': 'testnet',
                                            'uptime': 118.37029600143433,
                                            'entrypoints': [
                                                'tcp:localhost:8000'
                                            ]
                                        },
                                        'known_peers': [],
                                        'connections': {
                                            'connected_peers': [_openapi_connected_peer],
                                            'handshaking_peers': [
                                                {
                                                    'address': '192.168.1.1:54321',
                                                    'state': 'HELLO',
                                                    'uptime': 0.0010249614715576172,
                                                    'app_version': 'Unknown'
                                                }
                                            ],
                                            'connecting_peers': [_openapi_connecting_peer]
                                        },
                                        'dag': {
                                            'first_timestamp': 1539271481,
                                            'latest_timestamp': 1539271483,
                                            'best_block_tips': [
                                                {
                                                    'hash':
                                                    '000007eb968a6cdf0499e2d033faf1e163e0dc9cf41876acad4d421836972038',  # noqa
                                                    'height': 0
                                                }
                                            ],
                                            'best_block': {
                                                'hash':
                                                '000007eb968a6cdf0499e2d033faf1e163e0dc9cf41876acad4d421836972038',  # noqa
                                                'height': 0
                                            },
                                            'best_blockchain': [_openapi_height_info]
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
}
