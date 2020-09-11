import time
from typing import TYPE_CHECKING

from twisted.web import resource
from twisted.web.http import Request

import hathor
from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.util import json_dumpb

if TYPE_CHECKING:
    from hathor.manager import HathorManager  # noqa: F401


@register_resource
class StatusResource(resource.Resource):
    """ Implements an status web server API, which responds with a summary
    of the node state.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: 'HathorManager'):
        self.manager = manager

    def render_GET(self, request: Request) -> bytes:
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        connecting_peers = []
        for endpoint, deferred in self.manager.connections.connecting_peers.items():
            host = getattr(endpoint, '_host', '')
            port = getattr(endpoint, '_port', '')
            connecting_peers.append({'deferred': str(deferred), 'address': '{}:{}'.format(host, port)})

        handshaking_peers = []
        for conn in self.manager.connections.handshaking_peers:
            remote = conn.transport.getPeer()
            handshaking_peers.append({
                'address': '{}:{}'.format(remote.host, remote.port),
                'state': conn.state.state_name if conn.state is not None else None,
                'uptime': time.time() - conn.connection_time,
                'app_version': conn.app_version,
            })

        connected_peers = []
        for conn in self.manager.connections.connected_peers.values():
            remote = conn.transport.getPeer()
            status = {}
            for name, plugin in conn.state.plugins.items():
                status[name] = plugin.get_status()
            connected_peers.append({
                'id': conn.peer.id if conn.peer is not None else None,
                'app_version': conn.app_version,
                'uptime': time.time() - conn.connection_time,
                'address': '{}:{}'.format(remote.host, remote.port),
                'state': conn.state.state_name if conn.state is not None else None,
                # 'received_bytes': conn.received_bytes,
                'last_message': time.time() - conn.last_message,
                'plugins': status,
                'warning_flags': [flag.value if flag is not None else None for flag in conn.warning_flags],
            })

        known_peers = []
        for peer in self.manager.connections.peer_storage.values():
            known_peers.append({
                'id': peer.id,
                'entrypoints': peer.entrypoints,
                'flags': [flag.value if flag is not None else None for flag in peer.flags],
            })

        app = 'Hathor v{}'.format(hathor.__version__)
        data = {
            'server': {
                'id': self.manager.connections.my_peer.id,
                'app_version': app,
                'state': self.manager.state.value if self.manager.state is not None else None,
                'network': self.manager.network,
                'uptime': time.time() - self.manager.start_time,
                'entrypoints': self.manager.connections.my_peer.entrypoints,
            },
            'known_peers': known_peers,
            'connections': {
                'connected_peers': connected_peers,
                'handshaking_peers': handshaking_peers,
                'connecting_peers': connecting_peers,
            },
            'dag': {
                'first_timestamp': self.manager.tx_storage.first_timestamp,
                'latest_timestamp': self.manager.tx_storage.latest_timestamp,
            }
        }
        return json_dumpb(data)


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
                                            'connected_peers': [],
                                            'handshaking_peers': [
                                                {
                                                    'address': '192.168.1.1:54321',
                                                    'state': 'HELLO',
                                                    'uptime': 0.0010249614715576172,
                                                    'app_version': 'Unknown'
                                                }
                                            ],
                                            'connecting_peers': [
                                                {
                                                    'deferred': ('<bound method TCP4ClientEndpoint.connect of <twisted'
                                                                 '.internet.endpoints.TCP4ClientEndpoint object at '
                                                                 '0x10b16b470>>'),
                                                    'address': '192.168.1.1:54321'
                                                }
                                            ]
                                        },
                                        'dag': {
                                            'first_timestamp': 1539271481,
                                            'latest_timestamp': 1539271483
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
