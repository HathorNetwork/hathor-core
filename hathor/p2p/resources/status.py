import json
import time

from twisted.web import resource

import hathor
from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource


@register_resource
class StatusResource(resource.Resource):
    """ Implements an status web server API, which responds with a summary
    of the node state.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_GET(self, request):
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
                'state': conn.state.state_name,
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
                'id': conn.peer.id,
                'app_version': conn.app_version,
                'uptime': time.time() - conn.connection_time,
                'address': '{}:{}'.format(remote.host, remote.port),
                'state': conn.state.state_name,
                # 'received_bytes': conn.received_bytes,
                'last_message': time.time() - conn.last_message,
                'plugins': status,
            })

        known_peers = []
        for peer in self.manager.connections.peer_storage.values():
            known_peers.append({
                'id': peer.id,
                'entrypoints': peer.entrypoints,
            })

        app = 'Hathor v{}'.format(hathor.__version__)
        data = {
            'server': {
                'id': self.manager.connections.my_peer.id,
                'app_version': app,
                'state': self.manager.state.value,
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
        return json.dumps(data, indent=4).encode('utf-8')


StatusResource.openapi = {
    '/status': {
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
