
from twisted.web import resource
from hathor.api_util import set_cors
import hathor

import json
import time


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
            connecting_peers.append({
                'deferred': str(deferred),
                'address': '{}:{}'.format(host, port)
            })

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
            for plugin in conn.state.plugins.values():
                status[plugin.get_name()] = plugin.get_status()
            connected_peers.append({
                'id': conn.peer.id,
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
            'connections': {
                'known_peers': known_peers,
                'connected_peers': connected_peers,
                'handshaking_peers': handshaking_peers,
                'connecting_peers': connecting_peers,
            },
            'dag': {
                'latest_timestamp': self.manager.latest_timestamp,
            }
        }
        return json.dumps(data, indent=4).encode('utf-8')
