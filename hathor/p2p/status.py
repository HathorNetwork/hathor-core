
from twisted.web import resource

import json
import time


class StatusResource(resource.Resource):
    isLeaf = True

    def __init__(self, factory):
        self.factory = factory

    def render_GET(self, request):
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        peers = []
        for conn in self.factory.connected_peers.values():
            remote = conn.transport.getPeer()
            peers.append({
                'id': conn.peer_id.id,
                'address': '{}:{}'.format(remote.host, remote.port),
                'last_message': time.time() - conn.last_message,
            })
        data = {
            'server': {
                'uptime': time.time() - self.factory.start_time,
                'id': self.factory.peer_id.id,
            },
            'peers': peers,
        }
        return json.dumps(data).encode('utf-8')
