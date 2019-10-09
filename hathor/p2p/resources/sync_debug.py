import json
import time

from twisted.web import resource

import hathor
from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource


@register_resource
class SyncDebugResource(resource.Resource):
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

        peer_id = request.args[b'peer_id'][0].decode('utf-8')
        timestamp = int(request.args[b'timestamp'][0].decode('utf-8'))
        timestamp2 = int(request.args[b'timestamp2'][0].decode('utf-8'))

        protocol = self.manager.connections.connected_peers[peer_id]
        node_sync = protocol.state.plugins['node-sync-timestamp']

        intervals = self.manager.tx_storage.get_all_tips(timestamp)
        my_tips = [x.data.hex() for x in intervals]
        get_peer_tips = [x.hash.hex() for x in self.manager.tx_storage.get_all_sorted_txs_from_to(timestamp, timestamp2)]
        #get_peer_next = node_sync.get_peer_next(timestamp, offset=250)

        data = {
            'my_tips': my_tips,
            'get_peer_tips': get_peer_tips,
        }
        return json.dumps(data, indent=4).encode('utf-8')
