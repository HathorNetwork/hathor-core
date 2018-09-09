# encoding: utf-8

from twisted.web import resource

from hathor.transaction import Block

import json
import base64


class MiningResource(resource.Resource):
    """ Implements an status web server API, which responds with a summary
    of the node state.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_POST(self, request):
        block_bytes_str = request.args[b'block_bytes'][0]
        block_bytes = base64.b64decode(block_bytes_str)
        block = Block.create_from_struct(block_bytes)
        print('New block found: {}'.format(block.hash.hex()))
        self.manager.propagate_tx(block)
        return b''

    def render_GET(self, request):
        request.setHeader(b'content-type', b'application/json; charset=utf-8')

        block = self.manager.generate_mining_block()
        block_bytes = block.get_struct()

        data = {
            'parents': [x.hex() for x in block.parents],
            'block_bytes': base64.b64encode(block_bytes).decode('utf-8'),
        }
        return json.dumps(data, indent=4).encode('utf-8')
