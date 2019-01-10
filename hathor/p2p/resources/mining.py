import base64
import json

from twisted.web import resource

from hathor.transaction import Block


class MiningResource(resource.Resource):
    """ Implements an status web server API, which responds with a summary
    of the node state.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_POST(self, request):
        """ POST request /mining/
            Expects a parameter 'block_bytes' that is the block in bytes
            Create the block object from the bytes and propagate it

            :rtype: bytes
        """
        post_data = json.loads(request.content.read().decode('utf-8'))
        block_bytes_str = post_data['block_bytes']
        block_bytes = base64.b64decode(block_bytes_str)
        block = Block.create_from_struct(block_bytes, storage=self.manager.tx_storage)
        self.manager.propagate_tx(block)
        return b''

    def render_GET(self, request):
        """ GET request /mining/
            Generates a new block to be mined with correct parents
            Returns a json with a list of parents hash and the block in bytes

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')

        block = self.manager.generate_mining_block()
        block_bytes = block.get_struct()

        data = {
            'parents': [x.hex() for x in block.parents],
            'block_bytes': base64.b64encode(block_bytes).decode('utf-8'),
        }
        return json.dumps(data, indent=4).encode('utf-8')
