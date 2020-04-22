import json

from twisted.web import resource

from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.util import get_mined_tokens


@register_resource
class MinedTokensResource(resource.Resource):
    """ Implements a web server API with GET to return the mined tokens and height of the network

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_GET(self, request):
        """ GET request for /mined_tokens/ that returns the network mined tokens and current height
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        timestamp = max(self.manager.tx_storage.latest_timestamp, self.manager.reactor.seconds())
        tip_blocks = self.manager.tx_storage.get_best_block_tips(timestamp)

        assert len(tip_blocks) > 0

        last_block = self.manager.tx_storage.get_transaction(tip_blocks[0])
        height = last_block.get_metadata().height

        mined_tokens = get_mined_tokens(height)

        data = {
            'height': height,
            'mined_tokens': mined_tokens
        }
        return json.dumps(data, indent=4).encode('utf-8')


MinedTokensResource.openapi = {
    '/mined_tokens': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '10r/s',
                    'burst': 20,
                    'delay': 180
                }
            ],
            'per-ip': [
                {
                    'rate': '2r/s',
                    'burst': 5,
                    'delay': 3
                }
            ]
        },
        'get': {
            'operationId': 'mined-tokens',
            'summary': 'Hathor mined tokens',
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Success',
                                    'value': {
                                        'mined_tokens': 2005331200,
                                        'height': 313333,
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
