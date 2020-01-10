import json
from math import log

from twisted.web import resource

from hathor.cli.openapi_files.register import register_resource
from hathor.merged_mining.coordinator import diff_from_weight


@register_resource
class MiningInfoResource(resource.Resource):
    """ Implements an status web server API, which responds with a summary
    of the node state.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_GET(self, request):
        """ GET request /getmininginfo/

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')

        if not self.manager.can_start_mining():
            return json.dumps({'success': False, 'message': 'Node still syncing'}).encode('utf-8')

        # We can use any address.
        burn_address = bytes.fromhex('28acbfb94571417423c1ed66f706730c4aea516ac5762cccb8')
        block = self.manager.generate_mining_block(address=burn_address)

        parent = block.get_block_parent()
        parent_meta = parent.get_metadata()

        height = parent_meta.height
        difficulty = diff_from_weight(block.weight)
        hashrate = 2**(parent.weight - log(30, 2))

        data = {
            'hashrate': hashrate,
            'difficulty': difficulty,
            'blocks': height,
            'success': True,
        }
        return json.dumps(data, indent=4).encode('utf-8')


MiningInfoResource.openapi = {
    '/getmininginfo': {
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
            'operationId': 'mining_get',
            'summary': 'Mining info',
            'description': 'Return the block\'s height, global hashrate, and mining difficulty.',
            'parameters': [],
            'responses': {
                '200': {
                    'description': 'Node still syncing',
                    'content': {
                        'application/json': {
                            'examples': {
                                'error': {
                                    'summary': 'Node still syncing',
                                    'value': {
                                        'success': False,
                                        'message': 'Node still syncing'
                                    }
                                }
                            }
                        },
                    }
                },
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Block\'s height, global hashrate, and mining difficulty.',
                                    'value': {
                                        'blocks': 6354,
                                        'difficulty': 1023.984375,
                                        'networkhashps': 146601550370.13358,
                                        'success': True
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
