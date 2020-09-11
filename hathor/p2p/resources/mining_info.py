from math import log
from typing import TYPE_CHECKING

from twisted.web import resource
from twisted.web.http import Request

from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.conf import HathorSettings
from hathor.difficulty import Weight
from hathor.util import get_mined_tokens, json_dumpb

if TYPE_CHECKING:
    from hathor.manager import HathorManager  # noqa: F401

settings = HathorSettings()


@register_resource
class MiningInfoResource(resource.Resource):
    """ Implements an status web server API, which responds with mining information

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: 'HathorManager'):
        self.manager = manager

    def render_GET(self, request: Request) -> bytes:
        """ GET request /getmininginfo/

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        if not self.manager.can_start_mining():
            return json_dumpb({'success': False, 'message': 'Node still syncing'})

        # We can use any address.
        burn_address = bytes.fromhex(
            settings.P2PKH_VERSION_BYTE.hex() + 'acbfb94571417423c1ed66f706730c4aea516ac5762cccb8'
        )
        block = self.manager.generate_mining_block(address=burn_address)

        height = block.calculate_height() - 1
        difficulty = max(int(Weight(block.weight).to_pdiff()), 1)

        parent = block.get_block_parent()
        hashrate = 2**(parent.weight - log(30, 2))

        mined_tokens = get_mined_tokens(height)

        data = {
            'hashrate': hashrate,
            'difficulty': difficulty,
            'blocks': height,
            'mined_tokens': mined_tokens,
            'success': True,
        }
        return json_dumpb(data)


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
            'operationId': 'mining_info',
            'summary': 'Mining info',
            'description': 'Return the block\'s height, global hashrate, and mining difficulty.',
            'parameters': [],
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Block\'s height, global hashrate, and mining difficulty.',
                                    'value': {
                                        'blocks': 6354,
                                        'mined_tokens': 40665600,
                                        'difficulty': 1023.984375,
                                        'networkhashps': 146601550370.13358,
                                        'success': True
                                    }
                                },
                                'error': {
                                    'summary': 'Node still syncing',
                                    'value': {
                                        'success': False,
                                        'message': 'Node still syncing'
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
