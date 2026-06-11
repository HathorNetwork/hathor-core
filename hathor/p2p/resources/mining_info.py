# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from math import log

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, set_cors
from hathor.conf.get_settings import get_global_settings
from hathor.difficulty import Weight
from hathor.util import json_dumpb


@register_resource
class MiningInfoResource(Resource):
    """ Implements an status web server API, which responds with mining information

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self._settings = get_global_settings()
        self.manager = manager

    def render_GET(self, request):
        """ GET request /getmininginfo/

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        if not self.manager.can_start_mining():
            return json_dumpb({'success': False, 'message': 'Node still syncing'})

        # We can use any address.
        burn_address = bytes.fromhex(
            self._settings.P2PKH_VERSION_BYTE.hex() + 'acbfb94571417423c1ed66f706730c4aea516ac5762cccb8'
        )
        block = self.manager.generate_mining_block(address=burn_address)
        block.init_static_metadata_from_storage(self._settings, self.manager.tx_storage)

        height = block.static_metadata.height - 1
        difficulty = max(int(Weight(block.weight).to_pdiff()), 1)

        parent = block.get_block_parent()
        avg_time = self.manager.daa_factory.create_from_parent(parent).avg_time_between_blocks
        hashrate = 2**(parent.weight - log(avg_time, 2))

        mined_tokens = self.manager.daa_factory.create_from_parent(parent).get_mined_tokens(height)

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
