# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
from math import log

from twisted.web import resource

from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.conf import HathorSettings
from hathor.daa import get_mined_tokens
from hathor.difficulty import Weight

settings = HathorSettings()


@register_resource
class MiningInfoResource(resource.Resource):
    """ Implements an status web server API, which responds with mining information

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
        set_cors(request, 'GET')

        if not self.manager.can_start_mining():
            return json.dumps({'success': False, 'message': 'Node still syncing'}).encode('utf-8')

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
