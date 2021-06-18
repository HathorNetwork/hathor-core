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
from typing import TYPE_CHECKING

from twisted.web import resource

from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource

if TYPE_CHECKING:
    from twisted.web.http import Request

    from hathor.manager import HathorManager


@register_resource
class MempoolResource(resource.Resource):
    """ Implements a web server API to return transactions on the mempool.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: 'HathorManager'):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def render_GET(self, request: 'Request') -> bytes:
        """ Get request /mempool/ that returns transactions on the mempool

            :rtype: string (json list)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        # Get a list of all txs on the mempool
        tx_ids = map(
            # get only tx_ids
            lambda tx: tx.hash_hex,
            # order by timestamp
            sorted(list(self.manager.tx_storage.iter_mempool()), key=lambda tx: tx.timestamp),
        )
        data = {'success': True, 'transactions': list(tx_ids)}
        return json.dumps(data, indent=4).encode('utf-8')


MempoolResource.openapi = {
    '/mempool': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '50r/s',
                    'burst': 100,
                    'delay': 50
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
            'tags': ['mempool'],
            'operationId': 'mempool',
            'summary': 'List of mempool transactions',
            'description': 'Returns a list of all transactions currently on the mempool',
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {}
                    }
                }
            }
        }
    }
}
