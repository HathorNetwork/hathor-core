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
from itertools import islice
from typing import TYPE_CHECKING

from twisted.web import resource

from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.conf import HathorSettings

settings = HathorSettings()

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
        # Only return up to settings.MEMPOOL_API_TX_LIMIT txs per call (default: 100)
        data = {'success': True, 'transactions': list(islice(tx_ids, settings.MEMPOOL_API_TX_LIMIT))}
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
                    'rate': '1r/s',
                    'burst': 5,
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
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Success',
                                    'value': {
                                        'success': True,
                                        'transactions': [
                                            '339f47da87435842b0b1b528ecd9eac2495ce983b3e9c923a37e1befbe12c792',
                                            '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952',
                                            '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869',
                                        ],
                                    },
                                },
                            },
                        },
                    }
                }
            }
        }
    }
}
