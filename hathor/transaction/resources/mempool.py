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

from enum import Enum
from itertools import islice
from typing import TYPE_CHECKING, Iterator

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, get_args, parse_args, set_cors
from hathor.conf.get_settings import get_global_settings
from hathor.transaction import Transaction
from hathor.util import json_dumpb

if TYPE_CHECKING:
    from twisted.web.http import Request

    from hathor.manager import HathorManager


class IndexSource(Enum):
    ANY = 'any'
    MEMPOOL = 'mempool'
    TX_TIPS = 'tx-tips'


@register_resource
class MempoolResource(Resource):
    """ Implements a web server API to return transactions on the mempool.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: 'HathorManager'):
        # Important to have the manager so we can know the tx_storage
        self._settings = get_global_settings()
        self.manager = manager

    def render_GET(self, request: 'Request') -> bytes:
        """ Get request /mempool/ that returns transactions on the mempool

            :rtype: string (json list)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        # XXX: get an explicit index source if requested, only the order of results can change
        index_source = IndexSource.ANY
        args = get_args(request)
        if 'index' in args:
            parsed_args = parse_args(args, ['index'])
            if not parsed_args['success']:
                return json_dumpb({
                    'success': False,
                    'message': 'Failed to parse \'index\''
                })
            try:
                index_source = IndexSource(parsed_args['index'])
            except ValueError as e:
                return json_dumpb({
                    'success': False,
                    'message': f'Failed to parse \'index\': {e}'
                })

        # Get a list of all txs on the mempool
        tx_ids = map(
            # get only tx_ids
            lambda tx: tx.hash_hex,
            # order by timestamp
            sorted(list(self._get_from_index(index_source)), key=lambda tx: tx.timestamp),
        )
        # Only return up to settings.MEMPOOL_API_TX_LIMIT txs per call (default: 100)
        data = {'success': True, 'transactions': list(islice(tx_ids, self._settings.MEMPOOL_API_TX_LIMIT))}
        return json_dumpb(data)

    def _get_from_index(self, index_source: IndexSource) -> Iterator[Transaction]:
        tx_storage = self.manager.tx_storage
        assert tx_storage.indexes is not None
        if index_source == IndexSource.ANY or index_source == IndexSource.MEMPOOL:
            # XXX: if source is ANY we try to use the mempool when possible
            if tx_storage.indexes.mempool_tips is None:
                raise ValueError('mempool index is not enabled')
            yield from self._get_from_mempool_tips_index()
        elif index_source == IndexSource.TX_TIPS:
            raise ValueError('tx-tips index has been removed')
        else:
            raise NotImplementedError  # XXX: this cannot happen

    def _get_from_mempool_tips_index(self) -> Iterator[Transaction]:
        tx_storage = self.manager.tx_storage
        assert tx_storage.indexes is not None
        assert tx_storage.indexes.mempool_tips is not None
        yield from tx_storage.indexes.mempool_tips.iter_all(tx_storage)


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
